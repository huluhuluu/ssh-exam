use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use serde::{Deserialize, Serialize};

pub const LEGACY_BANK_ID: &str = "legacy";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BankEnvironment {
    Host,
    Docker,
    Network,
    #[default]
    General,
}

impl BankEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Docker => "docker",
            Self::Network => "network",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Quiz {
    pub title: String,
    #[serde(default)]
    pub environment: BankEnvironment,
    #[serde(default = "default_pass_threshold")]
    pub pass_threshold_percent: u32,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    pub questions: Vec<Question>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub prompt: String,
    pub choices: Vec<String>,
    pub correct_index: usize,
}

#[derive(Clone, Debug)]
pub struct PreparedQuiz {
    pub title: String,
    pub pass_threshold_percent: u32,
    pub max_attempts: u32,
    pub questions: Vec<PreparedQuestion>,
}

#[derive(Clone, Debug)]
pub struct PreparedQuestion {
    pub prompt: String,
    pub choices: Vec<String>,
    pub correct_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Score {
    pub correct: u32,
    pub total: u32,
    pub percent: u32,
    pub passed: bool,
}

#[derive(Clone, Debug)]
pub struct QuizBank {
    pub id: String,
    pub quiz: Quiz,
    pub legacy: bool,
}

#[derive(Clone, Debug)]
pub struct QuizCatalog {
    legacy_path: PathBuf,
    directory: Option<PathBuf>,
}

fn default_pass_threshold() -> u32 {
    80
}

fn default_max_attempts() -> u32 {
    3
}

impl Quiz {
    pub fn from_slice(raw: &[u8]) -> Result<Self> {
        let quiz: Self = serde_json::from_slice(raw).context("invalid quiz JSON")?;
        quiz.validate()?;
        Ok(quiz)
    }

    pub fn load(path: &Path) -> Result<Self> {
        regular_file_metadata(path)?;
        let raw = fs::read(path)
            .with_context(|| format!("failed to read quiz config {}", path.display()))?;
        let quiz: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("invalid quiz config {}", path.display()))?;
        quiz.validate()?;
        Ok(quiz)
    }

    pub fn ensure_writable(path: &Path) -> Result<()> {
        Self::load(path)?;
        OpenOptions::new().write(true).open(path).with_context(|| {
            format!(
                "quiz file {} is not writable by the admin service",
                path.display()
            )
        })?;

        let (probe_path, probe) = create_temporary_file(path, 0o640).with_context(|| {
            format!(
                "quiz directory for {} is not writable by the admin service; atomic updates require write access to the parent directory",
                path.display()
            )
        })?;
        drop(probe);
        fs::remove_file(&probe_path).with_context(|| {
            format!(
                "failed to remove quiz writability probe {}",
                probe_path.display()
            )
        })?;
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mode = quiz_file_mode(path)?;
        let encoded = serde_json::to_vec_pretty(self).context("failed to serialize quiz")?;
        let (temporary_path, mut temporary) =
            create_temporary_file(path, mode).with_context(|| {
                format!(
                    "failed to create a temporary quiz file for {}",
                    path.display()
                )
            })?;

        let result = (|| -> Result<()> {
            temporary
                .write_all(&encoded)
                .with_context(|| format!("failed to write {}", temporary_path.display()))?;
            temporary
                .write_all(b"\n")
                .with_context(|| format!("failed to write {}", temporary_path.display()))?;
            temporary
                .sync_all()
                .with_context(|| format!("failed to sync {}", temporary_path.display()))?;
            drop(temporary);
            fs::rename(&temporary_path, path).with_context(|| {
                format!("failed to atomically replace quiz file {}", path.display())
            })?;
            sync_parent_directory(path);
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    pub fn update(path: &Path, operation: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        let mut quiz = Self::load(path)?;
        operation(&mut quiz)?;
        quiz.validate()?;
        quiz.save_atomic(path)?;
        Ok(quiz)
    }

    pub fn update_settings(&mut self, title: String, threshold: u32, attempts: u32) -> Result<()> {
        let previous = (
            std::mem::replace(&mut self.title, title),
            std::mem::replace(&mut self.pass_threshold_percent, threshold),
            std::mem::replace(&mut self.max_attempts, attempts),
        );
        if let Err(error) = self.validate() {
            self.title = previous.0;
            self.pass_threshold_percent = previous.1;
            self.max_attempts = previous.2;
            return Err(error);
        }
        Ok(())
    }

    pub fn add_question(&mut self, question: Question) -> Result<()> {
        self.questions.push(question);
        if let Err(error) = self.validate() {
            self.questions.pop();
            return Err(error);
        }
        Ok(())
    }

    pub fn edit_question(&mut self, index: usize, question: Question) -> Result<()> {
        if index >= self.questions.len() {
            bail!("question not found");
        }
        let previous = std::mem::replace(&mut self.questions[index], question);
        if let Err(error) = self.validate() {
            self.questions[index] = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn delete_question(&mut self, index: usize) -> Result<()> {
        if index >= self.questions.len() {
            bail!("question not found");
        }
        if self.questions.len() == 1 {
            bail!("the exam must keep at least one question");
        }
        self.questions.remove(index);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.title, 200) {
            bail!("quiz title must contain 1-200 printable characters");
        }
        if !(1..=100).contains(&self.pass_threshold_percent) {
            bail!("pass_threshold_percent must be between 1 and 100");
        }
        if self.max_attempts == 0 || self.max_attempts > 100 {
            bail!("max_attempts must be between 1 and 100");
        }
        if self.questions.is_empty() || self.questions.len() > 200 {
            bail!("quiz must contain between 1 and 200 questions");
        }
        for (index, question) in self.questions.iter().enumerate() {
            if !valid_text(&question.prompt, 2_000) {
                bail!(
                    "question {} prompt must contain 1-2000 printable characters",
                    index + 1
                );
            }
            if !(2..=20).contains(&question.choices.len()) {
                bail!("question {} must have between 2 and 20 choices", index + 1);
            }
            if question.correct_index >= question.choices.len() {
                bail!("question {} has an invalid correct_index", index + 1);
            }
            if question
                .choices
                .iter()
                .any(|choice| !valid_text(choice, 500))
            {
                bail!(
                    "question {} choices must contain 1-500 printable characters",
                    index + 1
                );
            }
            for (choice_index, choice) in question.choices.iter().enumerate() {
                if question.choices[..choice_index]
                    .iter()
                    .any(|previous| previous.trim() == choice.trim())
                {
                    bail!("question {} choices must be unique", index + 1);
                }
            }
        }
        Ok(())
    }

    pub fn prepare(&self) -> PreparedQuiz {
        let mut rng = OsRng;
        let mut questions = self.questions.clone();
        questions.shuffle(&mut rng);
        let questions = questions
            .into_iter()
            .map(|question| {
                let correct = question.choices[question.correct_index].clone();
                let mut choices = question.choices;
                choices.shuffle(&mut rng);
                let correct_index = choices
                    .iter()
                    .position(|choice| choice == &correct)
                    .expect("the correct choice remains after shuffling");
                PreparedQuestion {
                    prompt: question.prompt,
                    choices,
                    correct_index,
                }
            })
            .collect();
        PreparedQuiz {
            title: self.title.clone(),
            pass_threshold_percent: self.pass_threshold_percent,
            max_attempts: self.max_attempts,
            questions,
        }
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>> {
        let mut encoded = serde_json::to_vec_pretty(self).context("failed to serialize quiz")?;
        encoded.push(b'\n');
        Ok(encoded)
    }
}

impl QuizCatalog {
    pub fn new(legacy_path: impl Into<PathBuf>, directory: Option<PathBuf>) -> Self {
        Self {
            legacy_path: legacy_path.into(),
            directory,
        }
    }

    pub fn catalog_directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }

    pub fn discover(&self) -> Result<Vec<QuizBank>> {
        let mut banks = vec![QuizBank {
            id: LEGACY_BANK_ID.to_owned(),
            quiz: Quiz::load(&self.legacy_path)?,
            legacy: true,
        }];
        let Some(directory) = &self.directory else {
            return Ok(banks);
        };
        regular_directory_metadata(directory)?;
        for entry in fs::read_dir(directory)
            .with_context(|| format!("failed to read quiz catalog {}", directory.display()))?
        {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read quiz catalog entry in {}",
                    directory.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow::anyhow!("quiz bank filename must be valid UTF-8"))?;
            validate_bank_id(id)?;
            if id == LEGACY_BANK_ID {
                bail!("quiz bank id {LEGACY_BANK_ID} is reserved for quiz_path");
            }
            banks.push(QuizBank {
                id: id.to_owned(),
                quiz: Quiz::load(&path)?,
                legacy: false,
            });
        }
        banks[1..].sort_by(|left, right| left.id.cmp(&right.id));
        Ok(banks)
    }

    pub fn load(&self, id: &str) -> Result<Quiz> {
        let path = self.bank_path(id)?;
        Quiz::load(&path).with_context(|| format!("failed to load quiz bank {id}"))
    }

    pub fn import(&self, id: &str, raw: &[u8]) -> Result<QuizBank> {
        if raw.len() > 1024 * 1024 {
            bail!("quiz bank JSON must not exceed 1 MiB");
        }
        let quiz = Quiz::from_slice(raw)?;
        self.create(id, &quiz)
    }

    pub fn compose(
        &self,
        title: String,
        bank_ids: &[String],
        pass_threshold_percent: u32,
        max_attempts: u32,
    ) -> Result<Quiz> {
        if bank_ids.is_empty() {
            bail!("a test must include at least one question bank");
        }
        let mut unique = std::collections::HashSet::new();
        let mut environment = None;
        let mut questions = Vec::new();
        for bank_id in bank_ids {
            validate_bank_id(bank_id)?;
            if !unique.insert(bank_id.as_str()) {
                bail!("a test cannot include the same question bank twice");
            }
            let bank = self.load(bank_id)?;
            environment = match environment {
                None => Some(bank.environment),
                Some(current) if current == bank.environment => Some(current),
                Some(_) => Some(BankEnvironment::General),
            };
            questions.extend(bank.questions);
        }
        let quiz = Quiz {
            title,
            environment: environment.unwrap_or_default(),
            pass_threshold_percent,
            max_attempts,
            questions,
        };
        quiz.validate()?;
        Ok(quiz)
    }

    pub fn ensure_writable(&self) -> Result<()> {
        Quiz::ensure_writable(&self.legacy_path)?;
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        regular_directory_metadata(directory)?;
        let probe_target = directory.join("catalog-probe.json");
        let (probe_path, probe) =
            create_temporary_file(&probe_target, 0o640).with_context(|| {
                format!(
                    "quiz catalog {} is not writable by the admin service",
                    directory.display()
                )
            })?;
        drop(probe);
        fs::remove_file(&probe_path)
            .with_context(|| format!("failed to remove catalog probe {}", probe_path.display()))?;
        self.discover()?;
        Ok(())
    }

    pub fn create(&self, id: &str, quiz: &Quiz) -> Result<QuizBank> {
        validate_bank_id(id)?;
        if id == LEGACY_BANK_ID {
            bail!("quiz bank id {LEGACY_BANK_ID} is reserved for quiz_path");
        }
        let Some(directory) = &self.directory else {
            bail!("quiz_directory is not configured");
        };
        regular_directory_metadata(directory)?;
        let path = directory.join(format!("{id}.json"));
        match fs::symlink_metadata(&path) {
            Ok(_) => bail!("quiz bank {id} already exists"),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect quiz bank {}", path.display()))
            }
        }
        quiz.save_atomic(&path)?;
        Ok(QuizBank {
            id: id.to_owned(),
            quiz: quiz.clone(),
            legacy: false,
        })
    }

    pub fn update(
        &self,
        id: &str,
        operation: impl FnOnce(&mut Quiz) -> Result<()>,
    ) -> Result<Quiz> {
        let path = self.bank_path(id)?;
        Quiz::update(&path, operation)
    }

    fn bank_path(&self, id: &str) -> Result<PathBuf> {
        validate_bank_id(id)?;
        if id == LEGACY_BANK_ID {
            return Ok(self.legacy_path.clone());
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("quiz bank {id} is unavailable in legacy mode"))?;
        Ok(directory.join(format!("{id}.json")))
    }
}

pub fn validate_bank_id(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty()
        || bytes.len() > 64
        || !valid_edge(bytes[0])
        || !valid_edge(bytes[bytes.len() - 1])
        || !bytes.iter().all(|byte| valid_edge(*byte) || *byte == b'-')
        || value.contains("--")
    {
        bail!("bank id must use 1-64 lowercase letters or digits with single internal hyphens");
    }
    Ok(())
}

fn valid_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect quiz config {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("quiz config {} must not be a symbolic link", path.display());
    }
    if !metadata.is_file() {
        bail!("quiz config {} must be a regular file", path.display());
    }
    Ok(metadata)
}

fn regular_directory_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect quiz catalog {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "quiz catalog {} must not be a symbolic link",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!("quiz catalog {} must be a directory", path.display());
    }
    Ok(metadata)
}

fn quiz_file_mode(path: &Path) -> Result<u32> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("quiz config {} must not be a symbolic link", path.display());
            }
            if !metadata.is_file() {
                bail!("quiz config {} must be a regular file", path.display());
            }
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode() & 0o777;
                Ok(if mode & 0o022 == 0 { mode } else { 0o640 })
            }
            #[cfg(not(unix))]
            {
                Ok(0o640)
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(0o640),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect quiz config {}", path.display()))
        }
    }
}

fn create_temporary_file(path: &Path, mode: u32) -> Result<(PathBuf, File)> {
    #[cfg(not(unix))]
    let _ = mode;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("quiz path must have a parent directory"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("quiz filename must be valid UTF-8"))?;

    for _ in 0..16 {
        let candidate = parent.join(format!(".{name}.tmp.{:016x}", OsRng.next_u64()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(mode);
        match options.open(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a unique temporary quiz filename")
}

fn sync_parent_directory(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
    }
}

impl PreparedQuiz {
    pub fn score(&self, answers: &[usize]) -> Result<Score> {
        if answers.len() != self.questions.len() {
            bail!("every question must be answered");
        }
        let correct = answers
            .iter()
            .zip(&self.questions)
            .filter(|(answer, question)| **answer == question.correct_index)
            .count() as u32;
        let total = self.questions.len() as u32;
        let percent = correct * 100 / total;
        Ok(Score {
            correct,
            total,
            percent,
            passed: correct * 100 >= self.pass_threshold_percent * total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn quiz() -> Quiz {
        Quiz {
            title: "Safety".to_owned(),
            environment: BankEnvironment::General,
            pass_threshold_percent: 80,
            max_attempts: 3,
            questions: (0..5)
                .map(|index| Question {
                    prompt: format!("Question {index}"),
                    choices: vec!["Correct".to_owned(), "Wrong".to_owned()],
                    correct_index: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn threshold_is_inclusive_and_integer_safe() {
        let prepared = quiz().prepare();
        let answers: Vec<_> = prepared
            .questions
            .iter()
            .enumerate()
            .map(|(index, question)| {
                if index == 0 {
                    (question.correct_index + 1) % question.choices.len()
                } else {
                    question.correct_index
                }
            })
            .collect();
        assert_eq!(
            prepared.score(&answers).unwrap(),
            Score {
                correct: 4,
                total: 5,
                percent: 80,
                passed: true
            }
        );
    }

    #[test]
    fn shuffled_questions_keep_correct_choices() {
        let prepared = quiz().prepare();
        let answers: Vec<_> = prepared
            .questions
            .iter()
            .map(|question| question.correct_index)
            .collect();
        assert_eq!(prepared.score(&answers).unwrap().correct, 5);
    }

    #[test]
    fn validates_limits_and_answer_count() {
        let mut invalid = quiz();
        invalid.max_attempts = 0;
        assert!(invalid.validate().is_err());
        assert!(quiz().prepare().score(&[]).is_err());
    }

    #[test]
    fn settings_and_question_operations_validate_and_rollback() {
        let mut quiz = quiz();
        quiz.update_settings("Updated exam".to_owned(), 75, 5)
            .unwrap();
        assert_eq!(quiz.title, "Updated exam");
        assert_eq!(quiz.pass_threshold_percent, 75);
        assert_eq!(quiz.max_attempts, 5);
        assert!(quiz.update_settings("".to_owned(), 75, 5).is_err());
        assert_eq!(quiz.title, "Updated exam");

        quiz.add_question(Question {
            prompt: "Added?".to_owned(),
            choices: vec!["Yes".to_owned(), "No".to_owned()],
            correct_index: 0,
        })
        .unwrap();
        let added = quiz.questions.len() - 1;
        quiz.edit_question(
            added,
            Question {
                prompt: "Edited?".to_owned(),
                choices: vec!["No".to_owned(), "Yes".to_owned()],
                correct_index: 1,
            },
        )
        .unwrap();
        assert_eq!(quiz.questions[added].prompt, "Edited?");
        quiz.delete_question(added).unwrap();
        assert_eq!(quiz.questions.len(), 5);
        assert!(quiz.edit_question(99, quiz.questions[0].clone()).is_err());
    }

    #[test]
    fn cannot_delete_the_final_question() {
        let mut quiz = quiz();
        quiz.questions.truncate(1);
        let before = quiz.clone();
        assert!(quiz.delete_question(0).is_err());
        assert_eq!(quiz, before);
    }

    #[test]
    fn atomic_update_persists_valid_json_and_leaves_no_temporary_file() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("quiz.json");
        quiz().save_atomic(&path).unwrap();
        Quiz::ensure_writable(&path).unwrap();

        let updated = Quiz::update(&path, |quiz| {
            quiz.update_settings("Persisted".to_owned(), 90, 2)
        })
        .unwrap();
        assert_eq!(Quiz::load(&path).unwrap(), updated);
        assert_eq!(updated.title, "Persisted");
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            1,
            "temporary quiz files must be removed"
        );

        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_quiz_paths() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let target = directory.path().join("target.json");
        quiz().save_atomic(&target).unwrap();
        let link = directory.path().join("quiz.json");
        symlink(&target, &link).unwrap();
        assert!(Quiz::load(&link).is_err());
        assert!(quiz().save_atomic(&link).is_err());
    }

    #[test]
    fn catalog_discovers_safe_sorted_banks_and_loads_legacy() {
        let directory = TempDir::new().unwrap();
        let legacy_path = directory.path().join("quiz.json");
        quiz().save_atomic(&legacy_path).unwrap();
        let banks_path = directory.path().join("banks");
        fs::create_dir(&banks_path).unwrap();
        let catalog = QuizCatalog::new(&legacy_path, Some(banks_path));

        let mut docker = quiz();
        docker.title = "Docker SSH".to_owned();
        docker.environment = BankEnvironment::Docker;
        catalog.create("docker-ssh", &docker).unwrap();
        let mut host = quiz();
        host.title = "Host SSH".to_owned();
        host.environment = BankEnvironment::Host;
        catalog.create("host-ssh", &host).unwrap();

        let banks = catalog.discover().unwrap();
        assert_eq!(
            banks
                .iter()
                .map(|bank| bank.id.as_str())
                .collect::<Vec<_>>(),
            vec!["legacy", "docker-ssh", "host-ssh"]
        );
        assert_eq!(catalog.load("legacy").unwrap().title, "Safety");
        assert_eq!(
            catalog.load("docker-ssh").unwrap().environment,
            BankEnvironment::Docker
        );
    }

    #[test]
    fn catalog_rejects_unsafe_ids_and_mutates_one_file_atomically() {
        let directory = TempDir::new().unwrap();
        let legacy_path = directory.path().join("quiz.json");
        quiz().save_atomic(&legacy_path).unwrap();
        let banks_path = directory.path().join("banks");
        fs::create_dir(&banks_path).unwrap();
        let catalog = QuizCatalog::new(&legacy_path, Some(banks_path.clone()));
        catalog.create("host-ssh", &quiz()).unwrap();
        catalog.create("network-topology", &quiz()).unwrap();
        assert!(catalog.create("../escape", &quiz()).is_err());
        assert!(catalog.create("legacy", &quiz()).is_err());

        catalog
            .update("host-ssh", |bank| {
                bank.update_settings("Changed".to_owned(), 90, 2)
            })
            .unwrap();
        assert_eq!(catalog.load("host-ssh").unwrap().title, "Changed");
        assert_eq!(catalog.load("network-topology").unwrap().title, "Safety");
        assert_eq!(
            fs::read_dir(&banks_path).unwrap().count(),
            2,
            "catalog mutations must not leave temporary files"
        );
    }
}
