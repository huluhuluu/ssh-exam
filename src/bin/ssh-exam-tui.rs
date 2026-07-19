use std::{
    env,
    io::{self, Stdout},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use ssh_exam_gate::{
    config::AppConfig,
    db::{AttemptInput, Db, GateError, PendingIdentity},
    quiz::{PreparedQuiz, Score},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Language {
    En,
    Zh,
    Bilingual,
}

impl Language {
    fn text(self, en: &str, zh: &str) -> String {
        match self {
            Self::En => en.to_owned(),
            Self::Zh => zh.to_owned(),
            Self::Bilingual => format!("{en} / {zh}"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Full-screen SSH first-login exam")]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    fingerprint: String,
    #[arg(long, value_enum, default_value = "bilingual")]
    language: Language,
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("failed to enable terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("failed to enter alternate screen");
        }
        let terminal = Terminal::new(CrosstermBackend::new(stdout))
            .context("failed to initialize terminal")?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

#[derive(Clone, Copy)]
struct ResultScreen {
    score: Score,
    attempt_number: u32,
}

struct ExamApp {
    quiz: PreparedQuiz,
    identity: PendingIdentity,
    question_index: usize,
    selected: usize,
    answers: Vec<usize>,
    result: Option<ResultScreen>,
    language: Language,
}

impl ExamApp {
    fn new(quiz: PreparedQuiz, identity: PendingIdentity, language: Language) -> Self {
        Self {
            quiz,
            identity,
            question_index: 0,
            selected: 0,
            answers: Vec::new(),
            result: None,
            language,
        }
    }
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ssh-exam-tui: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<()> {
    let sudo_user = env::var("SUDO_USER").context("SUDO_USER is required")?;
    if sudo_user != arguments.username {
        bail!("session identity validation failed");
    }
    let config = AppConfig::load(&arguments.config)?;
    let db = Db::new(&config.database_path, config.busy_timeout());
    let identity = db
        .load_identity(&arguments.username, &arguments.fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("session identity validation failed"))?;
    let published = db
        .published_test()?
        .ok_or_else(|| anyhow::anyhow!("no test is currently published"))?;
    if identity.test_id != published.test_id || identity.revision != published.revision {
        bail!("published test changed; reconnect to start the current test");
    }
    if identity.passed {
        bail!(
            "{}",
            arguments.language.text(
                "exam already passed; reconnect to continue",
                "考试已通过，请重新连接以继续"
            )
        );
    }
    if identity.attempt_count >= published.quiz.max_attempts {
        bail!(
            "{}",
            arguments.language.text(
                "maximum exam attempts reached; contact an administrator",
                "已达到最大考试次数，请联系管理员"
            )
        );
    }

    let mut app = ExamApp::new(published.quiz.prepare(), identity, arguments.language);
    let mut terminal = TerminalGuard::enter()?;
    loop {
        terminal.terminal.draw(|frame| render(frame, &app))?;
        if app.result.is_some() {
            if event::poll(Duration::from_secs(5)).context("failed to poll terminal input")? {
                let _ = event::read();
            }
            break;
        }
        match event::read().context("failed to read terminal input")? {
            Event::Resize(_, _) => continue,
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break,
                KeyCode::Up | KeyCode::Char('k') => {
                    app.selected = app.selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let last = app.quiz.questions[app.question_index].choices.len() - 1;
                    app.selected = (app.selected + 1).min(last);
                }
                KeyCode::Char(value) if value.is_ascii_digit() && value != '0' => {
                    let selected = value.to_digit(10).expect("ASCII digit") as usize - 1;
                    if selected < app.quiz.questions[app.question_index].choices.len() {
                        app.selected = selected;
                    }
                }
                KeyCode::Enter => submit_answer(&mut app, &db)?,
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}

fn submit_answer(app: &mut ExamApp, db: &Db) -> Result<()> {
    app.answers.push(app.selected);
    if app.answers.len() < app.quiz.questions.len() {
        app.question_index += 1;
        app.selected = 0;
        return Ok(());
    }
    let score = app.quiz.score(&app.answers)?;
    let answers_json = serde_json::to_string(&app.answers)?;
    let attempt_number = db
        .record_attempt(&AttemptInput {
            person_id: app.identity.person_id,
            test_id: &app.identity.test_id,
            revision: &app.identity.revision,
            score: score.correct,
            total: score.total,
            passed: score.passed,
            answers_json: &answers_json,
            max_attempts: app.quiz.max_attempts,
        })
        .map_err(|error| match error {
            GateError::AttemptsExhausted => {
                anyhow::anyhow!(app.language.text(
                    "maximum exam attempts reached; contact an administrator",
                    "已达到最大考试次数，请联系管理员"
                ))
            }
            GateError::AlreadyPassed => anyhow::anyhow!(app
                .language
                .text("exam already passed; reconnect", "考试已通过，请重新连接")),
            other => anyhow::anyhow!(other),
        })?;
    app.result = Some(ResultScreen {
        score,
        attempt_number,
    });
    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &ExamApp) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let outer = Block::default()
        .title(format!(" {} ", app.quiz.title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(outer, area);
    let inner = area.inner(ratatui::layout::Margin {
        vertical: 1,
        horizontal: 2,
    });
    if let Some(result) = app.result {
        render_result(frame, inner, app, result);
    } else {
        render_question(frame, inner, app);
    }
}

fn render_question(frame: &mut Frame<'_>, area: ratatui::layout::Rect, app: &ExamApp) {
    let question = &app.quiz.questions[app.question_index];
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(4),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                &app.identity.display_name,
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {} {}/{}  {} {}/{}",
                app.language.text("Attempt", "尝试"),
                app.identity.attempt_count + 1,
                app.quiz.max_attempts,
                app.language.text("Question", "问题"),
                app.question_index + 1,
                app.quiz.questions.len()
            )),
        ])),
        sections[0],
    );
    frame.render_widget(
        Paragraph::new(question.prompt.as_str())
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::White)),
        sections[1],
    );
    let items: Vec<_> = question
        .choices
        .iter()
        .enumerate()
        .map(|(index, choice)| ListItem::new(format!("{}. {choice}", index + 1)))
        .collect();
    let mut state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(
        List::new(items).highlight_symbol("> ").highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        sections[2],
        &mut state,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "{}: {}%",
                app.language.text("Pass threshold", "通过分数"),
                app.quiz.pass_threshold_percent
            )),
            Line::from(app.language.text(
                "Up/Down select, Enter submit, q quit",
                "上/下选择，回车提交，q 退出",
            )),
        ]),
        sections[3],
    );
}

fn render_result(
    frame: &mut Frame<'_>,
    area: ratatui::layout::Rect,
    app: &ExamApp,
    result: ResultScreen,
) {
    let remaining = app.quiz.max_attempts.saturating_sub(result.attempt_number);
    let (heading, color, detail) = if result.score.passed {
        (
            app.language.text("PASSED", "已通过"),
            Color::Green,
            app.language.text(
                "Your result applies to all enabled registered keys. Disconnect and reconnect to continue.",
                "结果适用于所有已启用的注册密钥。请断开并重新连接以继续。",
            ),
        )
    } else if remaining == 0 {
        (
            app.language.text("NOT PASSED", "未通过"),
            Color::Red,
            app.language.text(
                "No attempts remain. Disconnect and contact an administrator.",
                "没有剩余尝试次数。请断开连接并联系管理员。",
            ),
        )
    } else {
        (
            app.language.text("NOT PASSED", "未通过"),
            Color::Yellow,
            app.language.text(
                "Disconnect and reconnect to make another attempt.",
                "请断开并重新连接以再次尝试。",
            ),
        )
    };
    let text = vec![
        Line::from(Span::styled(
            heading,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "{}: {}/{} ({}%). {}: {}%.",
            app.language.text("Score", "得分"),
            result.score.correct,
            result.score.total,
            result.score.percent,
            app.language.text("Required", "要求"),
            app.quiz.pass_threshold_percent
        )),
        Line::from(format!(
            "{}: {remaining}.",
            app.language.text("Attempts remaining", "剩余尝试次数")
        )),
        Line::from(""),
        Line::from(detail),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", app.language.text("Result", "结果"))),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}
