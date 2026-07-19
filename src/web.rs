use std::{
    collections::BTreeMap,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use askama::Template;
use axum::{
    extract::{DefaultBodyLimit, Form, Path as AxumPath, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng as RandOsRng, RngCore};
use serde::Deserialize;
use sha2::Sha256;

use crate::{
    config::AdminAuthConfig,
    db::{
        Db, GateError, KeyRecord, PersonRecord, PersonView, PublicationRecord, PublishedTest,
        TestDefinitionInput, TestDefinitionRecord,
    },
    quiz::{
        validate_bank_id, BankEnvironment, CompositionOptions, Question, Quiz, QuizBank,
        QuizCatalog, LEGACY_BANK_ID,
    },
};

type HmacSha256 = Hmac<Sha256>;
const SESSION_COOKIE: &str = "ssh_exam_session";
const LOGIN_CSRF_COOKIE: &str = "ssh_exam_login_csrf";
const FLASH_COOKIE: &str = "ssh_exam_flash";
const LANGUAGE_COOKIE: &str = "ssh_exam_language";
const LOGIN_FAILURE_LIMIT: u32 = 8;
const LOGIN_FAILURE_WINDOW_SECONDS: u64 = 60;
const LOGIN_BLOCK_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebLanguage {
    En,
    Zh,
    Bilingual,
}

impl WebLanguage {
    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh",
            Self::Bilingual => "bilingual",
        }
    }

    fn html_lang(self) -> &'static str {
        match self {
            Self::Zh => "zh-CN",
            Self::En | Self::Bilingual => "en",
        }
    }

    fn text(self, en: &str, zh: &str) -> String {
        match self {
            Self::En => en.to_owned(),
            Self::Zh => zh.to_owned(),
            Self::Bilingual => format!("{en} / {zh}"),
        }
    }
}

impl FromStr for WebLanguage {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "en" => Ok(Self::En),
            "zh" => Ok(Self::Zh),
            "bilingual" => Ok(Self::Bilingual),
            _ => Err(()),
        }
    }
}

macro_rules! define_labels {
    ($($name:ident => ($en:literal, $zh:literal)),+ $(,)?) => {
        #[derive(Clone)]
        struct Labels {
            html_lang: &'static str,
            $($name: String,)+
        }

        fn labels(language: WebLanguage) -> Labels {
            Labels {
                html_lang: language.html_lang(),
                $($name: language.text($en, $zh),)+
            }
        }
    };
}

define_labels! {
    overview => ("Overview", "概览"),
    people => ("People", "人员"),
    exam => ("Tests", "测试"),
    question_banks => ("Question banks", "题库"),
    sign_out => ("Sign out", "退出登录"),
    language => ("Language", "语言"),
    administration => ("Administration", "管理控制台"),
    admin_password => ("Admin password", "管理员密码"),
    sign_in => ("Sign in", "登录"),
    overview_help => ("Current registration, access, and exam state.", "当前注册、访问与考试状态。"),
    system_metrics => ("System metrics", "系统指标"),
    enabled_people => ("Enabled people", "已启用人员"),
    passed => ("Passed", "已通过"),
    active_keys => ("Active keys", "活跃密钥"),
    configured_accounts => ("Configured Unix accounts", "已配置 Unix 账号"),
    recorded_attempts => ("Recorded attempts", "已记录尝试"),
    current_exam => ("Current exam", "当前考试"),
    manage_exam => ("Manage exams", "管理考试"),
    title => ("Title", "标题"),
    environment => ("Environment", "环境"),
    pass_threshold => ("Pass threshold", "通过分数"),
    maximum_attempts => ("Maximum attempts", "最大尝试次数"),
    questions => ("Questions", "问题"),
    banks => ("Banks", "题库"),
    access_model => ("Identity model", "身份模型"),
    manage_people => ("Manage people", "管理人员"),
    access_help => ("Each person owns one Unix login account. Every enabled key inherits that account and the current published test qualification.", "每个人员直接绑定一个 Unix 登录账号；其所有已启用公钥继承该账号和当前发布测试资格。"),
    people_help => ("Registered identities, direct Unix accounts, device keys, and inherited exam status.", "注册身份、直接绑定的 Unix 账号、设备密钥与继承的考试状态。"),
    create_person => ("Create person", "创建人员"),
    create_person_help => ("Pass status belongs to the person and is inherited by every enabled registered key.", "通过状态属于人员，并由其所有已启用的注册密钥继承。"),
    display_name => ("Display name", "显示名称"),
    registered_people => ("Registered people", "已注册人员"),
    no_people => ("No people are registered.", "尚未注册人员。"),
    person => ("Person", "人员"),
    account_status => ("Account status", "账号状态"),
    exam_status => ("Exam status", "考试状态"),
    attempts => ("Attempts", "尝试次数"),
    device_keys => ("Device keys", "设备密钥"),
    unix_account => ("Unix account", "Unix 账号"),
    enabled => ("Enabled", "已启用"),
    disabled => ("Disabled", "已禁用"),
    pending => ("Pending", "待考试"),
    disable_person => ("Disable person", "禁用人员"),
    enable_person => ("Enable person", "启用人员"),
    reset_exam => ("Reset exam", "重置考试"),
    no_device_keys => ("No device keys are registered for this person.", "此人员尚未注册设备密钥。"),
    fingerprint => ("Fingerprint", "指纹"),
    type_and_label => ("Type and label", "类型与标签"),
    status => ("Status", "状态"),
    actions => ("Actions", "操作"),
    disable => ("Disable", "禁用"),
    enable => ("Enable", "启用"),
    remove => ("Remove", "移除"),
    danger_zone => ("Danger zone", "危险操作"),
    confirm_delete => ("I understand this deletion cannot be undone", "我确认此删除操作无法撤销"),
    delete_person => ("Delete person", "删除人员"),
    delete_person_help => ("Deletes this person, registered keys, attempts, and pass records.", "删除此人员及其公钥、尝试记录和通过记录。"),
    public_key => ("Public key", "公钥"),
    add_device_key => ("Add device key", "添加设备密钥"),
    unix_account_help => ("All enabled keys for this person authenticate only to this existing Unix account. Leave empty to deny SSH access.", "此人员的所有已启用公钥只能登录该已有 Unix 账号；留空将拒绝 SSH 访问。"),
    save_person => ("Save person", "保存人员"),
    unassigned => ("Unassigned", "未分配"),
    unix_login => ("Unix login account", "Unix 登录账号"),
    action => ("Action", "操作"),
    exam_help => ("Saved changes do not alter the active immutable revision until you publish this test again.", "保存的修改不会改变当前生效的不可变版本；重新发布此测试后才会生效。"),
    configured_banks => ("Configured banks", "已配置题库"),
    delete_bank => ("Delete bank", "删除题库"),
    delete_bank_help => ("Only non-legacy banks unused by saved tests can be deleted.", "只能删除未被已保存测试引用的非兼容题库。"),
    used_by_tests => ("Used by saved tests", "已保存测试引用数"),
    bank_in_use => ("This bank is referenced by a saved test", "此题库正被已保存测试引用"),
    legacy_bank => ("Legacy quiz_path", "兼容 quiz_path"),
    bank_id => ("Bank ID", "题库 ID"),
    bank_id_help => ("Lowercase letters, digits, and single internal hyphens.", "使用小写字母、数字和单个连接短横线。"),
    choices => ("Choices", "选项"),
    choices_help => ("One choice per line; 2-20 unique choices.", "每行一个选项；需要 2-20 个不重复选项。"),
    correct_answer => ("Correct answer", "正确答案"),
    settings => ("Settings", "设置"),
    save_settings => ("Save settings", "保存设置"),
    total => ("total", "总计"),
    question => ("Question", "问题"),
    answer => ("Answer", "答案"),
    prompt => ("Prompt", "题目"),
    choice => ("Choice", "选项"),
    save_question => ("Save question", "保存问题"),
    delete_question_help => ("Deleting a question does not change recorded person attempts.", "删除问题不会更改已记录的人员尝试。"),
    delete_question => ("Delete question", "删除问题"),
    keep_one_question => ("The bank must keep one question", "题库必须保留一个问题"),
    add_question => ("Add question", "添加问题"),
    catalog_disabled => ("Catalog mode is disabled; configure quiz_directory to create additional banks.", "题库目录模式未启用；请配置 quiz_directory 以创建更多题库。"),
    educational_only => ("Environment metadata is descriptive educational scope only; this gate does not execute or provision Docker, hosts, or networks.", "环境元数据仅描述教学范围；本系统不会执行或配置 Docker、主机或网络。"),
    view_details => ("View details", "查看详情"),
    import_json => ("Import JSON", "导入 JSON"),
    json_document => ("JSON document", "JSON 文档"),
    export_json => ("Export JSON", "导出 JSON"),
    saved_tests => ("Saved tests", "已保存测试"),
    create_test => ("Create test", "创建测试"),
    test_id => ("Test ID", "测试 ID"),
    draft => ("Draft", "草稿"),
    published => ("Published", "已发布"),
    publish => ("Publish", "发布"),
    bank_selection => ("Question bank IDs", "题库 ID"),
    bank_selection_help => ("Selected banks are composed in the order shown.", "所选题库将按照当前显示顺序组合。"),
    combined_questions => ("Combined questions", "组合题目数"),
    save_test => ("Save test", "保存测试"),
    delete_test => ("Delete test", "删除测试"),
    delete_test_help => ("Only unpublished drafts without publication history can be deleted.", "只能删除没有发布历史的未发布草稿。"),
    no_saved_tests => ("No saved tests.", "尚无已保存测试。"),
    current_revision => ("Current revision", "当前版本"),
    no_published_test => ("No test is published.", "当前没有已发布测试。"),
    question_limit => ("Questions per attempt", "每次考试题数"),
    question_limit_help => ("Leave empty to use every composed question.", "留空表示使用组合后的全部题目。"),
    shuffle_questions => ("Shuffle questions", "随机题目顺序"),
    shuffle_choices => ("Shuffle answer choices", "随机选项顺序"),
    publication_history => ("Publication history", "发布历史"),
    revision => ("Revision", "版本"),
    published_at => ("Published at", "发布时间"),
    activate => ("Activate", "重新启用"),
    active => ("Active", "当前生效"),
    historical => ("Historical", "历史版本"),
    import_help => ("Paste a complete question-bank JSON document. The server validates its schema and writes it atomically.", "粘贴完整题库 JSON 文档；服务器将校验格式并原子写入。"),
}

#[derive(Clone)]
pub struct WebState {
    db: Db,
    catalog: Arc<QuizCatalog>,
    quiz_lock: Arc<Mutex<()>>,
    login_throttle: Arc<Mutex<LoginThrottle>>,
    password_hash: String,
    session_secret: Arc<Vec<u8>>,
    session_ttl_seconds: u64,
}

#[derive(Default)]
struct LoginThrottle {
    window_started_at: u64,
    failures: u32,
    blocked_until: u64,
}

impl LoginThrottle {
    fn is_blocked(&mut self, now: u64) -> bool {
        if self.blocked_until > now {
            return true;
        }
        if now.saturating_sub(self.window_started_at) >= LOGIN_FAILURE_WINDOW_SECONDS {
            self.window_started_at = now;
            self.failures = 0;
            self.blocked_until = 0;
        }
        false
    }

    fn record(&mut self, success: bool, now: u64) {
        if success {
            *self = Self::default();
            return;
        }
        if self.window_started_at == 0
            || now.saturating_sub(self.window_started_at) >= LOGIN_FAILURE_WINDOW_SECONDS
        {
            self.window_started_at = now;
            self.failures = 0;
        }
        self.failures += 1;
        if self.failures >= LOGIN_FAILURE_LIMIT {
            self.blocked_until = now.saturating_add(LOGIN_BLOCK_SECONDS);
        }
    }
}

#[derive(Clone, Debug)]
struct Session {
    nonce: String,
    expires_at: u64,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    csrf: String,
    error: String,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "overview.html")]
struct OverviewTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    metrics: OverviewMetrics,
    quiz: Quiz,
    bank_count: usize,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "people.html")]
struct PeopleTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    people: Vec<PersonAdminView>,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "person.html")]
struct PersonTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    item: PersonAdminView,
    labels: Labels,
    current_path: String,
}

#[derive(Template)]
#[template(path = "banks.html")]
struct BanksTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    banks: Vec<BankOption>,
    catalog_enabled: bool,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "bank.html")]
struct BankTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    quiz: Quiz,
    bank_id: String,
    legacy: bool,
    reference_count: usize,
    environment: &'static str,
    questions: Vec<QuestionAdminView>,
    answer_options: Vec<AnswerOption>,
    labels: Labels,
    current_path: String,
}

#[derive(Template)]
#[template(path = "tests.html")]
struct TestsTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    tests: Vec<TestAdminView>,
    banks: Vec<BankOption>,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "test.html")]
struct TestTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    test: TestAdminView,
    banks: Vec<BankOption>,
    publications: Vec<PublicationAdminView>,
    labels: Labels,
    current_path: String,
}

#[derive(Default)]
struct OverviewMetrics {
    people: usize,
    enabled_people: usize,
    passed_people: usize,
    active_keys: usize,
    configured_accounts: usize,
    attempts: u32,
}

struct PersonAdminView {
    person: PersonRecord,
    keys: Vec<KeyRecord>,
    attempt_count: u32,
}

struct TestAdminView {
    test: TestDefinitionRecord,
    bank_names: String,
    question_count: usize,
    published: bool,
    revision: String,
}

struct PublicationAdminView {
    publication_id: i64,
    revision: String,
    question_count: usize,
    published_at: String,
    active: bool,
}

struct QuestionAdminView {
    index: usize,
    number: usize,
    prompt: String,
    choices_text: String,
    correct_index: usize,
    answer_options: Vec<AnswerOption>,
}

#[derive(Clone)]
struct AnswerOption {
    index: usize,
    number: usize,
}

#[derive(Clone)]
struct BankOption {
    position: usize,
    id: String,
    title: String,
    environment: &'static str,
    question_count: usize,
    legacy: bool,
    selected: bool,
}

#[derive(Default, Deserialize)]
struct LanguageQuery {
    next: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    csrf: String,
    password: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Deserialize)]
struct ConfirmForm {
    csrf: String,
    confirm: Option<String>,
}

#[derive(Deserialize)]
struct CreatePersonForm {
    csrf: String,
    display_name: String,
    unix_username: String,
}

#[derive(Deserialize)]
struct ToggleForm {
    csrf: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct AddKeyForm {
    csrf: String,
    public_key: String,
}

#[derive(Deserialize)]
struct UnixAccountForm {
    csrf: String,
    unix_username: String,
}

#[derive(Deserialize)]
struct PersonProfileForm {
    csrf: String,
    display_name: String,
    unix_username: String,
}

#[derive(Deserialize)]
struct ImportBankForm {
    csrf: String,
    bank_id: String,
    json: String,
}

#[derive(Deserialize)]
struct TestForm {
    csrf: String,
    test_id: String,
    title: String,
    #[serde(default)]
    bank_ids: String,
    pass_threshold_percent: String,
    max_attempts: String,
    #[serde(default)]
    question_limit: String,
    shuffle_questions: Option<String>,
    shuffle_choices: Option<String>,
    #[serde(flatten)]
    bank_selections: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ExamSettingsForm {
    csrf: String,
    title: String,
    pass_threshold_percent: String,
    max_attempts: String,
    environment: String,
}

#[derive(Deserialize)]
struct QuestionForm {
    csrf: String,
    prompt: String,
    choices: String,
    correct_index: String,
}

impl WebState {
    pub fn new(db: Db, quiz_path: PathBuf, auth: &AdminAuthConfig) -> Result<Self> {
        Self::new_with_catalog(db, quiz_path, None, auth)
    }

    pub fn new_with_catalog(
        db: Db,
        quiz_path: PathBuf,
        quiz_directory: Option<PathBuf>,
        auth: &AdminAuthConfig,
    ) -> Result<Self> {
        auth.validate()?;
        let catalog = QuizCatalog::new(quiz_path.clone(), quiz_directory);
        catalog.ensure_writable().with_context(|| {
            format!(
                "admin cannot manage quiz catalog for {}; grant the service account write access to the quiz file and configured catalog directory",
                quiz_path.display()
            )
        })?;
        db.ensure_legacy_test(&catalog.load(LEGACY_BANK_ID)?)?;
        Ok(Self {
            db,
            catalog: Arc::new(catalog),
            quiz_lock: Arc::new(Mutex::new(())),
            login_throttle: Arc::new(Mutex::new(LoginThrottle::default())),
            password_hash: auth.password_hash.clone(),
            session_secret: Arc::new(auth.session_secret()?),
            session_ttl_seconds: auth.session_ttl_seconds,
        })
    }
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/people", get(people_page))
        .route("/people/:id", get(person_page))
        .route("/banks", get(banks_page).post(import_bank))
        .route("/banks/:bank_id", get(bank_page))
        .route("/banks/:bank_id/export", get(export_bank))
        .route("/banks/:bank_id/delete", post(delete_bank))
        .route("/tests", get(tests_page).post(create_test))
        .route("/tests/:test_id", get(test_page).post(update_test))
        .route("/tests/:test_id/delete", post(delete_test))
        .route("/tests/:test_id/publish", post(publish_test))
        .route(
            "/tests/:test_id/publications/:publication_id/activate",
            post(activate_publication),
        )
        .route("/exam", get(legacy_exam_redirect))
        .route("/language/:language", get(select_language))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/persons", post(create_person))
        .route("/persons/:id/unix-account", post(update_unix_account))
        .route("/persons/:id/profile", post(update_person_profile))
        .route("/persons/:id/enabled", post(toggle_person))
        .route("/persons/:id/reset", post(reset_exam))
        .route("/persons/:id/delete", post(delete_person))
        .route("/persons/:id/keys", post(add_key))
        .route("/people/:person_id/keys/:id/enabled", post(toggle_key))
        .route("/people/:person_id/keys/:id/remove", post(remove_key))
        .route("/banks/:bank_id/settings", post(update_exam_settings))
        .route("/banks/:bank_id/questions", post(add_exam_question))
        .route(
            "/banks/:bank_id/questions/:index/edit",
            post(edit_exam_question),
        )
        .route(
            "/banks/:bank_id/questions/:index/delete",
            post(delete_exam_question),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

pub fn hash_password(password: &[u8]) -> Result<String> {
    if password.is_empty() || password.len() > 1024 {
        anyhow::bail!("password must contain between 1 and 1024 bytes");
    }
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password, &salt)
        .map_err(|error| anyhow::anyhow!("failed to hash password: {error}"))?
        .to_string())
}

async fn login_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if session_from_headers(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    let language = language_from_headers(&headers);
    render_login(&state, language, String::new())
}

async fn login(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !validate_login_csrf(&state, &headers, &form.csrf) {
        return localized_response(
            StatusCode::FORBIDDEN,
            language_from_headers(&headers),
            "request validation failed",
            "请求验证失败",
        );
    }
    let now = unix_time();
    let blocked = match state.login_throttle.lock() {
        Ok(mut throttle) => throttle.is_blocked(now),
        Err(_) => {
            return localized_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                language_from_headers(&headers),
                "login service unavailable",
                "登录服务不可用",
            )
        }
    };
    if blocked {
        return localized_response(
            StatusCode::TOO_MANY_REQUESTS,
            language_from_headers(&headers),
            "too many failed login attempts; try again shortly",
            "登录失败次数过多，请稍后重试",
        );
    }
    let hash = state.password_hash.clone();
    let password = form.password.into_bytes();
    let verified = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).ok().is_some_and(|parsed| {
            Argon2::default()
                .verify_password(&password, &parsed)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false);
    if let Ok(mut throttle) = state.login_throttle.lock() {
        throttle.record(verified, now);
    }
    if !verified {
        let language = language_from_headers(&headers);
        let mut response = render_login(
            &state,
            language,
            language.text("Invalid password", "密码无效"),
        );
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return response;
    }
    let session = new_session(&state);
    let value = encode_session(&state, &session);
    let mut response = Redirect::to("/").into_response();
    append_set_cookie(
        &mut response,
        &format!(
            "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            state.session_ttl_seconds
        ),
    );
    append_set_cookie(
        &mut response,
        &format!("{LOGIN_CSRF_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    response
}

async fn overview(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_overview(&state, &session, language, notice, StatusCode::OK).await;
    clear_flash(&mut response);
    response
}

async fn people_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_people(
        &state,
        &session,
        language,
        notice,
        String::new(),
        StatusCode::OK,
    );
    clear_flash(&mut response);
    response
}

async fn person_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_person(
        &state,
        &session,
        language,
        id,
        notice,
        String::new(),
        StatusCode::OK,
    );
    clear_flash(&mut response);
    response
}

async fn banks_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_banks(
        &state,
        &session,
        language,
        notice,
        String::new(),
        StatusCode::OK,
    )
    .await;
    clear_flash(&mut response);
    response
}

async fn bank_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
) -> Response {
    render_bank_page(state, headers, bank_id).await
}

async fn render_bank_page(state: WebState, headers: HeaderMap, bank_id: String) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_bank(
        &state,
        &session,
        language,
        &bank_id,
        notice,
        String::new(),
        StatusCode::OK,
    )
    .await;
    clear_flash(&mut response);
    response
}

async fn export_bank(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
) -> Response {
    if session_from_headers(&state, &headers).is_none() {
        return Redirect::to("/login").into_response();
    }
    if validate_bank_id(&bank_id).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state
        .catalog
        .load(&bank_id)
        .and_then(|quiz| quiz.to_pretty_json())
    {
        Ok(body) => (
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{bank_id}.json\""),
                ),
            ],
            body,
        )
            .into_response(),
        Err(error) => localized_response(
            StatusCode::NOT_FOUND,
            language_from_headers(&headers),
            &format!("question bank unavailable: {error}"),
            &format!("题库不可用：{error}"),
        ),
    }
}

async fn tests_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_tests(
        &state,
        &session,
        language,
        notice,
        String::new(),
        StatusCode::OK,
    )
    .await;
    clear_flash(&mut response);
    response
}

async fn test_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(test_id): AxumPath<String>,
) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_test(
        &state,
        &session,
        language,
        &test_id,
        notice,
        String::new(),
        StatusCode::OK,
    )
    .await;
    clear_flash(&mut response);
    response
}

async fn legacy_exam_redirect() -> Redirect {
    Redirect::to("/tests")
}

async fn select_language(
    State(_state): State<WebState>,
    AxumPath(language): AxumPath<String>,
    Query(query): Query<LanguageQuery>,
) -> Response {
    let Ok(language) = language.parse::<WebLanguage>() else {
        return (StatusCode::BAD_REQUEST, "invalid language / 无效语言").into_response();
    };
    let next = safe_return_path(query.next.as_deref());
    let mut response = Redirect::to(&next).into_response();
    append_set_cookie(
        &mut response,
        &format!(
            "{LANGUAGE_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000",
            language.code()
        ),
    );
    response
}

async fn logout(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Ok(_) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let mut response = Redirect::to("/login").into_response();
    append_set_cookie(
        &mut response,
        &format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    response
}

async fn create_person(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<CreatePersonForm>,
) -> Response {
    let Ok(_) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let unix_username = optional_text(&form.unix_username);
    match state
        .db
        .create_person(&form.display_name, unix_username.as_deref())
    {
        Ok(id) => flash_redirect(&state, &format!("/people/{id}"), "person-created"),
        Err(error) => {
            let language = language_from_headers(&headers);
            let session = session_from_headers(&state, &headers).expect("authorized session");
            render_people(
                &state,
                &session,
                language,
                String::new(),
                public_db_error(&error, language),
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

async fn delete_person(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    if form.confirm.as_deref() != Some("on") {
        return render_person(
            &state,
            &session,
            language,
            id,
            String::new(),
            language.text(
                "Confirm the deletion with the checkbox.",
                "请先勾选确认框以执行删除。",
            ),
            StatusCode::BAD_REQUEST,
        );
    }
    match state.db.delete_person(id) {
        Ok(()) => flash_redirect(&state, "/people", "person-deleted"),
        Err(error) => render_person(
            &state,
            &session,
            language,
            id,
            String::new(),
            public_db_error(&error, language),
            match error {
                GateError::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            },
        ),
    }
}

async fn toggle_person(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<ToggleForm>,
) -> Response {
    mutate_person(&state, &headers, &form.csrf, id, "person-updated", || {
        state.db.set_person_enabled(id, form.enabled)
    })
}

async fn reset_exam(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_person(&state, &headers, &form.csrf, id, "exam-reset", || {
        state.db.reset_exam(id)
    })
}

async fn update_unix_account(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<UnixAccountForm>,
) -> Response {
    let unix_username = optional_text(&form.unix_username);
    mutate_person(
        &state,
        &headers,
        &form.csrf,
        id,
        "unix-account-updated",
        || {
            state
                .db
                .set_person_unix_username(id, unix_username.as_deref())
        },
    )
}

async fn update_person_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<PersonProfileForm>,
) -> Response {
    let unix_username = optional_text(&form.unix_username);
    mutate_person(
        &state,
        &headers,
        &form.csrf,
        id,
        "person-profile-updated",
        || {
            state
                .db
                .update_person(id, &form.display_name, unix_username.as_deref())
        },
    )
}

async fn add_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<AddKeyForm>,
) -> Response {
    mutate_person(&state, &headers, &form.csrf, id, "key-added", || {
        state.db.add_key(id, &form.public_key).map(|_| ())
    })
}

async fn toggle_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath((person_id, id)): AxumPath<(i64, i64)>,
    Form(form): Form<ToggleForm>,
) -> Response {
    mutate_person(
        &state,
        &headers,
        &form.csrf,
        person_id,
        "key-updated",
        || {
            if !state
                .db
                .get_person(person_id)?
                .keys
                .iter()
                .any(|key| key.id == id)
            {
                return Err(GateError::NotFound);
            }
            state.db.set_key_enabled(id, form.enabled)
        },
    )
}

async fn remove_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath((person_id, id)): AxumPath<(i64, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_person(
        &state,
        &headers,
        &form.csrf,
        person_id,
        "key-removed",
        || {
            if !state
                .db
                .get_person(person_id)?
                .keys
                .iter()
                .any(|key| key.id == id)
            {
                return Err(GateError::NotFound);
            }
            state.db.remove_key(id)
        },
    )
}

async fn update_exam_settings(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
    Form(form): Form<ExamSettingsForm>,
) -> Response {
    let title = form.title.trim().to_owned();
    let threshold = form.pass_threshold_percent.parse::<u32>();
    let attempts = form.max_attempts.parse::<u32>();
    let environment = parse_environment(&form.environment);
    mutate_quiz(
        state,
        headers,
        form.csrf,
        bank_id,
        "settings-updated",
        move |quiz| {
            quiz.environment = environment?;
            quiz.update_settings(
                title,
                threshold.context("pass threshold must be a whole number")?,
                attempts.context("maximum attempts must be a whole number")?,
            )
        },
    )
    .await
}

async fn add_exam_question(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
    Form(form): Form<QuestionForm>,
) -> Response {
    let question = parse_question(&form);
    mutate_quiz(
        state,
        headers,
        form.csrf,
        bank_id,
        "question-added",
        move |quiz| quiz.add_question(question?),
    )
    .await
}

async fn edit_exam_question(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath((bank_id, index)): AxumPath<(String, usize)>,
    Form(form): Form<QuestionForm>,
) -> Response {
    let question = parse_question(&form);
    mutate_quiz(
        state,
        headers,
        form.csrf,
        bank_id,
        "question-updated",
        move |quiz| quiz.edit_question(index, question?),
    )
    .await
}

async fn delete_exam_question(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath((bank_id, index)): AxumPath<(String, usize)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_quiz(
        state,
        headers,
        form.csrf,
        bank_id,
        "question-deleted",
        move |quiz| quiz.delete_question(index),
    )
    .await
}

async fn import_bank(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<ImportBankForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    let bank_id = form.bank_id.trim().to_owned();
    let catalog = state.catalog.clone();
    let lock = state.quiz_lock.clone();
    let import_id = bank_id.clone();
    let raw = form.json.into_bytes();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = lock
            .lock()
            .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
        catalog.import(&import_id, &raw)
    })
    .await;
    match result {
        Ok(Ok(_)) => flash_redirect(&state, &format!("/banks/{bank_id}"), "bank-imported"),
        Ok(Err(error)) => {
            render_banks(
                &state,
                &session,
                language,
                String::new(),
                localized_error(language, &error.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "quiz import task failed",
            "题库导入任务失败",
        ),
    }
}

async fn delete_bank(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    if form.confirm.as_deref() != Some("on") {
        return render_bank(
            &state,
            &session,
            language,
            &bank_id,
            String::new(),
            language.text(
                "Confirm the deletion with the checkbox.",
                "请先勾选确认框以执行删除。",
            ),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    let catalog = state.catalog.clone();
    let db = state.db.clone();
    let lock = state.quiz_lock.clone();
    let delete_id = bank_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = lock
            .lock()
            .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
        if !db.tests_using_bank(&delete_id)?.is_empty() {
            return Err(anyhow::anyhow!(
                "question bank is referenced by a saved test"
            ));
        }
        catalog.delete(&delete_id)
    })
    .await;
    match result {
        Ok(Ok(())) => flash_redirect(&state, "/banks", "bank-deleted"),
        Ok(Err(error)) => {
            render_bank(
                &state,
                &session,
                language,
                &bank_id,
                String::new(),
                localized_error(language, &error.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "quiz delete task failed",
            "题库删除任务失败",
        ),
    }
}

async fn create_test(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<TestForm>,
) -> Response {
    mutate_test_definition(state, headers, form, None).await
}

async fn update_test(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(test_id): AxumPath<String>,
    Form(form): Form<TestForm>,
) -> Response {
    mutate_test_definition(state, headers, form, Some(test_id)).await
}

async fn delete_test(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(test_id): AxumPath<String>,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    if form.confirm.as_deref() != Some("on") {
        return render_test(
            &state,
            &session,
            language,
            &test_id,
            String::new(),
            language.text(
                "Confirm the deletion with the checkbox.",
                "请先勾选确认框以执行删除。",
            ),
            StatusCode::BAD_REQUEST,
        )
        .await;
    }
    match state.db.delete_test(&test_id) {
        Ok(()) => flash_redirect(&state, "/tests", "test-deleted"),
        Err(error) => {
            render_test(
                &state,
                &session,
                language,
                &test_id,
                String::new(),
                public_db_error(&error, language),
                match error {
                    GateError::NotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_REQUEST,
                },
            )
            .await
        }
    }
}

async fn mutate_test_definition(
    state: WebState,
    headers: HeaderMap,
    form: TestForm,
    existing_id: Option<String>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    let input = parse_test_form(&form);
    let result = input.and_then(|input| {
        let _guard = state
            .quiz_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
        state.catalog.compose(
            input.title.clone(),
            &input.bank_ids,
            CompositionOptions {
                pass_threshold_percent: input.pass_threshold_percent,
                max_attempts: input.max_attempts,
                question_limit: input.question_limit,
                shuffle_questions: input.shuffle_questions,
                shuffle_choices: input.shuffle_choices,
            },
        )?;
        match existing_id.as_deref() {
            Some(id) => state
                .db
                .update_test(id, &input)
                .map_err(anyhow::Error::from),
            None => state.db.create_test(&input).map_err(anyhow::Error::from),
        }?;
        Ok(input.id)
    });
    match result {
        Ok(test_id) => flash_redirect(
            &state,
            &format!("/tests/{test_id}"),
            if existing_id.is_some() {
                "test-updated"
            } else {
                "test-created"
            },
        ),
        Err(error) => match existing_id {
            Some(test_id) => {
                render_test(
                    &state,
                    &session,
                    language,
                    &test_id,
                    String::new(),
                    localized_error(language, &error.to_string()),
                    StatusCode::BAD_REQUEST,
                )
                .await
            }
            None => {
                render_tests(
                    &state,
                    &session,
                    language,
                    String::new(),
                    localized_error(language, &error.to_string()),
                    StatusCode::BAD_REQUEST,
                )
                .await
            }
        },
    }
}

async fn publish_test(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(test_id): AxumPath<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    let result = (|| -> Result<PublishedTest> {
        let _guard = state
            .quiz_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
        let test = state.db.get_test(&test_id)?;
        let quiz = state.catalog.compose(
            test.title,
            &test.bank_ids,
            CompositionOptions {
                pass_threshold_percent: test.pass_threshold_percent,
                max_attempts: test.max_attempts,
                question_limit: test.question_limit,
                shuffle_questions: test.shuffle_questions,
                shuffle_choices: test.shuffle_choices,
            },
        )?;
        Ok(state.db.publish_test(&test_id, &quiz)?)
    })();
    match result {
        Ok(_) => flash_redirect(&state, &format!("/tests/{test_id}"), "test-published"),
        Err(error) => {
            render_test(
                &state,
                &session,
                language,
                &test_id,
                String::new(),
                localized_error(language, &error.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
    }
}

async fn activate_publication(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath((test_id, publication_id)): AxumPath<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    match state.db.activate_publication(&test_id, publication_id) {
        Ok(_) => flash_redirect(
            &state,
            &format!("/tests/{test_id}"),
            "publication-activated",
        ),
        Err(error) => {
            render_test(
                &state,
                &session,
                language,
                &test_id,
                String::new(),
                public_db_error(&error, language),
                match error {
                    GateError::NotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_REQUEST,
                },
            )
            .await
        }
    }
}

fn parse_test_form(form: &TestForm) -> Result<TestDefinitionInput> {
    let mut checkbox_banks = form
        .bank_selections
        .iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("bank_")?
                .parse::<usize>()
                .ok()
                .map(|position| (position, value.as_str()))
        })
        .collect::<Vec<_>>();
    checkbox_banks.sort_by_key(|(position, _)| *position);
    let bank_values = if checkbox_banks.is_empty() {
        vec![form.bank_ids.as_str()]
    } else {
        checkbox_banks.into_iter().map(|(_, value)| value).collect()
    };
    let bank_ids = bank_values
        .into_iter()
        .flat_map(str::lines)
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let question_limit = optional_text(&form.question_limit)
        .map(|value| {
            value
                .parse::<u32>()
                .context("question limit must be a whole number")
        })
        .transpose()?;
    Ok(TestDefinitionInput {
        id: form.test_id.trim().to_owned(),
        title: form.title.trim().to_owned(),
        bank_ids,
        pass_threshold_percent: form
            .pass_threshold_percent
            .parse()
            .context("pass threshold must be a whole number")?,
        max_attempts: form
            .max_attempts
            .parse()
            .context("maximum attempts must be a whole number")?,
        question_limit,
        shuffle_questions: form.shuffle_questions.is_some(),
        shuffle_choices: form.shuffle_choices.is_some(),
    })
}

fn optional_text(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn mutate_person(
    state: &WebState,
    headers: &HeaderMap,
    csrf: &str,
    person_id: i64,
    success_code: &'static str,
    operation: impl FnOnce() -> Result<(), GateError>,
) -> Response {
    let Ok(session) = authorize_mutation(state, headers, csrf) else {
        return mutation_rejection(state, headers);
    };
    match operation() {
        Ok(()) => flash_redirect(state, &format!("/people/{person_id}"), success_code),
        Err(error) => render_person(
            state,
            &session,
            language_from_headers(headers),
            person_id,
            String::new(),
            public_db_error(&error, language_from_headers(headers)),
            match error {
                GateError::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            },
        ),
    }
}

async fn mutate_quiz(
    state: WebState,
    headers: HeaderMap,
    csrf: String,
    bank_id: String,
    success_code: &'static str,
    operation: impl FnOnce(&mut Quiz) -> Result<()> + Send + 'static,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let catalog = state.catalog.clone();
    let lock = state.quiz_lock.clone();
    let update_id = bank_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _guard = lock
            .lock()
            .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
        catalog.update(&update_id, operation)
    })
    .await;

    match result {
        Ok(Ok(_)) => flash_redirect(&state, &format!("/banks/{bank_id}"), success_code),
        Ok(Err(error)) => {
            render_bank(
                &state,
                &session,
                language_from_headers(&headers),
                &bank_id,
                String::new(),
                localized_error(language_from_headers(&headers), &error.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language_from_headers(&headers),
            "quiz update task failed",
            "题库更新任务失败",
        ),
    }
}

fn parse_question(form: &QuestionForm) -> Result<Question> {
    parse_question_fields(&form.prompt, &form.choices, &form.correct_index)
}

fn parse_question_fields(prompt: &str, choices: &str, correct_index: &str) -> Result<Question> {
    let choices = choices
        .lines()
        .map(str::trim)
        .filter(|choice| !choice.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let correct_index = correct_index
        .parse::<usize>()
        .context("correct answer selection is invalid")?;
    Ok(Question {
        prompt: prompt.trim().to_owned(),
        choices,
        correct_index,
    })
}

fn parse_environment(value: &str) -> Result<BankEnvironment> {
    match value {
        "host" => Ok(BankEnvironment::Host),
        "docker" => Ok(BankEnvironment::Docker),
        "network" => Ok(BankEnvironment::Network),
        "general" => Ok(BankEnvironment::General),
        _ => anyhow::bail!("invalid bank environment"),
    }
}

fn authorize_mutation(
    state: &WebState,
    headers: &HeaderMap,
    csrf: &str,
) -> std::result::Result<Session, ()> {
    let session = session_from_headers(state, headers).ok_or(())?;
    if csrf_for_session(state, &session) != csrf {
        return Err(());
    }
    Ok(session)
}

fn mutation_rejection(state: &WebState, headers: &HeaderMap) -> Response {
    if session_from_headers(state, headers).is_some() {
        localized_response(
            StatusCode::FORBIDDEN,
            language_from_headers(headers),
            "request validation failed",
            "请求验证失败",
        )
    } else {
        Redirect::to("/login").into_response()
    }
}

fn render_login(state: &WebState, language: WebLanguage, error: String) -> Response {
    let mut random = [0_u8; 32];
    RandOsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    let signed = sign_value(state, "login", &token);
    let template = LoginTemplate {
        csrf: token,
        error,
        labels: labels(language),
        current_path: "/login",
    };
    let mut response = render_template(&template);
    append_set_cookie(
        &mut response,
        &format!(
            "{LOGIN_CSRF_COOKIE}={signed}; Path=/login; HttpOnly; SameSite=Strict; Max-Age=600"
        ),
    );
    response
}

async fn render_overview(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    notice: String,
    status: StatusCode,
) -> Response {
    let people = match state.db.list_people() {
        Ok(people) => people,
        Err(_) => {
            return localized_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                language,
                "database error",
                "数据库错误",
            )
        }
    };
    let banks = match load_banks(state.catalog.clone()).await {
        Ok(banks) => banks,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                localized_error(language, &format!("quiz catalog error: {error}")),
            )
                .into_response()
        }
    };
    let quiz = match state.db.published_test() {
        Ok(Some(published)) => published.quiz,
        Ok(None) => banks
            .first()
            .expect("catalog always includes the legacy bank")
            .quiz
            .clone(),
        Err(_) => {
            return localized_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                language,
                "database error",
                "数据库错误",
            )
        }
    };
    let metrics = overview_metrics(&people);
    let template = OverviewTemplate {
        csrf: csrf_for_session(state, session),
        active_page: "overview",
        notice,
        metrics,
        quiz,
        bank_count: banks.len(),
        labels: labels(language),
        current_path: "/",
    };
    response_with_status(render_template(&template), status)
}

fn render_people(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    match state.db.list_people() {
        Ok(people) => {
            let template = PeopleTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "people",
                notice,
                error,
                people: people.into_iter().map(person_admin_view).collect(),
                labels: labels(language),
                current_path: "/people",
            };
            response_with_status(render_template(&template), status)
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "database error",
            "数据库错误",
        ),
    }
}

fn render_person(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    person_id: i64,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    match state.db.get_person(person_id) {
        Ok(item) => {
            let template = PersonTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "people",
                notice,
                error,
                item: person_admin_view(item),
                labels: labels(language),
                current_path: format!("/people/{person_id}"),
            };
            response_with_status(render_template(&template), status)
        }
        Err(GateError::NotFound) => localized_response(
            StatusCode::NOT_FOUND,
            language,
            "person not found",
            "未找到人员",
        ),
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "database error",
            "数据库错误",
        ),
    }
}

async fn render_banks(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    match load_banks(state.catalog.clone()).await {
        Ok(banks) => {
            let template = BanksTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "banks",
                notice,
                error,
                banks: bank_options(&banks),
                catalog_enabled: state.catalog.catalog_directory().is_some(),
                labels: labels(language),
                current_path: "/banks",
            };
            response_with_status(render_template(&template), status)
        }
        Err(error) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            &format!("quiz catalog error: {error}"),
            &format!("题库目录错误：{error}"),
        ),
    }
}

async fn render_bank(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    bank_id: &str,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    match load_banks(state.catalog.clone()).await {
        Ok(banks) => {
            let Some(selected) = banks.iter().find(|bank| bank.id == bank_id) else {
                return localized_response(
                    StatusCode::NOT_FOUND,
                    language,
                    "quiz bank not found",
                    "未找到题库",
                );
            };
            let quiz = selected.quiz.clone();
            let reference_count = match state.db.tests_using_bank(bank_id) {
                Ok(references) => references.len(),
                Err(_) => {
                    return localized_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        language,
                        "database error",
                        "数据库错误",
                    )
                }
            };
            let environment = quiz.environment.as_str();
            let questions = quiz
                .questions
                .iter()
                .enumerate()
                .map(|(index, question)| QuestionAdminView {
                    index,
                    number: index + 1,
                    prompt: question.prompt.clone(),
                    choices_text: question.choices.join("\n"),
                    correct_index: question.correct_index,
                    answer_options: answer_options(question.choices.len()),
                })
                .collect();
            let template = BankTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "banks",
                notice,
                error,
                quiz,
                bank_id: bank_id.to_owned(),
                legacy: selected.legacy,
                reference_count,
                environment,
                questions,
                answer_options: answer_options(20),
                labels: labels(language),
                current_path: format!("/banks/{bank_id}"),
            };
            response_with_status(render_template(&template), status)
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            localized_error(language, &format!("quiz catalog error: {error}")),
        )
            .into_response(),
    }
}

async fn render_tests(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    let banks = match load_banks(state.catalog.clone()).await {
        Ok(banks) => banks,
        Err(error) => {
            return localized_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                language,
                &format!("quiz catalog error: {error}"),
                &format!("题库目录错误：{error}"),
            )
        }
    };
    match test_admin_views(state, &banks) {
        Ok(tests) => {
            let template = TestsTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "tests",
                notice,
                error,
                tests,
                banks: bank_options(&banks),
                labels: labels(language),
                current_path: "/tests",
            };
            response_with_status(render_template(&template), status)
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "database error",
            "数据库错误",
        ),
    }
}

async fn render_test(
    state: &WebState,
    session: &Session,
    language: WebLanguage,
    test_id: &str,
    notice: String,
    error: String,
    status: StatusCode,
) -> Response {
    let banks = match load_banks(state.catalog.clone()).await {
        Ok(banks) => banks,
        Err(error) => {
            return localized_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                language,
                &format!("quiz catalog error: {error}"),
                &format!("题库目录错误：{error}"),
            )
        }
    };
    match test_admin_views(state, &banks) {
        Ok(tests) => {
            let Some(test) = tests.into_iter().find(|test| test.test.id == test_id) else {
                return localized_response(
                    StatusCode::NOT_FOUND,
                    language,
                    "test not found",
                    "未找到测试",
                );
            };
            let bank_options = bank_options_for_test(&banks, &test.test.bank_ids);
            let publications = match state.db.list_publications(test_id) {
                Ok(publications) => publications
                    .into_iter()
                    .map(publication_admin_view)
                    .collect(),
                Err(_) => {
                    return localized_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        language,
                        "database error",
                        "数据库错误",
                    )
                }
            };
            let template = TestTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "tests",
                notice,
                error,
                test,
                banks: bank_options,
                publications,
                labels: labels(language),
                current_path: format!("/tests/{test_id}"),
            };
            response_with_status(render_template(&template), status)
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "database error",
            "数据库错误",
        ),
    }
}

fn publication_admin_view(publication: PublicationRecord) -> PublicationAdminView {
    PublicationAdminView {
        publication_id: publication.publication_id,
        revision: publication.revision,
        question_count: publication
            .quiz
            .question_limit
            .unwrap_or(publication.quiz.questions.len() as u32) as usize,
        published_at: publication.published_at,
        active: publication.active,
    }
}

fn test_admin_views(state: &WebState, banks: &[QuizBank]) -> Result<Vec<TestAdminView>, GateError> {
    let active = state.db.published_test()?;
    state
        .db
        .list_tests()?
        .into_iter()
        .map(|test| {
            let question_count = test
                .bank_ids
                .iter()
                .filter_map(|id| banks.iter().find(|bank| &bank.id == id))
                .map(|bank| bank.quiz.questions.len())
                .sum();
            let bank_names = test.bank_ids.join(", ");
            let published = active
                .as_ref()
                .is_some_and(|publication| publication.test_id == test.id);
            let revision = active
                .as_ref()
                .filter(|publication| publication.test_id == test.id)
                .map(|publication| publication.revision.clone())
                .unwrap_or_default();
            Ok(TestAdminView {
                test,
                bank_names,
                question_count,
                published,
                revision,
            })
        })
        .collect()
}

async fn load_banks(catalog: Arc<QuizCatalog>) -> Result<Vec<QuizBank>> {
    tokio::task::spawn_blocking(move || catalog.discover())
        .await
        .context("quiz catalog load task failed")?
}

fn overview_metrics(people: &[PersonView]) -> OverviewMetrics {
    OverviewMetrics {
        people: people.len(),
        enabled_people: people.iter().filter(|item| item.person.enabled).count(),
        passed_people: people
            .iter()
            .filter(|item| item.person.passed_at.is_some())
            .count(),
        active_keys: people
            .iter()
            .flat_map(|item| &item.keys)
            .filter(|key| key.enabled)
            .count(),
        configured_accounts: people
            .iter()
            .filter(|item| item.person.unix_username.is_some())
            .count(),
        attempts: people.iter().map(|item| item.attempt_count).sum(),
    }
}

fn person_admin_view(item: PersonView) -> PersonAdminView {
    PersonAdminView {
        person: item.person,
        keys: item.keys,
        attempt_count: item.attempt_count,
    }
}

fn bank_options(banks: &[QuizBank]) -> Vec<BankOption> {
    banks
        .iter()
        .enumerate()
        .map(|(position, bank)| BankOption {
            position,
            id: bank.id.clone(),
            title: bank.quiz.title.clone(),
            environment: bank.quiz.environment.as_str(),
            question_count: bank.quiz.questions.len(),
            legacy: bank.legacy,
            selected: false,
        })
        .collect()
}

fn bank_options_for_test(banks: &[QuizBank], selected_ids: &[String]) -> Vec<BankOption> {
    let mut ordered = Vec::with_capacity(banks.len());
    for id in selected_ids {
        if let Some(bank) = banks.iter().find(|bank| &bank.id == id) {
            ordered.push(bank);
        }
    }
    ordered.extend(
        banks
            .iter()
            .filter(|bank| !selected_ids.iter().any(|id| id == &bank.id)),
    );
    ordered
        .into_iter()
        .enumerate()
        .map(|(position, bank)| BankOption {
            position,
            id: bank.id.clone(),
            title: bank.quiz.title.clone(),
            environment: bank.quiz.environment.as_str(),
            question_count: bank.quiz.questions.len(),
            legacy: bank.legacy,
            selected: selected_ids.iter().any(|id| id == &bank.id),
        })
        .collect()
}

fn answer_options(count: usize) -> Vec<AnswerOption> {
    (0..count)
        .map(|index| AnswerOption {
            index,
            number: index + 1,
        })
        .collect()
}

fn render_template(template: &impl Template) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response(),
    }
}

fn response_with_status(mut response: Response, status: StatusCode) -> Response {
    *response.status_mut() = status;
    response
}

async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

fn new_session(state: &WebState) -> Session {
    let mut nonce = [0_u8; 24];
    RandOsRng.fill_bytes(&mut nonce);
    Session {
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at: unix_time().saturating_add(state.session_ttl_seconds),
    }
}

fn encode_session(state: &WebState, session: &Session) -> String {
    let payload = format!("{}:{}", session.expires_at, session.nonce);
    sign_value(state, "session", &payload)
}

fn session_from_headers(state: &WebState, headers: &HeaderMap) -> Option<Session> {
    let signed = cookie(headers, SESSION_COOKIE)?;
    let payload = verify_value(state, "session", signed)?;
    let (expires, nonce) = payload.split_once(':')?;
    let expires_at = expires.parse::<u64>().ok()?;
    if expires_at < unix_time() || nonce.len() < 16 {
        return None;
    }
    Some(Session {
        nonce: nonce.to_owned(),
        expires_at,
    })
}

fn csrf_for_session(state: &WebState, session: &Session) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&state.session_secret).expect("HMAC accepts keys of any length");
    mac.update(b"csrf\0");
    mac.update(session.nonce.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn validate_login_csrf(state: &WebState, headers: &HeaderMap, submitted: &str) -> bool {
    cookie(headers, LOGIN_CSRF_COOKIE)
        .and_then(|signed| verify_value(state, "login", signed))
        .is_some_and(|token| token == submitted)
}

fn sign_value(state: &WebState, domain: &str, value: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&state.session_secret).expect("HMAC accepts keys of any length");
    mac.update(domain.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    format!(
        "{value}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn verify_value<'a>(state: &WebState, domain: &str, signed: &'a str) -> Option<&'a str> {
    let (value, signature) = signed.rsplit_once('.')?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(&state.session_secret).ok()?;
    mac.update(domain.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(value)
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| {
            part.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
        })
}

fn append_set_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn language_from_headers(headers: &HeaderMap) -> WebLanguage {
    cookie(headers, LANGUAGE_COOKIE)
        .and_then(|value| value.parse().ok())
        .unwrap_or(WebLanguage::Bilingual)
}

fn safe_return_path(value: Option<&str>) -> String {
    let value = value.unwrap_or("/");
    if matches!(value, "/" | "/people" | "/banks" | "/tests" | "/login") {
        return value.to_owned();
    }
    if let Some(person_id) = value.strip_prefix("/people/") {
        if !person_id.contains('/') && person_id.parse::<i64>().is_ok() {
            return value.to_owned();
        }
    }
    for prefix in ["/banks/", "/tests/"] {
        if let Some(id) = value.strip_prefix(prefix) {
            if !id.contains('/') && validate_bank_id(id).is_ok() {
                return value.to_owned();
            }
        }
    }
    if value == "/exam" {
        return value.to_owned();
    }
    "/".to_owned()
}

fn flash_redirect(state: &WebState, path: &str, code: &str) -> Response {
    let mut nonce = [0_u8; 12];
    RandOsRng.fill_bytes(&mut nonce);
    let payload = format!(
        "{}:{}:{code}",
        unix_time().saturating_add(60),
        URL_SAFE_NO_PAD.encode(nonce)
    );
    let signed = sign_value(state, "flash", &payload);
    let mut response = Redirect::to(path).into_response();
    append_set_cookie(
        &mut response,
        &format!("{FLASH_COOKIE}={signed}; Path=/; HttpOnly; SameSite=Strict; Max-Age=60"),
    );
    response
}

fn flash_message(state: &WebState, headers: &HeaderMap, language: WebLanguage) -> String {
    let Some(payload) =
        cookie(headers, FLASH_COOKIE).and_then(|value| verify_value(state, "flash", value))
    else {
        return String::new();
    };
    let mut fields = payload.splitn(3, ':');
    let Some(expires_at) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
        return String::new();
    };
    let Some(nonce) = fields.next() else {
        return String::new();
    };
    let Some(code) = fields.next() else {
        return String::new();
    };
    if expires_at < unix_time() || nonce.len() < 8 {
        return String::new();
    }
    match code {
        "person-created" => language.text("Person created.", "人员已创建。"),
        "person-deleted" => language.text("Person deleted.", "人员已删除。"),
        "person-updated" => language.text("Person status updated.", "人员状态已更新。"),
        "person-profile-updated" => language.text("Person saved.", "人员信息已保存。"),
        "exam-reset" => language.text(
            "Exam status and attempts reset.",
            "考试状态与尝试记录已重置。",
        ),
        "key-added" => language.text("Device key added.", "设备密钥已添加。"),
        "key-updated" => language.text("Device key status updated.", "设备密钥状态已更新。"),
        "key-removed" => language.text("Device key removed.", "设备密钥已移除。"),
        "unix-account-updated" => language.text("Unix account saved.", "Unix 账号已保存。"),
        "bank-created" => language.text("Quiz bank created.", "题库已创建。"),
        "bank-imported" => language.text("Question bank imported.", "题库已导入。"),
        "bank-deleted" => language.text("Question bank deleted.", "题库已删除。"),
        "settings-updated" => language.text("Exam settings saved.", "考试设置已保存。"),
        "question-added" => language.text("Question added.", "问题已添加。"),
        "question-updated" => language.text("Question saved.", "问题已保存。"),
        "question-deleted" => language.text("Question deleted.", "问题已删除。"),
        "test-created" => language.text("Test created.", "测试已创建。"),
        "test-updated" => language.text("Test saved.", "测试已保存。"),
        "test-deleted" => language.text("Test deleted.", "测试已删除。"),
        "test-published" => language.text(
            "Test published. Users must pass this revision before normal SSH access.",
            "测试已发布；用户必须通过此版本后才能正常使用 SSH。",
        ),
        "publication-activated" => {
            language.text("Published revision activated.", "已重新启用该发布版本。")
        }
        _ => String::new(),
    }
}

fn clear_flash(response: &mut Response) {
    append_set_cookie(
        response,
        &format!("{FLASH_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
}

fn localized_error(language: WebLanguage, error: &str) -> String {
    match language {
        WebLanguage::En => error.to_owned(),
        WebLanguage::Zh => format!("操作失败：{error}"),
        WebLanguage::Bilingual => format!("Operation failed / 操作失败: {error}"),
    }
}

fn localized_response(status: StatusCode, language: WebLanguage, en: &str, zh: &str) -> Response {
    (status, language.text(en, zh)).into_response()
}

fn unix_time() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs()
}

fn public_db_error(error: &GateError, language: WebLanguage) -> String {
    let english = match error {
        GateError::Invalid(message) | GateError::Conflict(message) => message.clone(),
        GateError::NotFound => "record not found".to_owned(),
        GateError::AttemptsExhausted => "maximum exam attempts reached".to_owned(),
        GateError::AlreadyPassed => "exam already passed".to_owned(),
        GateError::Database(_) => "database operation failed".to_owned(),
    };
    localized_error(language, &english)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{body::to_bytes, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        db::AttemptInput,
        quiz::{Question, Quiz},
    };

    const TEST_ADMIN_INPUT: &str = "unit-test-admin-input";

    struct Harness {
        _directory: TempDir,
        state: WebState,
        app: Router,
    }

    fn sample_quiz() -> Quiz {
        Quiz {
            title: "Safety".to_owned(),
            environment: crate::quiz::BankEnvironment::General,
            pass_threshold_percent: 80,
            max_attempts: 3,
            question_limit: None,
            shuffle_questions: true,
            shuffle_choices: true,
            questions: vec![Question {
                prompt: "Safe?".to_owned(),
                choices: vec!["Yes".to_owned(), "No".to_owned()],
                correct_index: 0,
            }],
        }
    }

    #[test]
    fn login_throttle_blocks_bursts_and_resets_after_success() {
        let mut throttle = LoginThrottle::default();
        for _ in 0..LOGIN_FAILURE_LIMIT {
            assert!(!throttle.is_blocked(100));
            throttle.record(false, 100);
        }
        assert!(throttle.is_blocked(100));
        assert!(!throttle.is_blocked(100 + LOGIN_BLOCK_SECONDS));
        throttle.record(false, 200);
        throttle.record(true, 200);
        assert_eq!(throttle.failures, 0);
        assert!(!throttle.is_blocked(200));
    }

    #[test]
    fn legacy_text_bank_selection_remains_supported() {
        let form = TestForm {
            csrf: "token".to_owned(),
            test_id: "onboarding".to_owned(),
            title: "Onboarding".to_owned(),
            bank_ids: "legacy\nhost-ssh".to_owned(),
            pass_threshold_percent: "80".to_owned(),
            max_attempts: "3".to_owned(),
            question_limit: String::new(),
            shuffle_questions: Some("on".to_owned()),
            shuffle_choices: None,
            bank_selections: BTreeMap::new(),
        };
        let parsed = parse_test_form(&form).unwrap();
        assert_eq!(parsed.bank_ids, ["legacy", "host-ssh"]);
        assert!(parsed.shuffle_questions);
        assert!(!parsed.shuffle_choices);
    }

    fn harness() -> Harness {
        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        db.initialize().unwrap();
        let quiz_path = directory.path().join("quiz.json");
        sample_quiz().save_atomic(&quiz_path).unwrap();
        let banks_path = directory.path().join("banks");
        std::fs::create_dir(&banks_path).unwrap();
        let auth = AdminAuthConfig {
            password_hash: hash_password(TEST_ADMIN_INPUT.as_bytes()).unwrap(),
            session_secret_base64: base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
            session_ttl_seconds: 3600,
        };
        let state = WebState::new_with_catalog(db, quiz_path, Some(banks_path), &auth).unwrap();
        let app = router(state.clone());
        Harness {
            _directory: directory,
            state,
            app,
        }
    }

    async fn login(app: &Router) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::get("/login")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let login_cookie = cookie_pair(response.headers(), LOGIN_CSRF_COOKIE);
        let body = response_body(response).await;
        let csrf = hidden_value(&body, "csrf");
        let response = app
            .clone()
            .oneshot(
                Request::post("/login")
                    .header(header::COOKIE, &login_cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "csrf={csrf}&password={TEST_ADMIN_INPUT}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let session_cookie = cookie_pair(response.headers(), SESSION_COOKIE);
        let response = app
            .clone()
            .oneshot(
                Request::get("/")
                    .header(header::COOKIE, &session_cookie)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let csrf = hidden_value(&response_body(response).await, "csrf");
        (session_cookie, csrf)
    }

    #[tokio::test]
    async fn login_cookie_is_signed_http_only_and_strict() {
        let harness = harness();
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/login")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().ok()?;
                value.starts_with(LOGIN_CSRF_COOKIE).then_some(value)
            })
            .unwrap();
        assert!(login_cookie.contains("HttpOnly"));
        assert!(login_cookie.contains("SameSite=Strict"));
        let (session, _) = login(&harness.app).await;
        assert!(session.starts_with(SESSION_COOKIE));
    }

    #[tokio::test]
    async fn security_headers_apply_to_html_and_rejections() {
        let harness = harness();
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/login")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().contains_key("content-security-policy"));
        assert_eq!(response.headers()["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn rejects_unauthenticated_and_bad_csrf_mutations() {
        let harness = harness();
        for (path, body) in [
            (
                "/banks/legacy/settings",
                "csrf=bad&title=Safety&environment=general&pass_threshold_percent=80&max_attempts=3",
            ),
            (
                "/banks/legacy/questions",
                "csrf=bad&prompt=Safe%3F&choices=Yes%0ANo&correct_index=0",
            ),
        ] {
            let response = form_post(&harness.app, path, "", body).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
        }
        let (session, _) = login(&harness.app).await;
        for (path, body) in [
            (
                "/banks/legacy/settings",
                "csrf=bad&title=Safety&environment=general&pass_threshold_percent=80&max_attempts=3",
            ),
            (
                "/banks/legacy/questions",
                "csrf=bad&prompt=Safe%3F&choices=Yes%0ANo&correct_index=0",
            ),
        ] {
            let response = form_post(&harness.app, path, &session, body).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn crud_validation_handles_duplicate_key_and_invalid_unix_user() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/persons",
            &session,
            &format!("csrf={csrf}&display_name=Alice&unix_username=root"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let person_id = harness.state.db.list_people().unwrap()[0].person.id;
        let encoded_key = "ssh-ed25519+aGVsbG8%3D+device";
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/keys"),
            &session,
            &format!("csrf={csrf}&public_key={encoded_key}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/keys"),
            &session,
            &format!("csrf={csrf}&public_key={encoded_key}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/unix-account"),
            &session,
            &format!("csrf={csrf}&unix_username=Invalid%21"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn people_mutations_disable_update_account_reset_and_remove() {
        let harness = harness();
        let person_id = harness
            .state
            .db
            .create_person("Mutation Test", Some("root"))
            .unwrap();
        let key = harness
            .state
            .db
            .add_key(person_id, "ssh-ed25519 aGVsbG8= device")
            .unwrap();
        let published = harness.state.db.published_test().unwrap().unwrap();
        harness
            .state
            .db
            .record_attempt(&AttemptInput {
                person_id,
                test_id: &published.test_id,
                revision: &published.revision,
                score: 1,
                total: 1,
                passed: true,
                answers_json: "[0]",
                max_attempts: 3,
            })
            .unwrap();
        let (session, csrf) = login(&harness.app).await;

        for (path, body) in [
            (
                format!("/persons/{person_id}/enabled"),
                format!("csrf={csrf}&enabled=false"),
            ),
            (
                format!("/persons/{person_id}/enabled"),
                format!("csrf={csrf}&enabled=true"),
            ),
            (
                format!("/persons/{person_id}/unix-account"),
                format!("csrf={csrf}&unix_username=root"),
            ),
        ] {
            assert_eq!(
                form_post(&harness.app, &path, &session, &body)
                    .await
                    .status(),
                StatusCode::SEE_OTHER
            );
        }
        for (path, body) in [
            (
                format!("/people/{person_id}/keys/{}/enabled", key.id),
                format!("csrf={csrf}&enabled=false"),
            ),
            (
                format!("/persons/{person_id}/reset"),
                format!("csrf={csrf}"),
            ),
            (
                format!("/people/{person_id}/keys/{}/remove", key.id),
                format!("csrf={csrf}"),
            ),
        ] {
            assert_eq!(
                form_post(&harness.app, &path, &session, &body)
                    .await
                    .status(),
                StatusCode::SEE_OTHER
            );
        }
        let view = &harness.state.db.list_people().unwrap()[0];
        assert!(view.person.passed_at.is_none());
        assert_eq!(view.attempt_count, 0);
        assert!(view.keys.is_empty());

        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/profile"),
            &session,
            &format!("csrf={csrf}&display_name=Renamed+Mutation&unix_username=root"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            harness
                .state
                .db
                .get_person(person_id)
                .unwrap()
                .person
                .display_name,
            "Renamed Mutation"
        );

        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/delete"),
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/delete"),
            &session,
            &format!("csrf={csrf}&confirm=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(harness.state.db.list_people().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exam_settings_and_question_crud_persist() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/banks/legacy/settings",
            &session,
            &format!("csrf={csrf}&title=Updated+Exam&environment=host&pass_threshold_percent=90&max_attempts=4"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let saved = harness.state.catalog.load(LEGACY_BANK_ID).unwrap();
        assert_eq!(saved.title, "Updated Exam");
        assert_eq!(saved.environment, BankEnvironment::Host);
        assert_eq!(saved.pass_threshold_percent, 90);
        assert_eq!(saved.max_attempts, 4);

        let response = form_post(
            &harness.app,
            "/banks/legacy/questions",
            &session,
            &format!("csrf={csrf}&prompt=Added%3F&choices=Wrong%0ARight&correct_index=1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/legacy/questions/1/edit",
            &session,
            &format!("csrf={csrf}&prompt=Edited%3F&choices=Right%0AWrong&correct_index=0"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let saved = harness.state.catalog.load(LEGACY_BANK_ID).unwrap();
        assert_eq!(saved.questions[1].prompt, "Edited?");
        assert_eq!(saved.questions[1].correct_index, 0);

        let response = form_post(
            &harness.app,
            "/banks/legacy/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/legacy/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            harness
                .state
                .catalog
                .load(LEGACY_BANK_ID)
                .unwrap()
                .questions
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn invalid_exam_settings_are_rejected_without_changing_file() {
        let harness = harness();
        let before = harness.state.catalog.load(LEGACY_BANK_ID).unwrap();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/banks/legacy/settings",
            &session,
            &format!("csrf={csrf}&title=Safety&environment=general&pass_threshold_percent=0&max_attempts=3"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(harness.state.catalog.load(LEGACY_BANK_ID).unwrap(), before);
    }

    #[tokio::test]
    async fn web_imports_views_and_mutates_a_bank() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/banks",
            &session,
            &format!(
                "csrf={csrf}&bank_id=host-ssh&json=%7B%22title%22%3A%22Host+SSH%22%2C%22environment%22%3A%22host%22%2C%22questions%22%3A%5B%7B%22prompt%22%3A%22Ready%3F%22%2C%22choices%22%3A%5B%22Yes%22%2C%22No%22%5D%2C%22correct_index%22%3A0%7D%5D%7D"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/banks/host-ssh");
        assert_eq!(
            harness.state.catalog.load("host-ssh").unwrap().environment,
            BankEnvironment::Host
        );
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/banks/host-ssh/export")
                    .header(header::COOKIE, &session)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );

        let response = form_post(
            &harness.app,
            "/banks/host-ssh/settings",
            &session,
            &format!("csrf={csrf}&title=Host+Access&environment=general&pass_threshold_percent=90&max_attempts=2"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/host-ssh/questions",
            &session,
            &format!("csrf={csrf}&prompt=Second%3F&choices=One%0ATwo&correct_index=1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/host-ssh/questions/1/edit",
            &session,
            &format!("csrf={csrf}&prompt=Edited%3F&choices=Right%0AWrong&correct_index=0"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/host-ssh/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/banks/host-ssh/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let saved = harness.state.catalog.load("host-ssh").unwrap();
        assert_eq!(saved.title, "Host Access");
        assert_eq!(saved.questions[0].prompt, "Edited?");

        let response = form_post(
            &harness.app,
            "/banks/host-ssh/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = form_post(
            &harness.app,
            "/banks/host-ssh/delete",
            &session,
            &format!("csrf={csrf}&confirm=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(harness.state.catalog.load("host-ssh").is_err());
    }

    #[tokio::test]
    async fn direct_account_is_independent_from_question_banks() {
        let harness = harness();
        harness
            .state
            .catalog
            .create("host-ssh", &sample_quiz())
            .unwrap();
        let person_id = harness.state.db.create_person("Bank Test", None).unwrap();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/unix-account"),
            &session,
            &format!("csrf={csrf}&unix_username=root"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            harness.state.db.list_people().unwrap()[0]
                .person
                .unix_username
                .as_deref(),
            Some("root")
        );
    }

    #[tokio::test]
    async fn web_composes_and_publishes_multiple_banks() {
        let harness = harness();
        harness
            .state
            .catalog
            .create("host-ssh", &sample_quiz())
            .unwrap();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/tests",
            &session,
            &format!("csrf={csrf}&test_id=onboarding&title=Onboarding&bank_0=legacy&bank_1=host-ssh&pass_threshold_percent=80&max_attempts=3&question_limit=1&shuffle_questions=on&shuffle_choices=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/tests/onboarding");
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/tests/onboarding")
                    .header(header::COOKIE, &session)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response_body(response).await;
        assert!(body.contains("name=\"bank_0\" type=\"checkbox\" value=\"legacy\" checked"));
        assert!(body.contains("name=\"bank_1\" type=\"checkbox\" value=\"host-ssh\" checked"));
        let response = form_post(
            &harness.app,
            "/tests/onboarding/publish",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let published = harness.state.db.published_test().unwrap().unwrap();
        assert_eq!(published.test_id, "onboarding");
        assert_eq!(published.quiz.questions.len(), 2);
        assert_eq!(published.quiz.question_limit, Some(1));

        let response = form_post(
            &harness.app,
            "/tests/onboarding",
            &session,
            &format!("csrf={csrf}&test_id=onboarding&title=Onboarding+v2&bank_0=legacy&bank_1=host-ssh&pass_threshold_percent=90&max_attempts=4&question_limit=2&shuffle_questions=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let saved = harness.state.db.get_test("onboarding").unwrap();
        assert_eq!(saved.title, "Onboarding v2");
        assert_eq!(saved.question_limit, Some(2));
        assert!(saved.shuffle_questions);
        assert!(!saved.shuffle_choices);
        let response = form_post(
            &harness.app,
            "/tests/onboarding/publish",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let current = harness.state.db.published_test().unwrap().unwrap();
        assert_ne!(current.revision, published.revision);
        assert_eq!(
            harness
                .state
                .db
                .list_publications("onboarding")
                .unwrap()
                .len(),
            2
        );

        let response = form_post(
            &harness.app,
            &format!(
                "/tests/onboarding/publications/{}/activate",
                published.publication_id
            ),
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            harness.state.db.published_test().unwrap().unwrap().revision,
            published.revision
        );

        let response = form_post(
            &harness.app,
            "/banks/host-ssh/delete",
            &session,
            &format!("csrf={csrf}&confirm=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(harness.state.catalog.load("host-ssh").is_ok());

        let response = form_post(
            &harness.app,
            "/tests/onboarding/delete",
            &session,
            &format!("csrf={csrf}&confirm=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = form_post(
            &harness.app,
            "/tests",
            &session,
            &format!("csrf={csrf}&test_id=temporary&title=Temporary&bank_0=legacy&pass_threshold_percent=80&max_attempts=3"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/tests/temporary/delete",
            &session,
            &format!("csrf={csrf}&confirm=on"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(matches!(
            harness.state.db.get_test("temporary"),
            Err(GateError::NotFound)
        ));
    }

    #[tokio::test]
    async fn success_uses_signed_one_time_flash_and_canonical_url() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/persons",
            &session,
            &format!("csrf={csrf}&display_name=Flash+Test&unix_username=root"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/people/1");
        let flash = cookie_pair(response.headers(), FLASH_COOKIE);
        assert!(flash.contains('.'));

        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/people/1")
                    .header(header::COOKIE, format!("{session}; {flash}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let clears_flash = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.starts_with(FLASH_COOKIE) && value.contains("Max-Age=0"));
        assert!(clears_flash);
        let body = response_body(response).await;
        assert!(body.contains("Person created."));

        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/people")
                    .header(header::COOKIE, &session)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response_body(response).await.contains("Person created."));
    }

    #[tokio::test]
    async fn language_selector_sets_cookie_and_returns_clean_safe_path() {
        let harness = harness();
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/language/zh?next=/login")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/login");
        let language = cookie_pair(response.headers(), LANGUAGE_COOKIE);
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/login")
                    .header(header::COOKIE, language)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response_body(response).await;
        assert!(body.contains("管理控制台"));
        assert!(!body.contains(">Administration<"));

        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/language/en?next=https://example.org")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::LOCATION], "/");
    }

    #[cfg(unix)]
    #[test]
    fn admin_startup_reports_actionable_quiz_path_error() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let db = Db::new(directory.path().join("gate.db"), Duration::from_secs(1));
        db.initialize().unwrap();
        let target = directory.path().join("target.json");
        sample_quiz().save_atomic(&target).unwrap();
        let link = directory.path().join("quiz.json");
        symlink(&target, &link).unwrap();
        let auth = AdminAuthConfig {
            password_hash: hash_password(TEST_ADMIN_INPUT.as_bytes()).unwrap(),
            session_secret_base64: base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
            session_ttl_seconds: 3600,
        };
        let error = match WebState::new(db, link.clone(), &auth) {
            Ok(_) => panic!("symbolic-link quiz path was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("admin cannot manage quiz catalog"));
        assert!(error.contains(link.to_str().unwrap()));
        assert!(error.contains("write access to the quiz file"));
    }

    async fn form_post(app: &Router, path: &str, session: &str, body: &str) -> Response {
        let mut builder =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if !session.is_empty() {
            builder = builder.header(header::COOKIE, session);
        }
        app.clone()
            .oneshot(
                builder
                    .body(axum::body::Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn response_body(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    fn cookie_pair(headers: &HeaderMap, name: &str) -> String {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn hidden_value(body: &str, name: &str) -> String {
        let marker = format!("name=\"{name}\" value=\"");
        let start = body.find(&marker).unwrap() + marker.len();
        let rest = &body[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    }
}
