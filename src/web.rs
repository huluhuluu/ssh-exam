use std::{
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
    extract::{Form, Path as AxumPath, Query, State},
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
    db::{BindingInput, Db, GateError, KeyRecord, PersonRecord, PersonView},
    quiz::{
        validate_bank_id, BankEnvironment, Question, Quiz, QuizBank, QuizCatalog, LEGACY_BANK_ID,
    },
};

type HmacSha256 = Hmac<Sha256>;
const SESSION_COOKIE: &str = "ssh_exam_session";
const LOGIN_CSRF_COOKIE: &str = "ssh_exam_login_csrf";
const FLASH_COOKIE: &str = "ssh_exam_flash";
const LANGUAGE_COOKIE: &str = "ssh_exam_language";

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
    exam => ("Exam", "考试"),
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
    active_mappings => ("Active mappings", "活跃映射"),
    recorded_attempts => ("Recorded attempts", "已记录尝试"),
    current_exam => ("Current exam", "当前考试"),
    manage_exam => ("Manage exams", "管理考试"),
    title => ("Title", "标题"),
    environment => ("Environment", "环境"),
    pass_threshold => ("Pass threshold", "通过分数"),
    maximum_attempts => ("Maximum attempts", "最大尝试次数"),
    questions => ("Questions", "问题"),
    banks => ("Banks", "题库"),
    access_model => ("Access model", "访问模型"),
    manage_people => ("Manage people", "管理人员"),
    access_help => ("An Access mapping connects a registered person or device key to an existing Unix account, access type, and exam bank. It never configures the SSH listener port.", "访问映射将注册人员或设备密钥关联到现有 Unix 账号、访问类型和考试题库；它不会配置 SSH 监听端口。"),
    people_help => ("Registered identities, device keys, inherited exam status, and Access mappings.", "注册身份、设备密钥、继承的考试状态与访问映射。"),
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
    access_mappings => ("Access mappings", "访问映射"),
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
    public_key => ("Public key", "公钥"),
    add_device_key => ("Add device key", "添加设备密钥"),
    mapping_help => ("Map this person or one device key to an existing Unix login, access type, and exam bank. Allowed destinations apply only to Shared ProxyJump.", "将此人员或某个设备密钥映射到现有 Unix 登录账号、访问类型与考试题库。允许的目标仅适用于共享 ProxyJump。"),
    no_mappings => ("No Access mappings are configured for this person.", "此人员尚未配置访问映射。"),
    unix_login => ("Unix login account", "Unix 登录账号"),
    access_type => ("Access type", "访问类型"),
    scope => ("Scope", "范围"),
    allowed_destinations => ("Allowed destinations", "允许的目标"),
    action => ("Action", "操作"),
    normal_shell => ("Normal shell", "普通 Shell"),
    shared_proxyjump => ("Shared ProxyJump", "共享 ProxyJump"),
    all_registered_keys => ("All registered keys", "所有注册密钥"),
    selected_key => ("Selected key", "指定密钥"),
    add_mapping => ("Add Access mapping", "添加访问映射"),
    exam_help => ("Changes are written atomically and apply when the next TUI session starts.", "更改以原子方式写入，并在下一个 TUI 会话启动时生效。"),
    configured_banks => ("Configured banks", "已配置题库"),
    select => ("Select", "选择"),
    selected => ("Selected", "已选择"),
    legacy_bank => ("Legacy quiz_path", "兼容 quiz_path"),
    create_bank => ("Create bank", "创建题库"),
    bank_id => ("Bank ID", "题库 ID"),
    bank_id_help => ("Lowercase letters, digits, and single internal hyphens.", "使用小写字母、数字和单个连接短横线。"),
    initial_question => ("Initial question", "初始问题"),
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
}

#[derive(Clone)]
pub struct WebState {
    db: Db,
    catalog: Arc<QuizCatalog>,
    quiz_lock: Arc<Mutex<()>>,
    password_hash: String,
    session_secret: Arc<Vec<u8>>,
    session_ttl_seconds: u64,
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
    banks: Vec<BankOption>,
    labels: Labels,
    current_path: &'static str,
}

#[derive(Template)]
#[template(path = "exam.html")]
struct ExamTemplate {
    csrf: String,
    active_page: &'static str,
    notice: String,
    error: String,
    quiz: Quiz,
    bank_id: String,
    banks: Vec<BankOption>,
    catalog_enabled: bool,
    environment: &'static str,
    questions: Vec<QuestionAdminView>,
    answer_options: Vec<AnswerOption>,
    labels: Labels,
    current_path: String,
}

#[derive(Default)]
struct OverviewMetrics {
    people: usize,
    enabled_people: usize,
    passed_people: usize,
    active_keys: usize,
    active_mappings: usize,
    attempts: u32,
}

struct PersonAdminView {
    person: PersonRecord,
    keys: Vec<KeyRecord>,
    mappings: Vec<MappingAdminView>,
    attempt_count: u32,
}

struct MappingAdminView {
    id: i64,
    unix_username: String,
    access_type: &'static str,
    scope: String,
    allowed_destinations: String,
    bank_id: String,
    enabled: bool,
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
struct CreatePersonForm {
    csrf: String,
    display_name: String,
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
struct AddBindingForm {
    csrf: String,
    unix_username: String,
    access_mode: String,
    ssh_key_id: String,
    permitopen: String,
    bank_id: String,
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

#[derive(Deserialize)]
struct CreateBankForm {
    csrf: String,
    bank_id: String,
    title: String,
    environment: String,
    pass_threshold_percent: String,
    max_attempts: String,
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
        Ok(Self {
            db,
            catalog: Arc::new(catalog),
            quiz_lock: Arc::new(Mutex::new(())),
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
        .route("/exam", get(exam_page))
        .route("/exam/:bank_id", get(exam_bank_page))
        .route("/language/:language", get(select_language))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/persons", post(create_person))
        .route("/persons/:id/enabled", post(toggle_person))
        .route("/persons/:id/reset", post(reset_exam))
        .route("/persons/:id/keys", post(add_key))
        .route("/keys/:id/enabled", post(toggle_key))
        .route("/keys/:id/remove", post(remove_key))
        .route("/persons/:id/bindings", post(add_binding))
        .route("/bindings/:id/enabled", post(toggle_binding))
        .route("/exam/banks", post(create_exam_bank))
        .route("/exam/:bank_id/settings", post(update_exam_settings))
        .route("/exam/:bank_id/questions", post(add_exam_question))
        .route(
            "/exam/:bank_id/questions/:index/edit",
            post(edit_exam_question),
        )
        .route(
            "/exam/:bank_id/questions/:index/delete",
            post(delete_exam_question),
        )
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

async fn exam_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
    render_exam_page(state, headers, LEGACY_BANK_ID.to_owned()).await
}

async fn exam_bank_page(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(bank_id): AxumPath<String>,
) -> Response {
    render_exam_page(state, headers, bank_id).await
}

async fn render_exam_page(state: WebState, headers: HeaderMap, bank_id: String) -> Response {
    let Some(session) = session_from_headers(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let language = language_from_headers(&headers);
    let notice = flash_message(&state, &headers, language);
    let mut response = render_exam(
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
    mutate_people(&state, &headers, &form.csrf, "person-created", || {
        state.db.create_person(&form.display_name).map(|_| ())
    })
}

async fn toggle_person(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<ToggleForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "person-updated", || {
        state.db.set_person_enabled(id, form.enabled)
    })
}

async fn reset_exam(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "exam-reset", || {
        state.db.reset_exam(id)
    })
}

async fn add_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<AddKeyForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "key-added", || {
        state.db.add_key(id, &form.public_key).map(|_| ())
    })
}

async fn toggle_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<ToggleForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "key-updated", || {
        state.db.set_key_enabled(id, form.enabled)
    })
}

async fn remove_key(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<CsrfForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "key-removed", || {
        state.db.remove_key(id)
    })
}

async fn add_binding(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<AddBindingForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "mapping-added", || {
        state.catalog.load(&form.bank_id).map_err(|error| {
            GateError::Invalid(format!("selected quiz bank is unavailable: {error}"))
        })?;
        let mode = form.access_mode.parse()?;
        let ssh_key_id = if form.ssh_key_id.trim().is_empty() {
            None
        } else {
            Some(
                form.ssh_key_id
                    .parse::<i64>()
                    .map_err(|_| GateError::Invalid("invalid SSH key selection".to_owned()))?,
            )
        };
        let permitopen = form
            .permitopen
            .split([',', '\n'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        state
            .db
            .add_binding(&BindingInput {
                person_id: id,
                ssh_key_id,
                unix_username: form.unix_username.clone(),
                access_mode: mode,
                permitopen,
                bank_id: form.bank_id.clone(),
            })
            .map(|_| ())
    })
}

async fn toggle_binding(
    State(state): State<WebState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<ToggleForm>,
) -> Response {
    mutate_people(&state, &headers, &form.csrf, "mapping-updated", || {
        state.db.set_binding_enabled(id, form.enabled)
    })
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

async fn create_exam_bank(
    State(state): State<WebState>,
    headers: HeaderMap,
    Form(form): Form<CreateBankForm>,
) -> Response {
    let Ok(session) = authorize_mutation(&state, &headers, &form.csrf) else {
        return mutation_rejection(&state, &headers);
    };
    let language = language_from_headers(&headers);
    let bank_id = form.bank_id.trim().to_owned();
    let question = parse_question_fields(&form.prompt, &form.choices, &form.correct_index);
    let quiz = (|| -> Result<Quiz> {
        Ok(Quiz {
            title: form.title.trim().to_owned(),
            environment: parse_environment(&form.environment)?,
            pass_threshold_percent: form
                .pass_threshold_percent
                .parse()
                .context("pass threshold must be a whole number")?,
            max_attempts: form
                .max_attempts
                .parse()
                .context("maximum attempts must be a whole number")?,
            questions: vec![question?],
        })
    })();
    let catalog = state.catalog.clone();
    let lock = state.quiz_lock.clone();
    let create_id = bank_id.clone();
    let result = match quiz {
        Ok(quiz) => {
            tokio::task::spawn_blocking(move || {
                let _guard = lock
                    .lock()
                    .map_err(|_| anyhow::anyhow!("quiz update lock is unavailable"))?;
                catalog.create(&create_id, &quiz)
            })
            .await
        }
        Err(error) => Ok(Err(error)),
    };
    match result {
        Ok(Ok(_)) => flash_redirect(&state, &format!("/exam/{bank_id}"), "bank-created"),
        Ok(Err(error)) => {
            render_exam(
                &state,
                &session,
                language,
                LEGACY_BANK_ID,
                String::new(),
                localized_error(language, &error.to_string()),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(_) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "quiz update task failed",
            "题库更新任务失败",
        ),
    }
}

fn mutate_people(
    state: &WebState,
    headers: &HeaderMap,
    csrf: &str,
    success_code: &'static str,
    operation: impl FnOnce() -> Result<(), GateError>,
) -> Response {
    let Ok(session) = authorize_mutation(state, headers, csrf) else {
        return mutation_rejection(state, headers);
    };
    match operation() {
        Ok(()) => flash_redirect(state, "/people", success_code),
        Err(error) => render_people(
            state,
            &session,
            language_from_headers(headers),
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
        Ok(Ok(_)) => flash_redirect(&state, &format!("/exam/{bank_id}"), success_code),
        Ok(Err(error)) => {
            render_exam(
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
    let quiz = banks
        .first()
        .expect("catalog always includes the legacy bank")
        .quiz
        .clone();
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
    match (state.db.list_people(), state.catalog.discover()) {
        (Ok(people), Ok(banks)) => {
            let template = PeopleTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "people",
                notice,
                error,
                people: people
                    .into_iter()
                    .map(|item| person_admin_view(item, language))
                    .collect(),
                banks: bank_options(&banks, ""),
                labels: labels(language),
                current_path: "/people",
            };
            response_with_status(render_template(&template), status)
        }
        (Err(_), _) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            "database error",
            "数据库错误",
        ),
        (_, Err(error)) => localized_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            language,
            &format!("quiz catalog error: {error}"),
            &format!("题库目录错误：{error}"),
        ),
    }
}

async fn render_exam(
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
            let template = ExamTemplate {
                csrf: csrf_for_session(state, session),
                active_page: "exam",
                notice,
                error,
                quiz,
                bank_id: bank_id.to_owned(),
                banks: bank_options(&banks, bank_id),
                catalog_enabled: state.catalog.catalog_directory().is_some(),
                environment,
                questions,
                answer_options: answer_options(20),
                labels: labels(language),
                current_path: format!("/exam/{bank_id}"),
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
        active_mappings: people
            .iter()
            .flat_map(|item| &item.bindings)
            .filter(|binding| binding.enabled)
            .count(),
        attempts: people.iter().map(|item| item.attempt_count).sum(),
    }
}

fn person_admin_view(item: PersonView, language: WebLanguage) -> PersonAdminView {
    let mappings = item
        .bindings
        .into_iter()
        .map(|binding| {
            let scope = match binding.ssh_key_id {
                Some(key_id) => item
                    .keys
                    .iter()
                    .find(|key| key.id == key_id)
                    .map(|key| {
                        format!(
                            "{}: {}",
                            language.text("Selected device key", "指定设备密钥"),
                            key.fingerprint
                        )
                    })
                    .unwrap_or_else(|| {
                        format!(
                            "{} #{key_id}",
                            language.text("Selected device key", "指定设备密钥")
                        )
                    }),
                None => language.text("All registered keys", "所有注册密钥"),
            };
            MappingAdminView {
                id: binding.id,
                unix_username: binding.unix_username,
                access_type: match binding.access_mode {
                    crate::db::AccessMode::Shell => match language {
                        WebLanguage::En => "Normal shell",
                        WebLanguage::Zh => "普通 Shell",
                        WebLanguage::Bilingual => "Normal shell / 普通 Shell",
                    },
                    crate::db::AccessMode::Proxyjump => match language {
                        WebLanguage::En => "Shared ProxyJump",
                        WebLanguage::Zh => "共享 ProxyJump",
                        WebLanguage::Bilingual => "Shared ProxyJump / 共享 ProxyJump",
                    },
                },
                scope,
                allowed_destinations: if binding.permitopen.is_empty() {
                    language.text("Not applicable", "不适用")
                } else {
                    binding.permitopen.join(", ")
                },
                bank_id: binding.bank_id,
                enabled: binding.enabled,
            }
        })
        .collect();
    PersonAdminView {
        person: item.person,
        keys: item.keys,
        mappings,
        attempt_count: item.attempt_count,
    }
}

fn bank_options(banks: &[QuizBank], selected: &str) -> Vec<BankOption> {
    banks
        .iter()
        .map(|bank| BankOption {
            id: bank.id.clone(),
            title: bank.quiz.title.clone(),
            environment: bank.quiz.environment.as_str(),
            question_count: bank.quiz.questions.len(),
            legacy: bank.legacy,
            selected: bank.id == selected,
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
    if matches!(value, "/" | "/people" | "/exam" | "/login") {
        return value.to_owned();
    }
    if let Some(bank_id) = value.strip_prefix("/exam/") {
        if !bank_id.contains('/') && validate_bank_id(bank_id).is_ok() {
            return value.to_owned();
        }
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
        "person-updated" => language.text("Person status updated.", "人员状态已更新。"),
        "exam-reset" => language.text(
            "Exam status and attempts reset.",
            "考试状态与尝试记录已重置。",
        ),
        "key-added" => language.text("Device key added.", "设备密钥已添加。"),
        "key-updated" => language.text("Device key status updated.", "设备密钥状态已更新。"),
        "key-removed" => language.text("Device key removed.", "设备密钥已移除。"),
        "mapping-added" => language.text("Access mapping added.", "访问映射已添加。"),
        "mapping-updated" => {
            language.text("Access mapping status updated.", "访问映射状态已更新。")
        }
        "bank-created" => language.text("Quiz bank created.", "题库已创建。"),
        "settings-updated" => language.text("Exam settings saved.", "考试设置已保存。"),
        "question-added" => language.text("Question added.", "问题已添加。"),
        "question-updated" => language.text("Question saved.", "问题已保存。"),
        "question-deleted" => language.text("Question deleted.", "问题已删除。"),
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
            questions: vec![Question {
                prompt: "Safe?".to_owned(),
                choices: vec!["Yes".to_owned(), "No".to_owned()],
                correct_index: 0,
            }],
        }
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
                "/exam/legacy/settings",
                "csrf=bad&title=Safety&environment=general&pass_threshold_percent=80&max_attempts=3",
            ),
            (
                "/exam/legacy/questions",
                "csrf=bad&prompt=Safe%3F&choices=Yes%0ANo&correct_index=0",
            ),
        ] {
            let response = form_post(&harness.app, path, "", body).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
        }
        let (session, _) = login(&harness.app).await;
        for (path, body) in [
            (
                "/exam/legacy/settings",
                "csrf=bad&title=Safety&environment=general&pass_threshold_percent=80&max_attempts=3",
            ),
            (
                "/exam/legacy/questions",
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
            &format!("csrf={csrf}&display_name=Alice"),
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
            &format!("/persons/{person_id}/bindings"),
            &session,
            &format!(
                "csrf={csrf}&unix_username=missing_exam_user&access_mode=shell&ssh_key_id=&permitopen=&bank_id=legacy"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn people_mutations_disable_bind_reset_and_remove() {
        let harness = harness();
        let person_id = harness.state.db.create_person("Mutation Test").unwrap();
        let key = harness
            .state
            .db
            .add_key(person_id, "ssh-ed25519 aGVsbG8= device")
            .unwrap();
        harness
            .state
            .db
            .record_attempt(&AttemptInput {
                person_id,
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
                format!("/persons/{person_id}/bindings"),
                format!("csrf={csrf}&unix_username=root&access_mode=shell&ssh_key_id=&permitopen=&bank_id=legacy"),
            ),
        ] {
            assert_eq!(
                form_post(&harness.app, &path, &session, &body)
                    .await
                    .status(),
                StatusCode::SEE_OTHER
            );
        }
        let binding_id = harness.state.db.list_people().unwrap()[0].bindings[0].id;
        for (path, body) in [
            (
                format!("/bindings/{binding_id}/enabled"),
                format!("csrf={csrf}&enabled=false"),
            ),
            (
                format!("/keys/{}/enabled", key.id),
                format!("csrf={csrf}&enabled=false"),
            ),
            (
                format!("/persons/{person_id}/reset"),
                format!("csrf={csrf}"),
            ),
            (format!("/keys/{}/remove", key.id), format!("csrf={csrf}")),
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
    }

    #[tokio::test]
    async fn exam_settings_and_question_crud_persist() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/exam/legacy/settings",
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
            "/exam/legacy/questions",
            &session,
            &format!("csrf={csrf}&prompt=Added%3F&choices=Wrong%0ARight&correct_index=1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/legacy/questions/1/edit",
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
            "/exam/legacy/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/legacy/questions/0/delete",
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
            "/exam/legacy/settings",
            &session,
            &format!("csrf={csrf}&title=Safety&environment=general&pass_threshold_percent=0&max_attempts=3"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(harness.state.catalog.load(LEGACY_BANK_ID).unwrap(), before);
    }

    #[tokio::test]
    async fn web_catalog_creates_selects_and_mutates_a_bank() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/exam/banks",
            &session,
            &format!(
                "csrf={csrf}&bank_id=host-ssh&title=Host+SSH&environment=host&pass_threshold_percent=80&max_attempts=3&prompt=Ready%3F&choices=Yes%0ANo&correct_index=0"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/exam/host-ssh");
        assert_eq!(
            harness.state.catalog.load("host-ssh").unwrap().environment,
            BankEnvironment::Host
        );

        let response = form_post(
            &harness.app,
            "/exam/host-ssh/settings",
            &session,
            &format!("csrf={csrf}&title=Host+Access&environment=general&pass_threshold_percent=90&max_attempts=2"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/host-ssh/questions",
            &session,
            &format!("csrf={csrf}&prompt=Second%3F&choices=One%0ATwo&correct_index=1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/host-ssh/questions/1/edit",
            &session,
            &format!("csrf={csrf}&prompt=Edited%3F&choices=Right%0AWrong&correct_index=0"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/host-ssh/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let response = form_post(
            &harness.app,
            "/exam/host-ssh/questions/0/delete",
            &session,
            &format!("csrf={csrf}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let saved = harness.state.catalog.load("host-ssh").unwrap();
        assert_eq!(saved.title, "Host Access");
        assert_eq!(saved.questions[0].prompt, "Edited?");
    }

    #[tokio::test]
    async fn access_mapping_uses_selected_catalog_bank() {
        let harness = harness();
        harness
            .state
            .catalog
            .create("host-ssh", &sample_quiz())
            .unwrap();
        let person_id = harness.state.db.create_person("Bank Test").unwrap();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            &format!("/persons/{person_id}/bindings"),
            &session,
            &format!("csrf={csrf}&unix_username=root&access_mode=shell&ssh_key_id=&permitopen=&bank_id=host-ssh"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            harness.state.db.list_people().unwrap()[0].bindings[0].bank_id,
            "host-ssh"
        );
    }

    #[tokio::test]
    async fn success_uses_signed_one_time_flash_and_canonical_url() {
        let harness = harness();
        let (session, csrf) = login(&harness.app).await;
        let response = form_post(
            &harness.app,
            "/persons",
            &session,
            &format!("csrf={csrf}&display_name=Flash+Test"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/people");
        let flash = cookie_pair(response.headers(), FLASH_COOKIE);
        assert!(flash.contains('.'));

        let response = harness
            .app
            .clone()
            .oneshot(
                Request::get("/people")
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
