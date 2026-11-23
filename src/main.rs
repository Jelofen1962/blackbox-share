#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::Semaphore};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use uuid::Uuid;

const PORT: u16 = 1962;
const ADMIN_SESSION_DURATION: Duration = Duration::from_secs(12 * 60 * 60);
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const MAX_FAILED_LOGINS: usize = 6;
const MIN_FREE_DISK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PARALLEL_UPLOADS: usize = 3;
const JSON_BODY_LIMIT: usize = 512 * 1024;
const META_FILE: &str = ".blackbox-share.json";
const SHARE_TEXTS_FILE: &str = "share-texts.json";
const MAX_SHARE_TEXT_CHARS: usize = 100_000;
const MAX_UPLOAD_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB per file
const MAX_REQUEST_BYTES: usize = MAX_UPLOAD_BYTES as usize + 1024 * 1024;
const APP_CONFIG_FILE: &str = "config.json";
const STARTUP_SCRIPT: &str = "Blackbox Share.vbs";
const LEGACY_STARTUP_SCRIPT: &str = "Blackbox Share.cmd";

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    private_files: Arc<Mutex<HashSet<String>>>,
    share_texts: Arc<Mutex<Vec<ShareText>>>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    admin_password_hash: Arc<Mutex<Option<String>>>,
    failed_logins: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    upload_slots: Arc<Semaphore>,
}

#[derive(Serialize, Deserialize, Default)]
struct Metadata {
    private_files: HashSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ShareText {
    id: String,
    title: String,
    content: String,
}

#[derive(Deserialize)]
struct NewShareText {
    title: String,
    content: String,
}

#[derive(Serialize)]
struct FileItem {
    name: String,
    size: u64,
    modified: u64,
    private: bool,
}

#[derive(Deserialize)]
struct LoginInput { password: String }

#[derive(Deserialize)]
struct PrivateInput { private: bool }

#[derive(Deserialize)]
struct StartupInput { enabled: bool }

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct AppConfig {
    folder: Option<PathBuf>,
    // Missing fields in older config files default to false. The first upgraded
    // Windows launch opts in once, while later user changes remain respected.
    startup_configured: bool,
    startup_enabled: bool,
    admin_password_hash: Option<String>,
}

#[derive(Serialize)]
struct LoginResult { ok: bool }

fn safe_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." ||
        name.eq_ignore_ascii_case(SHARE_TEXTS_FILE) ||
        name.contains('/') || name.contains('\\') ||
        name.chars().any(char::is_control) || name.starts_with('.') {
        return None;
    }
    Some(name.to_string())
}

fn content_disposition(name: &str) -> String {
    // Keep an ASCII fallback for older clients and add RFC 5987 encoding so
    // filenames containing Persian or other Unicode characters download intact.
    let fallback = name.chars().map(|character| {
        if character.is_ascii_alphanumeric() || matches!(character, ' ' | '.' | '_' | '-') {
            character
        } else {
            '_'
        }
    }).collect::<String>();
    let encoded = name.as_bytes().iter().map(|byte| {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            (*byte as char).to_string()
        } else {
            format!("%{byte:02X}")
        }
    }).collect::<String>();
    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

// Always publish settings through a separate same-directory file, so a crash never
// leaves truncated JSON. The caller holds the relevant state lock while writing.
fn atomic_write(path: &FsPath, content: &[u8]) -> Result<(), String> {
    let directory = path.parent().ok_or("Missing parent directory")?;
    let temporary = directory.join(format!(".blackbox-write-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true)
            .open(&temporary).map_err(|error| error.to_string())?;
        file.write_all(content).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

fn load_metadata(root: &FsPath) -> Result<HashSet<String>, String> {
    let path = root.join(META_FILE);
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str::<Metadata>(&raw)
            .map(|meta| meta.private_files)
            .map_err(|error| format!("Cannot parse privacy metadata {}: {error}. Files will not be served until it is repaired.", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
        Err(error) => Err(format!("Cannot read privacy metadata {}: {error}. Files will not be served.", path.display())),
    }
}

fn persist_metadata(root: &FsPath, private_files: &HashSet<String>) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(&Metadata { private_files: private_files.clone() })
        .map_err(|error| error.to_string())?;
    atomic_write(&root.join(META_FILE), &data)
}

// Request filenames must match a real directory entry exactly. Windows may open
// differently capitalized paths, so a raw Path::join would bypass private flags.
// Symlinks and directory reparse points are excluded, preventing path escapes.
fn safe_existing_file(root: &FsPath, requested: &str) -> Option<PathBuf> {
    if safe_name(requested).is_none() { return None; }
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        if entry.file_name().to_str() != Some(requested) { continue; }
        if !entry.file_type().ok()?.is_file() { return None; }
        let path = entry.path();
        let real = fs::canonicalize(&path).ok()?;
        if real.parent() == Some(root) { return Some(path); }
        return None;
    }
    None
}

fn is_admin(headers: &HeaderMap, state: &AppState) -> bool {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = cookie.split(';').map(str::trim)
        .find_map(|part| part.strip_prefix("bb_session="));
    let Ok(mut sessions) = state.sessions.lock() else { return false; };
    let now = Instant::now();
    sessions.retain(|_, created| now.duration_since(*created) < ADMIN_SESSION_DURATION);
    token.map(|value| sessions.contains_key(value)).unwrap_or(false)
}

fn check_login_limit(state: &AppState, ip: IpAddr) -> bool {
    let Ok(mut attempts) = state.failed_logins.lock() else { return false; };
    let now = Instant::now();
    attempts.retain(|_, recent| {
        recent.retain(|time| now.duration_since(*time) < LOGIN_WINDOW);
        !recent.is_empty()
    });
    attempts.get(&ip).map(|recent| recent.len() < MAX_FAILED_LOGINS).unwrap_or(true)
}

fn record_bad_login(state: &AppState, ip: IpAddr) {
    if let Ok(mut attempts) = state.failed_logins.lock() {
        attempts.entry(ip).or_default().push(Instant::now());
    }
}

fn hash_admin_password(password: &str) -> Result<String, String> {
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes()).map_err(|error| error.to_string())?;
    Argon2::default().hash_password(password.as_bytes(), &salt)
        .map(|hashed| hashed.to_string()).map_err(|error| error.to_string())
}

fn verify_admin_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).ok().map(|parsed| {
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    }).unwrap_or(false)
}

fn json_error(code: StatusCode, message: &str) -> Response {
    (code, Json(serde_json::json!({"error": message}))).into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let admin = is_admin(&headers, &state);
    let private = match state.private_files.lock() {
        Ok(files) => files.clone(),
        Err(_) => return Json(Vec::<FileItem>::new()),
    };
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(&state.root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else { continue };
            if name == META_FILE || name.eq_ignore_ascii_case(SHARE_TEXTS_FILE) || name.starts_with('.') { continue; }
            if !entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) { continue; }
            if !admin && private.contains(&name) { continue; }
            let Ok(meta) = fs::metadata(&path) else { continue };
            let modified = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            files.push(FileItem { name: name.clone(), size: meta.len(), modified, private: private.contains(&name) });
        }
    }
    files.sort_by(|a,b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Json(files)
}

// Only administrator controls require a password; ordinary LAN upload/download
// endpoints remain accessible without any sign-in.
async fn setup_admin(
    State(state): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(input): Json<LoginInput>,
) -> Response {
    if !peer.ip().is_loopback() {
        return json_error(StatusCode::FORBIDDEN, "Set up the admin password from this PC using localhost");
    }
    if input.password.chars().count() < 8 {
        return json_error(StatusCode::BAD_REQUEST, "Use an admin password of at least 8 characters");
    }
    let Ok(mut configured) = state.admin_password_hash.lock() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Admin configuration unavailable");
    };
    if configured.is_some() {
        return json_error(StatusCode::CONFLICT, "An admin password has already been configured");
    }
    let hash = match hash_admin_password(&input.password) {
        Ok(hash) => hash,
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
    };
    if let Err(error) = update_app_config(|config| config.admin_password_hash = Some(hash.clone())) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error);
    }
    *configured = Some(hash);
    Json(serde_json::json!({"ok": true, "setup_complete": true})).into_response()
}

async fn login(
    State(state): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(input): Json<LoginInput>,
) -> Response {
    if !check_login_limit(&state, peer.ip()) {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "Too many unsuccessful admin logins. Try again in one minute.");
    }
    let verified = state.admin_password_hash.lock().ok()
        .and_then(|hash| hash.as_ref().map(|value| verify_admin_password(value, &input.password)));
    if verified != Some(true) {
        record_bad_login(&state, peer.ip());
        return json_error(StatusCode::UNAUTHORIZED, "Incorrect password or admin setup required");
    }
    if let Ok(mut attempts) = state.failed_logins.lock() { attempts.remove(&peer.ip()); }
    let token = Uuid::new_v4().to_string();
    if let Ok(mut sessions) = state.sessions.lock() { sessions.insert(token.clone(), Instant::now()); }
    let mut response = Json(LoginResult { ok: true }).into_response();
    let cookie = format!("bb_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200", token);
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    response
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        .unwrap_or("").split(';').map(str::trim).find_map(|p| p.strip_prefix("bb_session=")) {
        if let Ok(mut sessions) = state.sessions.lock() { sessions.remove(token); }
    }
    let mut response = Json(serde_json::json!({"ok":true})).into_response();
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("bb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"));
    response
}

async fn auth_status(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    Json(serde_json::json!({"admin": is_admin(&headers, &state), "setup_required": state.admin_password_hash.lock().map(|hash| hash.is_none()).unwrap_or(false)}))
}

async fn upload(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    // Concurrency is bounded using back-pressure, not user logins or rejections.
    let Ok(_permit) = state.upload_slots.clone().acquire_owned().await else {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "Upload service is closing");
    };
    let mut count = 0;

    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => return json_error(StatusCode::BAD_REQUEST, &format!("Could not read upload: {error}")),
        };

        let Some(raw_name) = field.file_name().map(str::to_string) else { continue };
        let Some(name) = safe_name(&raw_name) else {
            return json_error(StatusCode::BAD_REQUEST, "Invalid filename");
        };
        let destination = state.root.join(&name);
        if destination.exists() {
            return json_error(StatusCode::CONFLICT, "A file with this name already exists");
        }

        // Write to a hidden temporary file as chunks arrive. This keeps memory use
        // bounded for multi-gigabyte uploads and prevents partial files being listed.
        let temporary = state.root.join(format!(".blackbox-upload-{}.tmp", Uuid::new_v4()));
        let mut output = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
        {
            Ok(file) => file,
            Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        };

        let mut uploaded: u64 = 0;
        loop {
            let chunk = match field.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(error) => {
                    drop(output);
                    let _ = tokio::fs::remove_file(&temporary).await;
                    return json_error(StatusCode::BAD_REQUEST, &format!("Upload stream interrupted: {error}"));
                }
            };

            uploaded = uploaded.saturating_add(chunk.len() as u64);
            if uploaded > MAX_UPLOAD_BYTES {
                drop(output);
                let _ = tokio::fs::remove_file(&temporary).await;
                return json_error(StatusCode::PAYLOAD_TOO_LARGE, "File exceeds the 20 GiB limit");
            }

            // Keep a little free space for the operating system. Check in large
            // intervals so this does not slow down every streaming chunk.
            if uploaded == chunk.len() as u64 || uploaded % (8 * 1024 * 1024) < chunk.len() as u64 {
                match fs2::available_space(&state.root) {
                    Ok(available) if available < MIN_FREE_DISK_BYTES.saturating_add(chunk.len() as u64) => {
                        drop(output);
                        let _ = tokio::fs::remove_file(&temporary).await;
                        return json_error(StatusCode::INSUFFICIENT_STORAGE, "Not enough free disk space to continue upload");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        drop(output);
                        let _ = tokio::fs::remove_file(&temporary).await;
                        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not check disk space: {error}"));
                    }
                }
            }

            if let Err(error) = output.write_all(&chunk).await {
                drop(output);
                let _ = tokio::fs::remove_file(&temporary).await;
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not save upload: {error}"));
            }
        }

        if let Err(error) = output.flush().await {
            drop(output);
            let _ = tokio::fs::remove_file(&temporary).await;
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not finish upload: {error}"));
        }
        if let Err(error) = output.sync_all().await {
            drop(output);
            let _ = tokio::fs::remove_file(&temporary).await;
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not finish upload: {error}"));
        }
        drop(output);

        // Publish atomically without replacing an existing filename, including
        // case-insensitive Windows collisions. Works on NTFS and removable drives.
        if let Err(error) = publish_upload(&temporary, &destination) {
            let _ = tokio::fs::remove_file(&temporary).await;
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return json_error(StatusCode::CONFLICT, "A file with this name already exists");
            }
            return json_error(StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Could not publish upload: {error}"));
        }
        let _ = tokio::fs::remove_file(&temporary).await;

        count += 1;
    }

    Json(serde_json::json!({"ok":true,"uploaded":count})).into_response()
}

async fn set_private(
    State(state): State<AppState>, headers: HeaderMap, Path(name): Path<String>, Json(input): Json<PrivateInput>
) -> Response {
    if !is_admin(&headers, &state) { return json_error(StatusCode::UNAUTHORIZED, "Admin login required"); }
    let Some(name) = safe_name(&name) else { return json_error(StatusCode::BAD_REQUEST, "Invalid filename") };
    if safe_existing_file(&state.root, &name).is_none() {
        return json_error(StatusCode::NOT_FOUND, "File not found");
    }
    let Ok(mut current) = state.private_files.lock() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not lock file visibility");
    };
    let mut proposed = current.clone();
    if input.private { proposed.insert(name); } else { proposed.remove(&name); }
    if let Err(error) = persist_metadata(&state.root, &proposed) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error);
    }
    *current = proposed;
    Json(serde_json::json!({"ok":true})).into_response()
}

fn load_share_texts(root: &FsPath) -> Result<Vec<ShareText>, String> {
    let path = root.join(SHARE_TEXTS_FILE);
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str::<Vec<ShareText>>(&raw)
            .map_err(|error| format!("Cannot parse shared texts {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("Cannot read shared texts {}: {error}", path.display())),
    }
}

fn persist_share_texts(root: &FsPath, texts: &[ShareText]) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(texts).map_err(|error| error.to_string())?;
    atomic_write(&root.join(SHARE_TEXTS_FILE), &data)
}

async fn list_share_texts(State(state): State<AppState>) -> impl IntoResponse {
    let texts = state.share_texts.lock().map(|items| items.clone()).unwrap_or_default();
    Json(texts)
}

async fn add_share_text(
    State(state): State<AppState>, headers: HeaderMap, Json(input): Json<NewShareText>
) -> Response {
    let _ = headers; // Shared text is available to every LAN visitor.
    let title = input.title.trim();
    let content = input.content.trim();
    if content.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "Text cannot be empty");
    }
    if content.chars().count() > MAX_SHARE_TEXT_CHARS {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "Text is too long (maximum 100,000 characters)");
    }
    let item = ShareText {
        id: Uuid::new_v4().to_string(),
        title: if title.is_empty() { "Untitled text".to_string() } else { title.chars().take(100).collect() },
        content: content.to_string(),
    };
    let Ok(mut texts) = state.share_texts.lock() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not lock shared text list");
    };
    if texts.len() >= 500 {
        return json_error(StatusCode::TOO_MANY_REQUESTS, "The shared text list is full (500 items maximum)");
    }
    let mut proposed = texts.clone();
    proposed.insert(0, item.clone());
    if let Err(error) = persist_share_texts(&state.root, &proposed) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error);
    }
    *texts = proposed;
    Json(item).into_response()
}

async fn delete_share_text(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>
) -> Response {
    if !is_admin(&headers, &state) {
        return json_error(StatusCode::UNAUTHORIZED, "Admin login required");
    }
    let Ok(mut texts) = state.share_texts.lock() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not lock shared text list");
    };
    let mut proposed = texts.clone();
    proposed.retain(|item| item.id != id);
    if let Err(error) = persist_share_texts(&state.root, &proposed) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error);
    }
    *texts = proposed;
    Json(serde_json::json!({"ok":true})).into_response()
}


fn config_path() -> PathBuf {
    dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("BlackboxShare").join(APP_CONFIG_FILE)
}

fn load_app_config() -> AppConfig {
    fs::read_to_string(config_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<AppConfig>(&raw).ok())
        .unwrap_or_default()
}

fn save_app_config(config: &AppConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let data = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
    atomic_write(&path, &data)
}

// Serialize read-modify-write updates to the user configuration. This prevents
// startup settings from erasing a newly configured admin password.
fn update_app_config(action: impl FnOnce(&mut AppConfig)) -> Result<(), String> {
    static CONFIG_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    let lock = CONFIG_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().map_err(|_| "Config lock unavailable")?;
    let mut config = load_app_config();
    action(&mut config);
    save_app_config(&config)
}

fn load_saved_folder() -> Option<PathBuf> {
    let folder = load_app_config().folder?;
    if folder.is_dir() { Some(folder) } else { None }
}

fn save_folder(folder: &FsPath) {
    let _ = update_app_config(|config| config.folder = Some(folder.to_path_buf()));
}

fn startup_script_path() -> Option<PathBuf> {
    #[cfg(windows)] {
        let appdata = std::env::var_os("APPDATA")?;
        return Some(PathBuf::from(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup").join(STARTUP_SCRIPT));
    }
    #[cfg(not(windows))] { None }
}

fn startup_enabled() -> bool {
    startup_script_path().map(|p| p.is_file()).unwrap_or(false)
}

fn set_startup_enabled(enabled: bool) -> Result<bool, String> {
    #[cfg(windows)] {
        let path = startup_script_path().ok_or("Could not locate the Windows Startup folder")?;
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let legacy = PathBuf::from(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup").join(LEGACY_STARTUP_SCRIPT);
            if legacy.exists() { let _ = fs::remove_file(legacy); }
        }
        if enabled {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            fs::create_dir_all(path.parent().ok_or("Invalid Startup folder")?).map_err(|e| e.to_string())?;
            let exe_text = exe.display().to_string().replace('"', "\"\"");
            let script = format!("Set shell = CreateObject(\"WScript.Shell\")\r\nshell.Run Chr(34) & \"{}\" & Chr(34), 0, False\r\n", exe_text);
            fs::write(&path, script).map_err(|e| e.to_string())?;
        } else if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        let enabled_now = startup_enabled();
        update_app_config(|config| {
            config.startup_configured = true;
            config.startup_enabled = enabled_now;
        })?;
        return Ok(enabled_now);
    }
    #[cfg(not(windows))] {
        let _ = enabled;
        Err("Automatic startup is supported in the Windows release only".to_string())
    }
}

async fn get_startup(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    Json(serde_json::json!({"enabled": startup_enabled(), "supported": cfg!(windows), "admin": is_admin(&headers, &state)}))
}

async fn update_startup(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<StartupInput>) -> Response {
    if !is_admin(&headers, &state) { return json_error(StatusCode::UNAUTHORIZED, "Admin login required"); }
    match set_startup_enabled(input.enabled) {
        Ok(enabled) => Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, &e),
    }
}

async fn network_info() -> Json<serde_json::Value> {
    let ip = local_ip();
    Json(serde_json::json!({
        "lan_ip": ip.to_string(),
        "base_url": format!("http://{}:{}", ip, PORT),
        "port": PORT
    }))
}

async fn download(State(state): State<AppState>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let Some(name) = safe_name(&name) else { return json_error(StatusCode::BAD_REQUEST, "Invalid filename") };
    // Always resolve an actual, case-exact, non-symlink directory entry before
    // checking private status. Ordinary public downloads need no login.
    let Some(path) = safe_existing_file(&state.root, &name) else {
        return json_error(StatusCode::NOT_FOUND, "File not found");
    };
    let private = match state.private_files.lock() {
        Ok(private) => private.contains(&name),
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "File visibility unavailable"),
    };
    if private && !is_admin(&headers, &state) {
        return json_error(StatusCode::NOT_FOUND, "File not found");
    }
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return json_error(StatusCode::NOT_FOUND, "File not found");
    };
    let Ok(metadata) = file.metadata().await else {
        return json_error(StatusCode::NOT_FOUND, "File not found");
    };
    let mime = mime_guess::from_path(&path).first_or_octet_stream().to_string();
    let stream = tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from_str(&metadata.len().to_string()).unwrap_or(HeaderValue::from_static("0")));
    response.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&content_disposition(&name)).unwrap_or(HeaderValue::from_static("attachment")));
    response
}

// MoveFileW does not replace existing targets, unlike std::fs::rename on
// Windows. It also works on FAT/exFAT, where hard links are unsupported.
#[cfg(windows)]
fn publish_upload(temporary: &FsPath, destination: &FsPath) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileW(existing: *const u16, destination: *const u16) -> i32;
    }
    let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileW(from.as_ptr(), to.as_ptr()) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn publish_upload(temporary: &FsPath, destination: &FsPath) -> std::io::Result<()> {
    // Same-directory link creation fails if the destination already exists.
    fs::hard_link(temporary, destination)?;
    fs::remove_file(temporary)?;
    Ok(())
}

fn cleanup_stale_uploads(root: &FsPath) {
    let Ok(entries) = fs::read_dir(root) else { return; };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue; };
        if !name.starts_with(".blackbox-upload-") || !name.ends_with(".tmp") { continue; }
        let Ok(metadata) = entry.metadata() else { continue; };
        if !metadata.is_file() { continue; }
        let old = metadata.modified().ok()
            .and_then(|when| SystemTime::now().duration_since(when).ok())
            .map(|age| age >= Duration::from_secs(24 * 60 * 60)).unwrap_or(false);
        if old { let _ = fs::remove_file(entry.path()); }
    }
}

fn local_ip() -> IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0").ok()
        .and_then(|s| { s.connect("192.0.2.1:80").ok()?; s.local_addr().ok().map(|a| a.ip()) })
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

#[cfg(windows)]
fn setup_tray() -> Result<tray_icon::TrayIcon, String> {
    use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    let menu = Menu::new();
    let open_item = MenuItem::new("Open Blackbox Share", true, None);
    let quit_item = MenuItem::new("Exit Blackbox Share", true, None);
    menu.append(&open_item).map_err(|e| e.to_string())?;
    menu.append(&PredefinedMenuItem::separator()).map_err(|e| e.to_string())?;
    menu.append(&quit_item).map_err(|e| e.to_string())?;

    // Small custom coffee-brown tray glyph, generated in memory.
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for y in 0..32_i32 {
        for x in 0..32_i32 {
            let dx = x - 15;
            let dy = y - 15;
            if dx * dx + dy * dy <= 12 * 12 {
                let i = ((y * 32 + x) * 4) as usize;
                rgba[i] = 54; rgba[i + 1] = 36; rgba[i + 2] = 28; rgba[i + 3] = 255;
                if (dx.abs() <= 5 && dy.abs() <= 7) || (dy.abs() <= 2 && dx.abs() <= 8) {
                    rgba[i] = 249; rgba[i + 1] = 245; rgba[i + 2] = 243; rgba[i + 3] = 255;
                }
            }
        }
    }
    let icon = Icon::from_rgba(rgba, 32, 32).map_err(|e| e.to_string())?;
    let tray = TrayIconBuilder::new()
        .with_tooltip("Blackbox Share · Port 1962")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()
        .map_err(|e| e.to_string())?;

    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();
    let receiver = MenuEvent::receiver();
    std::thread::spawn(move || loop {
        if let Ok(event) = receiver.recv() {
            if event.id == open_id {
                let _ = open::that(format!("http://127.0.0.1:{PORT}"));
            } else if event.id == quit_id {
                std::process::exit(0);
            }
        }
    });
    Ok(tray)
}

#[tokio::main]
async fn main() {
    println!("\n  BLACKBOX / SHARE");
    println!("  ──────────────────────────────────────");
    println!("  Made by Jelofen1962 · https://github.com/Jelofen1962");
    println!("  Starting file server...\n");
    let folder = match load_saved_folder() {
        Some(folder) => {
            println!("Using saved folder: {}", folder.display());
            folder
        }
        None => {
            println!("Choose the folder used for uploads and downloads.");
            let Some(folder) = rfd::FileDialog::new().set_title("Choose upload/download folder").pick_folder() else {
                eprintln!("No folder selected. Exiting.");
                return;
            };
            save_folder(&folder);
            folder
        }
    };
    if let Err(e) = fs::create_dir_all(&folder) { eprintln!("Cannot use folder: {e}"); return; }

    // Keep the original automatic-startup behavior for existing installations.
    #[cfg(windows)]
    {
        let config = load_app_config();
        if !config.startup_configured {
            if let Err(error) = set_startup_enabled(true) {
                eprintln!("Could not enable Windows startup: {error}");
            }
        }
    }

    let root = match fs::canonicalize(&folder) {
        Ok(root) => root,
        Err(error) => { eprintln!("Cannot resolve shared folder: {error}"); return; }
    };
    let private_files = match load_metadata(&root) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("{error}");
            #[cfg(windows)]
            rfd::MessageDialog::new().set_title("Blackbox Share: privacy data error")
                .set_description(error.as_str()).show();
            return;
        }
    };
    let share_texts = match load_share_texts(&root) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("{error}");
            #[cfg(windows)]
            rfd::MessageDialog::new().set_title("Blackbox Share: shared text error")
                .set_description(error.as_str()).show();
            return;
        }
    };
    cleanup_stale_uploads(&root);
    let state = AppState {
        private_files: Arc::new(Mutex::new(private_files)),
        share_texts: Arc::new(Mutex::new(share_texts)),
        root,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        admin_password_hash: Arc::new(Mutex::new(load_app_config().admin_password_hash)),
        failed_logins: Arc::new(Mutex::new(HashMap::new())),
        upload_slots: Arc::new(Semaphore::new(MAX_PARALLEL_UPLOADS)),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/files", get(list_files))
        .route("/api/network", get(network_info))
        .route("/api/texts", get(list_share_texts).post(add_share_text))
        .route("/api/texts/:id", axum::routing::delete(delete_share_text))
        .route("/api/login", post(login))
        .route("/api/admin/setup", post(setup_admin))
        .route("/api/logout", post(logout))
        .route("/api/auth", get(auth_status))
        .route("/api/startup", get(get_startup).post(update_startup))
        .route("/api/upload", post(upload).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)))
        .route("/api/private/:name", post(set_private))
        .route("/download/:name", get(download))
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Could not bind port {PORT}: {e}");
            if e.kind() == std::io::ErrorKind::AddrInUse {
                let _ = open::that(format!("http://127.0.0.1:{PORT}"));
            } else {
                #[cfg(windows)]
                rfd::MessageDialog::new().set_title("Blackbox Share could not start")
                    .set_description(format!("Port {PORT}: {e}")).show();
            }
            return;
        }
    };
    println!("\nFolder: {}", folder.display());
    println!("Made by Jelofen1962 · https://github.com/Jelofen1962");
    println!("Local:  http://127.0.0.1:{PORT}");
    println!("LAN:    http://{}:{PORT}", local_ip());
    println!("Designed for trusted local networks; no public internet port forwarding.");
    println!("Blackbox Share runs in the system tray. Right-click its tray icon to open the dashboard or exit.");
    println!("Made by Jelofen1962 · https://github.com/Jelofen1962");
    #[cfg(windows)]
    let _tray = match setup_tray() {
        Ok(tray) => Some(tray),
        Err(error) => {
            eprintln!("Could not create tray icon: {error}");
            rfd::MessageDialog::new().set_title("Blackbox Share tray unavailable")
                .set_description("The server is running, but its tray icon could not be created. Close the application from Task Manager if necessary.").show();
            None
        }
    };
    let _ = open::that(format!("http://127.0.0.1:{PORT}"));
    if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await { eprintln!("Server error: {e}"); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reserved_and_unsafe_filenames() {
        for name in ["", ".", "..", "../private", "folder\\name", ".hidden", "share-texts.json", "SHARE-TEXTS.JSON"] {
            assert!(safe_name(name).is_none(), "Accepted invalid filename: {name:?}");
        }
        assert_eq!(safe_name("فارسی file.pdf").as_deref(), Some("فارسی file.pdf"));
    }

    #[test]
    fn privacy_metadata_is_not_silently_reset() {
        let folder = tempfile::tempdir().unwrap();
        assert!(load_metadata(folder.path()).unwrap().is_empty());
        fs::write(folder.path().join(META_FILE), b"{broken json").unwrap();
        assert!(load_metadata(folder.path()).is_err());
    }

    #[test]
    fn shared_text_corruption_is_reported_not_erased() {
        let folder = tempfile::tempdir().unwrap();
        fs::write(folder.path().join(SHARE_TEXTS_FILE), "not valid JSON").unwrap();
        assert!(load_share_texts(folder.path()).is_err());
    }

    #[test]
    fn admin_password_is_hashed_and_verified() {
        let stored = hash_admin_password("test-password-123").unwrap();
        assert!(!stored.contains("test-password-123"));
        assert!(verify_admin_password(&stored, "test-password-123"));
        assert!(!verify_admin_password(&stored, "incorrect-password"));
    }

    #[test]
    fn privacy_metadata_roundtrip_is_atomic() {
        let folder = tempfile::tempdir().unwrap();
        let mut private = HashSet::new();
        private.insert("Secret.pdf".to_string());
        persist_metadata(folder.path(), &private).unwrap();
        assert!(load_metadata(folder.path()).unwrap().contains("Secret.pdf"));
        assert!(!folder.path().join(".blackbox-write-corrupted.tmp").exists());
    }

    #[test]
    fn filename_case_must_match_existing_entry() {
        let folder = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(folder.path()).unwrap();
        fs::write(root.join("Secret.pdf"), b"secret").unwrap();
        assert!(safe_existing_file(&root, "Secret.pdf").is_some());
        assert!(safe_existing_file(&root, "SECRET.PDF").is_none());
    }

    #[test]
    fn publishing_does_not_replace_existing_files() {
        let folder = tempfile::tempdir().unwrap();
        let target = folder.path().join("report.txt");
        let temp = folder.path().join(".blackbox-upload-test.tmp");
        fs::write(&target, b"original").unwrap();
        fs::write(&temp, b"new data").unwrap();
        assert!(publish_upload(&temp, &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_served() {
        use std::os::unix::fs::symlink;
        let folder = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(folder.path()).unwrap();
        let secret = tempfile::NamedTempFile::new().unwrap();
        symlink(secret.path(), root.join("linked-file.txt")).unwrap();
        assert!(safe_existing_file(&root, "linked-file.txt").is_none());
    }
}
