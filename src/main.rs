#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::UNIX_EPOCH,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use uuid::Uuid;

const PORT: u16 = 1962;
const ADMIN_PASSWORD: &str = "Amir1962$#";
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
    sessions: Arc<Mutex<HashSet<String>>>,
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
}

#[derive(Serialize)]
struct LoginResult { ok: bool }

fn safe_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." ||
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

fn load_metadata(root: &FsPath) -> HashSet<String> {
    let path = root.join(META_FILE);
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Metadata>(&s).ok())
        .map(|m| m.private_files)
        .unwrap_or_default()
}

fn save_metadata(state: &AppState) -> Result<(), String> {
    let private_files = state.private_files.lock().map_err(|_| "Lock error")?.clone();
    let data = serde_json::to_string_pretty(&Metadata { private_files }).map_err(|e| e.to_string())?;
    fs::write(state.root.join(META_FILE), data).map_err(|e| e.to_string())
}

fn is_admin(headers: &HeaderMap, state: &AppState) -> bool {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = cookie.split(';').map(str::trim)
        .find_map(|part| part.strip_prefix("bb_session="));
    token.map(|t| state.sessions.lock().map(|s| s.contains(t)).unwrap_or(false)).unwrap_or(false)
}

fn json_error(code: StatusCode, message: &str) -> Response {
    (code, Json(serde_json::json!({"error": message}))).into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let admin = is_admin(&headers, &state);
    let private = state.private_files.lock().map(|s| s.clone()).unwrap_or_default();
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(&state.root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else { continue };
            if name == META_FILE || name.starts_with('.') || !path.is_file() { continue; }
            if !admin && private.contains(&name) { continue; }
            let Ok(meta) = fs::metadata(&path) else { continue };
            let modified = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            files.push(FileItem { name: name.clone(), size: meta.len(), modified, private: private.contains(&name) });
        }
    }
    files.sort_by(|a,b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Json(files)
}

async fn login(State(state): State<AppState>, Json(input): Json<LoginInput>) -> Response {
    if input.password != ADMIN_PASSWORD {
        return json_error(StatusCode::UNAUTHORIZED, "Incorrect password");
    }
    let token = Uuid::new_v4().to_string();
    if let Ok(mut sessions) = state.sessions.lock() { sessions.insert(token.clone()); }
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
    Json(serde_json::json!({"admin": is_admin(&headers, &state)}))
}

async fn upload(State(state): State<AppState>, headers: HeaderMap, mut multipart: Multipart) -> Response {
    let admin = is_admin(&headers, &state);
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

        // Check again after receiving the stream in case another client uploaded
        // the same name at the same time.
        if destination.exists() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return json_error(StatusCode::CONFLICT, "A file with this name already exists");
        }
        if let Err(error) = tokio::fs::rename(&temporary, &destination).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not publish uploaded file: {error}"));
        }

        if !admin {
            // New uploads are public by default. Admin can mark them private afterwards.
        }
        count += 1;
    }

    Json(serde_json::json!({"ok":true,"uploaded":count})).into_response()
}

async fn set_private(
    State(state): State<AppState>, headers: HeaderMap, Path(name): Path<String>, Json(input): Json<PrivateInput>
) -> Response {
    if !is_admin(&headers, &state) { return json_error(StatusCode::UNAUTHORIZED, "Admin login required"); }
    let Some(name) = safe_name(&name) else { return json_error(StatusCode::BAD_REQUEST, "Invalid filename") };
    if !state.root.join(&name).is_file() { return json_error(StatusCode::NOT_FOUND, "File not found"); }
    if let Ok(mut private) = state.private_files.lock() {
        if input.private { private.insert(name); } else { private.remove(&name); }
    }
    match save_metadata(&state) {
        Ok(()) => Json(serde_json::json!({"ok":true})).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}


fn load_share_texts(root: &FsPath) -> Vec<ShareText> {
    fs::read_to_string(root.join(SHARE_TEXTS_FILE))
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<ShareText>>(&s).ok())
        .unwrap_or_default()
}

fn save_share_texts(state: &AppState) -> Result<(), String> {
    let texts = state.share_texts.lock().map_err(|_| "Lock error")?.clone();
    let data = serde_json::to_string_pretty(&texts).map_err(|e| e.to_string())?;
    fs::write(state.root.join(SHARE_TEXTS_FILE), data).map_err(|e| e.to_string())
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
    if let Ok(mut texts) = state.share_texts.lock() {
        if texts.len() >= 500 {
            return json_error(StatusCode::TOO_MANY_REQUESTS, "The shared text list is full (500 items maximum)");
        }
        texts.insert(0, item.clone());
    }
    match save_share_texts(&state) {
        Ok(()) => Json(item).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn delete_share_text(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>
) -> Response {
    if !is_admin(&headers, &state) {
        return json_error(StatusCode::UNAUTHORIZED, "Admin login required");
    }
    if let Ok(mut texts) = state.share_texts.lock() { texts.retain(|item| item.id != id); }
    match save_share_texts(&state) {
        Ok(()) => Json(serde_json::json!({"ok":true})).into_response(),
        Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
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
    let data = serde_json::to_string_pretty(config).map_err(|error| error.to_string())?;
    fs::write(path, data).map_err(|error| error.to_string())
}

fn load_saved_folder() -> Option<PathBuf> {
    let folder = load_app_config().folder?;
    if folder.is_dir() { Some(folder) } else { None }
}

fn save_folder(folder: &FsPath) {
    let mut config = load_app_config();
    config.folder = Some(folder.to_path_buf());
    let _ = save_app_config(&config);
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
        let mut config = load_app_config();
        config.startup_configured = true;
        config.startup_enabled = enabled_now;
        save_app_config(&config)?;
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
    let private = state.private_files.lock().map(|s| s.contains(&name)).unwrap_or(false);
    if private && !is_admin(&headers, &state) { return json_error(StatusCode::NOT_FOUND, "File not found"); }
    let path = state.root.join(&name);
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

    // Opt in to Windows sign-in startup once on first run. The admin switch can
    // still disable it, and that choice is persisted across future launches.
    #[cfg(windows)]
    {
        let mut config = load_app_config();
        if !config.startup_configured {
            match set_startup_enabled(true) {
                Ok(enabled) => {
                    config.startup_configured = true;
                    config.startup_enabled = enabled;
                    if let Err(error) = save_app_config(&config) {
                        eprintln!("Could not save startup preference: {error}");
                    }
                }
                Err(error) => eprintln!("Could not enable Windows startup: {error}"),
            }
        }
    }

    let state = AppState {
        private_files: Arc::new(Mutex::new(load_metadata(&folder))),
        share_texts: Arc::new(Mutex::new(load_share_texts(&folder))),
        root: folder.clone(),
        sessions: Arc::new(Mutex::new(HashSet::new())),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/api/files", get(list_files))
        .route("/api/network", get(network_info))
        .route("/api/texts", get(list_share_texts).post(add_share_text))
        .route("/api/texts/:id", axum::routing::delete(delete_share_text))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/auth", get(auth_status))
        .route("/api/startup", get(get_startup).post(update_startup))
        .route("/api/upload", post(upload))
        .route("/api/private/:name", post(set_private))
        .route("/download/:name", get(download))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], PORT));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => { eprintln!("Could not bind port {PORT}: {e}"); return; }
    };
    println!("\nFolder: {}", folder.display());
    println!("Made by Jelofen1962 · https://github.com/Jelofen1962");
    println!("Local:  http://127.0.0.1:{PORT}");
    println!("LAN:    http://{}:{PORT}", local_ip());
    println!("For internet sharing, configure router/firewall port forwarding and use your public IP.");
    println!("Blackbox Share runs in the system tray. Right-click its tray icon to open the dashboard or exit.");
    println!("Made by Jelofen1962 · https://github.com/Jelofen1962");
    #[cfg(windows)]
    let _tray = match setup_tray() {
        Ok(tray) => Some(tray),
        Err(error) => { eprintln!("Could not create tray icon: {error}"); None }
    };
    let _ = open::that(format!("http://127.0.0.1:{PORT}"));
    if let Err(e) = axum::serve(listener, app).await { eprintln!("Server error: {e}"); }
}
