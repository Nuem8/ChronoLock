mod store;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::{now_unix, Record, Store, TakeError};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");
const APP_JS: &str = include_str!("../web/app.js");
const LOGO: &[u8] = include_bytes!("../web/logo.png");

const MAX_PLAIN_BYTES: usize = 8 * 1024;
const GCM_OVERHEAD: usize = 12 + 16;
const MAX_CIPHER_BYTES: usize = MAX_PLAIN_BYTES + GCM_OVERHEAD;
const MIN_CIPHER_BYTES: usize = GCM_OVERHEAD;
const MIN_TTL: u64 = 60;
const DEFAULT_MAX_TTL: u64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    limiter: Arc<Limiter>,
    max_ttl: u64,
    trust_proxy: bool,
}

struct Limiter {
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Limiter {
    fn allow(&self, key: &str, limit: usize, window: Duration) -> bool {
        let Ok(mut hits) = self.hits.lock() else {
            return false;
        };
        let now = Instant::now();
        if hits.len() > 10_000 {
            hits.retain(|_, times| times.iter().any(|at| now.duration_since(*at) < window));
        }
        let times = hits.entry(key.to_string()).or_default();
        times.retain(|at| now.duration_since(*at) < window);
        if times.len() >= limit {
            return false;
        }
        times.push(now);
        true
    }
}

#[derive(Deserialize)]
struct CreateBody {
    ciphertext: String,
    ttl_seconds: u64,
    burn: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct CreateResponse {
    id: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct RevealResponse {
    ciphertext: String,
    burn: bool,
    expires_at: i64,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[tokio::main]
async fn main() {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let store = if args.memory {
        eprintln!("ChronoLock storage is memory. Secrets die when this process stops.");
        Store::memory()
    } else {
        match Store::sqlite(&args.data) {
            Ok(store) => {
                eprintln!(
                    "ChronoLock storage is SQLite at {}. Secrets stay until they are revealed or they expire.",
                    args.data
                );
                store
            }
            Err(message) => {
                eprintln!("Could not open the SQLite file: {message}");
                std::process::exit(1);
            }
        }
    };
    store.delete_expired();

    let state = AppState {
        store: Arc::new(store),
        limiter: Arc::new(Limiter {
            hits: Mutex::new(HashMap::new()),
        }),
        max_ttl: args.max_ttl,
        trust_proxy: args.trust_proxy,
    };
    let cleaner = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            cleaner.store.delete_expired();
        }
    });

    let app = router(state);
    let listener = match tokio::net::TcpListener::bind(&args.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Could not listen on {}: {err}", args.listen);
            std::process::exit(1);
        }
    };
    eprintln!(
        "NueM8 ChronoLock listening on http://{}. No telemetry. The decryption key stays in the browser.",
        args.listen
    );

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    if let Err(err) = server.await {
        eprintln!("ChronoLock stopped: {err}");
        std::process::exit(1);
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/logo.png", get(logo))
        .route("/s/:id", get(index))
        .route("/api/secrets", post(create))
        .route("/api/secrets/:id/reveal", post(reveal))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

struct Args {
    listen: String,
    data: String,
    memory: bool,
    max_ttl: u64,
    trust_proxy: bool,
}

impl Args {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut listen = "127.0.0.1:8787".to_string();
        let mut data = "chronolock.db".to_string();
        let mut memory = false;
        let mut max_ttl = DEFAULT_MAX_TTL;
        let mut trust_proxy = false;
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => listen = need(&mut args, "--listen")?,
                "--data" => data = need(&mut args, "--data")?,
                "--store" => {
                    memory = match need(&mut args, "--store")?.as_str() {
                        "memory" => true,
                        "sqlite" => false,
                        other => {
                            return Err(format!(
                                "Unknown --store {other}. Use sqlite or memory."
                            ))
                        }
                    }
                }
                "--max-ttl" => {
                    let value = need(&mut args, "--max-ttl")?;
                    max_ttl = value.parse().map_err(|_| {
                        format!("--max-ttl needs a number of seconds, got {value}")
                    })?;
                    if max_ttl < MIN_TTL {
                        return Err(format!("--max-ttl must be at least {MIN_TTL} seconds."));
                    }
                }
                "--trust-proxy" => trust_proxy = true,
                "--help" | "-h" => return Err(help()),
                other => return Err(format!("Unknown argument {other}.\n{}", help())),
            }
        }
        Ok(Self {
            listen,
            data,
            memory,
            max_ttl,
            trust_proxy,
        })
    }
}

fn need(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{flag} needs a value."))
}

fn help() -> String {
    "NueM8 ChronoLock\n\n\
     --listen 127.0.0.1:8787   Address to serve\n\
     --store sqlite|memory     sqlite keeps secrets until they die; memory dies with the process\n\
     --data chronolock.db      SQLite file\n\
     --max-ttl 604800          Longest lifetime, in seconds\n\
     --trust-proxy             Read X-Forwarded-For when the peer is loopback\n"
        .to_string()
}

async fn index() -> Response {
    page(header::CONTENT_TYPE, "text/html; charset=utf-8", INDEX_HTML)
}

async fn css() -> Response {
    page(header::CONTENT_TYPE, "text/css; charset=utf-8", APP_CSS)
}

async fn js() -> Response {
    page(
        header::CONTENT_TYPE,
        "text/javascript; charset=utf-8",
        APP_JS,
    )
}

async fn logo() -> Response {
    let mut response = Response::new(LOGO.into());
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn page(kind: header::HeaderName, value: &'static str, body: &'static str) -> Response {
    let mut response = Response::new(body.into());
    let headers = response.headers_mut();
    headers.insert(kind, HeaderValue::from_static(value));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    response
}

async fn create(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateBody>,
) -> Response {
    let ip = client_ip(peer, &headers, state.trust_proxy);
    if !state
        .limiter
        .allow(&format!("create:{ip}"), 30, Duration::from_secs(60))
    {
        return error(StatusCode::TOO_MANY_REQUESTS, "Wait a minute, then try again.");
    }

    if body.ttl_seconds < MIN_TTL || body.ttl_seconds > state.max_ttl {
        return error(
            StatusCode::BAD_REQUEST,
            "Choose a lifetime between 1 minute and the server maximum.",
        );
    }

    let ciphertext = match decode_cipher(&body.ciphertext) {
        Ok(ciphertext) => ciphertext,
        Err(CipherError::TooLarge) => {
            return error(StatusCode::BAD_REQUEST, "That secret is larger than 8KB.");
        }
        Err(CipherError::Invalid) => {
            return error(StatusCode::BAD_REQUEST, "The encrypted secret is not valid.");
        }
    };

    let id = new_id();
    let expires_at = now_unix().saturating_add(body.ttl_seconds as i64);
    let record = Record {
        ciphertext,
        expires_at,
        burn: body.burn.unwrap_or(true),
    };
    if state.store.put(&id, record).is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "The secret was not saved.");
    }
    state.store.record_use(store::Use::Created);

    (
        StatusCode::CREATED,
        Json(CreateResponse { id, expires_at }),
    )
        .into_response()
}

async fn reveal(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !valid_id(&id) {
        return error(StatusCode::NOT_FOUND, "This secret is gone.");
    }
    let ip = client_ip(peer, &headers, state.trust_proxy);
    if !state
        .limiter
        .allow(&format!("reveal:{ip}"), 60, Duration::from_secs(60))
    {
        return error(StatusCode::TOO_MANY_REQUESTS, "Wait a minute, then try again.");
    }

    match state.store.take(&id) {
        Ok(record) => {
            state.store.record_use(store::Use::Revealed);
            (
                StatusCode::OK,
                Json(RevealResponse {
                    ciphertext: URL_SAFE_NO_PAD.encode(record.ciphertext),
                    burn: record.burn,
                    expires_at: record.expires_at,
                }),
            )
                .into_response()
        }
        Err(TakeError::Gone) => error(StatusCode::NOT_FOUND, "This secret is gone."),
        Err(TakeError::Store) => {
            error(StatusCode::INTERNAL_SERVER_ERROR, "The secret could not be read.")
        }
    }
}

enum CipherError {
    Invalid,
    TooLarge,
}

fn decode_cipher(text: &str) -> Result<Vec<u8>, CipherError> {
    if text.len() > MAX_CIPHER_BYTES * 2 || !text.bytes().all(is_b64url) {
        return Err(CipherError::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .map_err(|_| CipherError::Invalid)?;
    if bytes.len() < MIN_CIPHER_BYTES {
        Err(CipherError::Invalid)
    } else if bytes.len() > MAX_CIPHER_BYTES {
        Err(CipherError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'='
}

fn valid_id(id: &str) -> bool {
    (16..=64).contains(&id.len()) && id.bytes().all(is_b64url) && !id.contains('=')
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn client_ip(peer: SocketAddr, headers: &axum::http::HeaderMap, trust_proxy: bool) -> String {
    if trust_proxy && peer.ip().is_loopback() {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let first = first.trim();
                if !first.is_empty() && first.len() <= 64 {
                    return first.to_string();
                }
            }
        }
    }
    peer.ip().to_string()
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(Store::memory()),
            limiter: Arc::new(Limiter {
                hits: Mutex::new(HashMap::new()),
            }),
            max_ttl: DEFAULT_MAX_TTL,
            trust_proxy: false,
        }
    }

    fn cipher() -> String {
        URL_SAFE_NO_PAD.encode(vec![7u8; 40])
    }

    async fn send(app: Router, mut request: Request<Body>) -> (StatusCode, String) {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9))));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_burned_secret_is_readable_once() {
        let app = router(test_state());
        let (status, body) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/secrets")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"ciphertext\":\"{}\",\"ttl_seconds\":3600,\"burn\":true}}",
                    cipher()
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let created: CreateResponse = serde_json::from_str(&body).unwrap();

        let (status, revealed) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri(format!("/api/secrets/{}/reveal", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(revealed.contains("\"burn\":true"));

        let (status, _) = send(
            app,
            Request::builder()
                .method("POST")
                .uri(format!("/api/secrets/{}/reveal", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn opening_the_page_does_not_burn_the_secret() {
        let app = router(test_state());
        let (status, body) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/secrets")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"ciphertext\":\"{}\",\"ttl_seconds\":3600,\"burn\":true}}",
                    cipher()
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let created: CreateResponse = serde_json::from_str(&body).unwrap();

        let (status, page) = send(
            app.clone(),
            Request::builder()
                .uri(format!("/s/{}", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("ChronoLock"));

        let (status, _) = send(
            app,
            Request::builder()
                .method("POST")
                .uri(format!("/api/secrets/{}/reveal", created.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_secret_over_8kb_is_refused() {
        let app = router(test_state());
        let too_big = URL_SAFE_NO_PAD.encode(vec![7u8; MAX_CIPHER_BYTES + 1]);
        let (status, body) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/secrets")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"ciphertext\":\"{}\",\"ttl_seconds\":3600,\"burn\":true}}",
                    too_big
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("8KB"));

        let at_limit = URL_SAFE_NO_PAD.encode(vec![7u8; MAX_CIPHER_BYTES]);
        let (status, _) = send(
            app,
            Request::builder()
                .method("POST")
                .uri("/api/secrets")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"ciphertext\":\"{}\",\"ttl_seconds\":3600,\"burn\":true}}",
                    at_limit
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
}
