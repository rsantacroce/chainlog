//! chainlog-server: a standalone, isolated audit-log service.
//!
//! Run this as its own process so the application being audited never touches
//! the log files or the encryption key. The HTTP API only allows **append**,
//! **read**, and **verify** — there is deliberately no update or delete
//! endpoint, so a compromised client can at most add entries, never rewrite
//! history.
//!
//! ## Configuration (environment)
//! - `CHAINLOG_ADDR`        bind address (default `127.0.0.1:8888`)
//! - `CHAINLOG_DATA`        path to the JSONL log file (default `./chainlog.log`)
//! - `CHAINLOG_KEY`         base64 master key, OR `CHAINLOG_KEY_FILE` path
//! - `CHAINLOG_WRITE_TOKEN` bearer token required to append
//! - `CHAINLOG_READ_TOKEN`  bearer token required to read / verify / decrypt
//!
//! Roles are separated on purpose: a writer that can append does not need read
//! access, modelling separation of duties.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chainlog_core::{
    open, read_all, AuditLog, FileStore, LocalKeyProvider, Outcome, Record, verify_entries,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
struct AppState {
    log: AuditLog,
    key: Arc<LocalKeyProvider>,
    data_path: PathBuf,
    write_token: String,
    read_token: String,
}

/// An error that maps onto an HTTP status + JSON body.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<chainlog_core::Error> for ApiError {
    fn from(e: chainlog_core::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn require(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    match bearer(headers) {
        Some(t) if !expected.is_empty() && t == expected => Ok(()),
        _ => Err(ApiError(StatusCode::UNAUTHORIZED, "invalid or missing bearer token".into())),
    }
}

#[derive(Deserialize)]
struct RecordRequest {
    event_type: String,
    outcome: Outcome,
    actor: String,
    #[serde(default)]
    instruction_id: Option<String>,
    #[serde(default)]
    data: Value,
    #[serde(default)]
    pii: Option<Value>,
    #[serde(default = "default_key_id")]
    key_id: String,
}

fn default_key_id() -> String {
    "master".to_string()
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn append(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RecordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.write_token)?;

    let mut rec = Record::new(req.event_type, req.outcome, req.actor).key_id(req.key_id);
    if let Some(id) = req.instruction_id {
        rec = rec.instruction_id(id);
    }
    rec = rec.data(req.data);
    if let Some(pii) = req.pii {
        rec = rec.pii(pii);
    }

    let receipt = st.log.record(rec)?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

async fn head(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let (seq, head_hash) = st.log.head()?;
    Ok(Json(json!({ "seq": seq, "head_hash": head_hash })))
}

#[derive(Deserialize)]
struct ReadQuery {
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
    #[serde(default)]
    decrypt: bool,
}

async fn read_records(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReadQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;

    let entries = match read_all(&st.data_path) {
        Ok(e) => e,
        // An empty / not-yet-created log reads as no entries.
        Err(chainlog_core::Error::Io(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };

    let from = q.from.unwrap_or(0);
    let to = q.to.unwrap_or(u64::MAX);

    let mut out = Vec::new();
    for e in entries.iter().filter(|e| e.seq >= from && e.seq <= to) {
        let mut v = serde_json::to_value(e)?;
        if q.decrypt {
            if let Some(pii) = &e.payload.pii {
                match open(st.key.as_ref(), pii) {
                    Ok(plain) => v["payload"]["pii_plaintext"] = plain,
                    Err(err) => v["payload"]["pii_error"] = json!(err.to_string()),
                }
            }
        }
        out.push(v);
    }

    Ok(Json(json!({ "count": out.len(), "entries": out })))
}

async fn verify(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let entries = match read_all(&st.data_path) {
        Ok(e) => e,
        Err(chainlog_core::Error::Io(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let report = verify_entries(&entries);
    let status = if report.is_valid() {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    Ok((status, Json(report)))
}

fn load_key() -> Result<LocalKeyProvider, String> {
    if let Ok(b64) = std::env::var("CHAINLOG_KEY") {
        return LocalKeyProvider::from_base64(&b64).map_err(|e| e.to_string());
    }
    if let Ok(path) = std::env::var("CHAINLOG_KEY_FILE") {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {path}: {e}"))?;
        return LocalKeyProvider::from_base64(&contents).map_err(|e| e.to_string());
    }
    Err("set CHAINLOG_KEY (base64) or CHAINLOG_KEY_FILE".into())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "chainlog_server=info,tower_http=info".into()),
        )
        .json()
        .init();

    let addr = std::env::var("CHAINLOG_ADDR").unwrap_or_else(|_| "127.0.0.1:8888".into());
    let data_path =
        PathBuf::from(std::env::var("CHAINLOG_DATA").unwrap_or_else(|_| "./chainlog.log".into()));
    let write_token = std::env::var("CHAINLOG_WRITE_TOKEN").unwrap_or_default();
    let read_token = std::env::var("CHAINLOG_READ_TOKEN").unwrap_or_default();

    if write_token.is_empty() || read_token.is_empty() {
        tracing::warn!(
            "CHAINLOG_WRITE_TOKEN and/or CHAINLOG_READ_TOKEN are empty; all requests will be rejected"
        );
    }

    let key = match load_key() {
        Ok(k) => Arc::new(k),
        Err(e) => {
            tracing::error!("key configuration error: {e}");
            std::process::exit(1);
        }
    };

    let store = match FileStore::open(&data_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("opening data file {}: {e}", data_path.display());
            std::process::exit(1);
        }
    };

    let log = match AuditLog::builder()
        .store(store)
        .key_provider_arc(key.clone())
        .build()
    {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("building audit log: {e}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        log,
        key,
        data_path,
        write_token,
        read_token,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/records", post(append).get(read_records))
        .route("/v1/head", get(head))
        .route("/v1/verify", get(verify))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("binding {addr}: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("chainlog-server listening on {addr}");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
