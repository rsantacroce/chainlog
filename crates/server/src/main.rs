//! chainlog-server: a standalone, isolated audit-log service.
//!
//! Run this as its own process so the application being audited never touches
//! the log files or the encryption key. The HTTP API only allows **append**,
//! **read**, and **verify** — there is deliberately no update or delete
//! endpoint, so a compromised client can at most add entries, never rewrite
//! history.
//!
//! ## Configuration (environment)
//! - `CHAINLOG_ADDR`: bind address (default `127.0.0.1:8888`)
//! - `CHAINLOG_DATA`: path to the JSONL log file, or segment dir (default `./chainlog.log`)
//! - `CHAINLOG_SEGMENT_MAX_ENTRIES`: if set, treat `CHAINLOG_DATA` as a segment directory and rotate every N entries
//! - `CHAINLOG_KEY`: base64 master key, OR `CHAINLOG_KEY_FILE` path
//! - `CHAINLOG_KEYRING_DIR`: if set, use per-subject keys here (enables crypto-shred + `/v1/keys` endpoints) instead of a master key
//! - `CHAINLOG_ADMIN_TOKEN`: bearer token required for key management
//! - `CHAINLOG_WRITE_TOKEN`: bearer token required to append
//! - `CHAINLOG_READ_TOKEN`: bearer token required to read / verify / decrypt
//! - `CHAINLOG_SIGN_KEY`: optional base64 Ed25519 seed; enables `/v1/checkpoint`
//!
//! Roles are separated on purpose: a writer that can append does not need read
//! access, modelling separation of duties.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    extract::{Path as AxPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chainlog_core::{
    build_merkle_anchor, merkle_proof_for_seq, merkle_root, now_ms, open, read_all,
    read_all_segmented, verify_entries, AuditEntry, AuditLog, CheckpointSigner, FileStore,
    KeyProvider, KeyringProvider, LocalKeyProvider, Outcome, Record, SegmentedStore,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
struct AppState {
    log: AuditLog,
    key: Arc<dyn KeyProvider>,
    keyring: Option<Arc<KeyringProvider>>,
    signer: Option<Arc<CheckpointSigner>>,
    data_path: PathBuf,
    segmented: bool,
    write_token: String,
    read_token: String,
    admin_token: String,
}

/// Read the full chain for reads/verify, tolerating a not-yet-created log.
fn read_log(path: &Path, segmented: bool) -> Result<Vec<AuditEntry>, ApiError> {
    let res = if segmented {
        read_all_segmented(path)
    } else {
        read_all(path)
    };
    match res {
        Ok(e) => Ok(e),
        Err(chainlog_core::Error::Io(_)) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
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
        _ => Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid or missing bearer token".into(),
        )),
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

    let entries = read_log(&st.data_path, st.segmented)?;

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

async fn checkpoint(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let signer = st.signer.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_IMPLEMENTED,
            "no signing key configured (set CHAINLOG_SIGN_KEY)".into(),
        )
    })?;
    let (seq, head_hash) = st.log.head()?;
    let cp = signer.sign(seq, &head_hash, now_ms());
    Ok(Json(cp))
}

async fn verify(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let entries = read_log(&st.data_path, st.segmented)?;
    let report = verify_entries(&entries);
    let status = if report.is_valid() {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    };
    Ok((status, Json(report)))
}

async fn merkle_anchor(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let signer = st.signer.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_IMPLEMENTED,
            "no signing key configured (set CHAINLOG_SIGN_KEY)".into(),
        )
    })?;
    let entries = read_log(&st.data_path, st.segmented)?;
    Ok(Json(build_merkle_anchor(signer, &entries, now_ms())))
}

#[derive(Deserialize)]
struct ProofQuery {
    seq: u64,
}

async fn merkle_proof_handler(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ProofQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.read_token)?;
    let entries = read_log(&st.data_path, st.segmented)?;
    let proof = merkle_proof_for_seq(&entries, q.seq).ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            format!("no entry with seq {}", q.seq),
        )
    })?;
    let leaf = entries
        .iter()
        .find(|e| e.seq == q.seq)
        .map(|e| e.entry_hash.clone());
    let leaves: Vec<&str> = entries.iter().map(|e| e.entry_hash.as_str()).collect();
    let root = merkle_root(&leaves);
    Ok(Json(json!({
        "seq": q.seq,
        "leaf": leaf,
        "root": root,
        "proof": proof,
    })))
}

fn require_keyring(st: &AppState) -> Result<&Arc<KeyringProvider>, ApiError> {
    st.keyring.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_IMPLEMENTED,
            "key management requires keyring mode (set CHAINLOG_KEYRING_DIR)".into(),
        )
    })
}

async fn create_key(
    State(st): State<AppState>,
    headers: HeaderMap,
    AxPath(key_id): AxPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.admin_token)?;
    let keyring = require_keyring(&st)?;
    let created = keyring.ensure(&key_id)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "key_id": key_id, "created": created })),
    ))
}

async fn shred_key(
    State(st): State<AppState>,
    headers: HeaderMap,
    AxPath(key_id): AxPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.admin_token)?;
    let keyring = require_keyring(&st)?;
    let shredded = keyring.shred(&key_id)?;
    Ok(Json(json!({ "key_id": key_id, "shredded": shredded })))
}

async fn list_keys(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require(&headers, &st.admin_token)?;
    let keyring = require_keyring(&st)?;
    Ok(Json(json!({ "key_ids": keyring.list()? })))
}

fn load_key() -> Result<LocalKeyProvider, String> {
    if let Ok(b64) = std::env::var("CHAINLOG_KEY") {
        return LocalKeyProvider::from_base64(&b64).map_err(|e| e.to_string());
    }
    if let Ok(path) = std::env::var("CHAINLOG_KEY_FILE") {
        let contents =
            std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?;
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

    // Pick a key provider: a per-subject keyring (enables crypto-shred + key
    // management endpoints) or a single master key.
    let (key, keyring): (Arc<dyn KeyProvider>, Option<Arc<KeyringProvider>>) =
        match std::env::var("CHAINLOG_KEYRING_DIR") {
            Ok(dir) => match KeyringProvider::open(&dir, true) {
                Ok(k) => {
                    tracing::info!("keyring mode: per-subject keys in {dir}");
                    let a = Arc::new(k);
                    (a.clone(), Some(a))
                }
                Err(e) => {
                    tracing::error!("opening keyring dir {dir}: {e}");
                    std::process::exit(1);
                }
            },
            Err(_) => match load_key() {
                Ok(k) => (Arc::new(k), None),
                Err(e) => {
                    tracing::error!("key configuration error: {e}");
                    std::process::exit(1);
                }
            },
        };
    let admin_token = std::env::var("CHAINLOG_ADMIN_TOKEN").unwrap_or_default();

    // If CHAINLOG_SEGMENT_MAX_ENTRIES is set, treat CHAINLOG_DATA as a segment
    // directory and rotate; otherwise it's a single append-only file.
    let segment_max = std::env::var("CHAINLOG_SEGMENT_MAX_ENTRIES")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let segmented = segment_max.is_some();

    let builder = AuditLog::builder().key_provider_arc(key.clone());
    let build_result = match segment_max {
        Some(max) => match SegmentedStore::open(&data_path, max) {
            Ok(s) => builder.store(s).build(),
            Err(e) => {
                tracing::error!("opening segment dir {}: {e}", data_path.display());
                std::process::exit(1);
            }
        },
        None => match FileStore::open(&data_path) {
            Ok(s) => builder.store(s).build(),
            Err(e) => {
                tracing::error!("opening data file {}: {e}", data_path.display());
                std::process::exit(1);
            }
        },
    };
    let log = match build_result {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("building audit log: {e}");
            std::process::exit(1);
        }
    };

    let signer = match std::env::var("CHAINLOG_SIGN_KEY") {
        Ok(b64) => match CheckpointSigner::from_base64(&b64) {
            Ok(s) => {
                tracing::info!("checkpoint signing enabled (pubkey {})", s.public_base64());
                Some(Arc::new(s))
            }
            Err(e) => {
                tracing::error!("invalid CHAINLOG_SIGN_KEY: {e}");
                std::process::exit(1);
            }
        },
        Err(_) => {
            tracing::info!("checkpoint signing disabled (set CHAINLOG_SIGN_KEY to enable)");
            None
        }
    };

    let state = AppState {
        log,
        key,
        keyring,
        signer,
        data_path,
        segmented,
        write_token,
        read_token,
        admin_token,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/records", post(append).get(read_records))
        .route("/v1/head", get(head))
        .route("/v1/checkpoint", get(checkpoint))
        .route("/v1/merkle-anchor", get(merkle_anchor))
        .route("/v1/merkle-proof", get(merkle_proof_handler))
        .route("/v1/verify", get(verify))
        .route("/v1/keys", get(list_keys))
        .route("/v1/keys/:key_id", post(create_key).delete(shred_key))
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
