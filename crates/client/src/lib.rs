//! # chainlog-client
//!
//! A small, typed async client for [`chainlog-server`]. It wraps the HTTP API
//! (append / read / head / verify / checkpoint / merkle / key management) and
//! returns the same types the core crate defines.
//!
//! ```no_run
//! use chainlog_client::{Client, AppendRequest};
//! use chainlog_core::Outcome;
//! use serde_json::json;
//!
//! # async fn run() -> Result<(), chainlog_client::Error> {
//! let client = Client::builder("http://127.0.0.1:8888")
//!     .write_token("write-secret")
//!     .read_token("read-secret")
//!     .build();
//!
//! let receipt = client
//!     .append(
//!         AppendRequest::new("user.login", Outcome::Success, "user-42")
//!             .data(json!({ "ip": "203.0.113.7" }))
//!             .pii(json!({ "email": "a@b.com" })),
//!     )
//!     .await?;
//! println!("sealed seq {}", receipt.seq);
//!
//! let report = client.verify().await?;
//! assert!(report.is_valid());
//! # Ok(())
//! # }
//! ```

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use chainlog_core::{
    AuditEntry, Checkpoint, MerkleAnchor, MerkleProof, Outcome, Receipt, VerifyReport,
};

/// Errors from the client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },

    #[error("this call requires a {0} token, but none was configured")]
    MissingToken(&'static str),
}

type Result<T> = std::result::Result<T, Error>;

/// Builder for a [`Client`].
pub struct ClientBuilder {
    base: String,
    write_token: Option<String>,
    read_token: Option<String>,
    admin_token: Option<String>,
}

impl ClientBuilder {
    pub fn write_token(mut self, t: impl Into<String>) -> Self {
        self.write_token = Some(t.into());
        self
    }
    pub fn read_token(mut self, t: impl Into<String>) -> Self {
        self.read_token = Some(t.into());
        self
    }
    pub fn admin_token(mut self, t: impl Into<String>) -> Self {
        self.admin_token = Some(t.into());
        self
    }
    pub fn build(self) -> Client {
        Client {
            base: self.base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            write_token: self.write_token,
            read_token: self.read_token,
            admin_token: self.admin_token,
        }
    }
}

/// An async client for a chainlog-server instance.
#[derive(Clone)]
pub struct Client {
    base: String,
    http: reqwest::Client,
    write_token: Option<String>,
    read_token: Option<String>,
    admin_token: Option<String>,
}

/// A record to append.
#[derive(Debug, Clone, Serialize)]
pub struct AppendRequest {
    pub event_type: String,
    pub outcome: Outcome,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl AppendRequest {
    pub fn new(event_type: impl Into<String>, outcome: Outcome, actor: impl Into<String>) -> Self {
        AppendRequest {
            event_type: event_type.into(),
            outcome,
            actor: actor.into(),
            instruction_id: None,
            data: serde_json::Value::Null,
            pii: None,
            key_id: None,
        }
    }
    pub fn instruction_id(mut self, id: impl Into<String>) -> Self {
        self.instruction_id = Some(id.into());
        self
    }
    pub fn data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }
    pub fn pii(mut self, pii: serde_json::Value) -> Self {
        self.pii = Some(pii);
        self
    }
    pub fn key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
}

/// The chain head.
#[derive(Debug, Clone, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub head_hash: String,
}

/// Response from a read query.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadResponse {
    pub count: usize,
    /// Entries as JSON values (PII bundles included; `pii_plaintext` present
    /// when `decrypt` was requested).
    pub entries: Vec<serde_json::Value>,
}

/// A Merkle inclusion proof response.
#[derive(Debug, Clone, Deserialize)]
pub struct MerkleProofResponse {
    pub seq: u64,
    pub leaf: Option<String>,
    pub root: String,
    pub proof: MerkleProof,
}

/// Result of creating a key.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub created: bool,
}

/// Result of shredding a key.
#[derive(Debug, Clone, Deserialize)]
pub struct ShredKeyResponse {
    pub key_id: String,
    pub shredded: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct KeyListResponse {
    key_ids: Vec<String>,
}

impl Client {
    pub fn builder(base: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base: base.into(),
            write_token: None,
            read_token: None,
            admin_token: None,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn write_tok(&self) -> Result<&str> {
        self.write_token
            .as_deref()
            .ok_or(Error::MissingToken("write"))
    }
    fn read_tok(&self) -> Result<&str> {
        self.read_token
            .as_deref()
            .ok_or(Error::MissingToken("read"))
    }
    fn admin_tok(&self) -> Result<&str> {
        self.admin_token
            .as_deref()
            .ok_or(Error::MissingToken("admin"))
    }

    /// Send a request and deserialize a success body, erroring on any non-2xx.
    async fn send<T: DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T> {
        let resp = rb.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Status {
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp.json::<T>().await?)
    }

    /// Append a record. Returns its receipt.
    pub async fn append(&self, req: AppendRequest) -> Result<Receipt> {
        let token = self.write_tok()?.to_string();
        self.send(
            self.http
                .post(self.url("/v1/records"))
                .bearer_auth(token)
                .json(&req),
        )
        .await
    }

    /// Read entries in `[from, to]`, optionally decrypting PII.
    pub async fn read(
        &self,
        from: Option<u64>,
        to: Option<u64>,
        decrypt: bool,
    ) -> Result<ReadResponse> {
        let token = self.read_tok()?.to_string();
        let mut q: Vec<(&str, String)> = vec![("decrypt", decrypt.to_string())];
        if let Some(f) = from {
            q.push(("from", f.to_string()));
        }
        if let Some(t) = to {
            q.push(("to", t.to_string()));
        }
        self.send(
            self.http
                .get(self.url("/v1/records"))
                .bearer_auth(token)
                .query(&q),
        )
        .await
    }

    /// Current chain head.
    pub async fn head(&self) -> Result<Head> {
        let token = self.read_tok()?.to_string();
        self.send(self.http.get(self.url("/v1/head")).bearer_auth(token))
            .await
    }

    /// Verify the chain. Returns the report on both a valid (`200`) and an
    /// invalid (`409`) chain; other statuses are errors.
    pub async fn verify(&self) -> Result<VerifyReport> {
        let token = self.read_tok()?.to_string();
        let resp = self
            .http
            .get(self.url("/v1/verify"))
            .bearer_auth(token)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() || status.as_u16() == 409 {
            Ok(resp.json::<VerifyReport>().await?)
        } else {
            Err(Error::Status {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    /// Fetch a fresh signed checkpoint of the head.
    pub async fn checkpoint(&self) -> Result<Checkpoint> {
        let token = self.read_tok()?.to_string();
        self.send(self.http.get(self.url("/v1/checkpoint")).bearer_auth(token))
            .await
    }

    /// Fetch a signed Merkle anchor over all entries.
    pub async fn merkle_anchor(&self) -> Result<MerkleAnchor> {
        let token = self.read_tok()?.to_string();
        self.send(
            self.http
                .get(self.url("/v1/merkle-anchor"))
                .bearer_auth(token),
        )
        .await
    }

    /// Fetch an inclusion proof for the entry with sequence `seq`.
    pub async fn merkle_proof(&self, seq: u64) -> Result<MerkleProofResponse> {
        let token = self.read_tok()?.to_string();
        self.send(
            self.http
                .get(self.url("/v1/merkle-proof"))
                .bearer_auth(token)
                .query(&[("seq", seq)]),
        )
        .await
    }

    /// Create (or ensure) a per-subject key. Requires keyring mode on the server.
    pub async fn create_key(&self, key_id: &str) -> Result<CreateKeyResponse> {
        let token = self.admin_tok()?.to_string();
        self.send(
            self.http
                .post(self.url(&format!("/v1/keys/{key_id}")))
                .bearer_auth(token),
        )
        .await
    }

    /// Crypto-shred a per-subject key. Requires keyring mode on the server.
    pub async fn shred_key(&self, key_id: &str) -> Result<ShredKeyResponse> {
        let token = self.admin_tok()?.to_string();
        self.send(
            self.http
                .delete(self.url(&format!("/v1/keys/{key_id}")))
                .bearer_auth(token),
        )
        .await
    }

    /// List the key_ids held by the server's keyring.
    pub async fn list_keys(&self) -> Result<Vec<String>> {
        let token = self.admin_tok()?.to_string();
        let resp: KeyListResponse = self
            .send(self.http.get(self.url("/v1/keys")).bearer_auth(token))
            .await?;
        Ok(resp.key_ids)
    }
}
