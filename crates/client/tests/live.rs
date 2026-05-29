//! Live round-trip test against a running chainlog-server.
//!
//! Ignored by default (CI compiles but doesn't run it). To run:
//!
//! ```bash
//! CHAINLOG_TEST_URL=http://127.0.0.1:8888 \
//! CHAINLOG_TEST_WRITE=write-secret \
//! CHAINLOG_TEST_READ=read-secret \
//! cargo test -p chainlog-client -- --ignored --nocapture
//! ```

use chainlog_client::{AppendRequest, Client};
use chainlog_core::Outcome;
use serde_json::json;

#[tokio::test]
#[ignore = "requires a running chainlog-server (set CHAINLOG_TEST_URL/WRITE/READ)"]
async fn live_roundtrip() {
    let url = std::env::var("CHAINLOG_TEST_URL").expect("CHAINLOG_TEST_URL");
    let write = std::env::var("CHAINLOG_TEST_WRITE").expect("CHAINLOG_TEST_WRITE");
    let read = std::env::var("CHAINLOG_TEST_READ").expect("CHAINLOG_TEST_READ");

    let client = Client::builder(url)
        .write_token(write)
        .read_token(read)
        .build();

    let receipt = client
        .append(
            AppendRequest::new("client.test", Outcome::Success, "tester")
                .data(json!({ "via": "chainlog-client" })),
        )
        .await
        .expect("append");
    assert!(receipt.seq >= 1);

    let head = client.head().await.expect("head");
    assert_eq!(head.head_hash, receipt.entry_hash);

    let report = client.verify().await.expect("verify");
    assert!(report.is_valid(), "chain should be intact: {report:?}");
}
