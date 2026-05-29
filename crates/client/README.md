# chainlog-client

Typed async HTTP client for [chainlog-server](https://github.com/rsantacroce/chainlog).

```rust,no_run
use chainlog_client::{Client, AppendRequest};
use chainlog_core::Outcome;
use serde_json::json;

# async fn run() -> Result<(), chainlog_client::Error> {
let client = Client::builder("http://127.0.0.1:8888")
    .write_token("write-secret")
    .read_token("read-secret")
    .build();

client.append(
    AppendRequest::new("user.login", Outcome::Success, "user-42")
        .pii(json!({ "email": "a@b.com" })),
).await?;

assert!(client.verify().await?.is_valid());
# Ok(())
# }
```

Covers append / read / head / verify / checkpoint / merkle / key management.

See the [repository](https://github.com/rsantacroce/chainlog) for details.

License: MIT
