# chainlog-server

Standalone, isolated HTTP service for [chainlog](https://github.com/rsantacroce/chainlog).

Run it as its own process so the audited application never touches the log files
or the encryption key — it can only **append**, never rewrite history. The API
covers append / read / head / verify / checkpoint / merkle anchoring / key
management (crypto-shred), with role-split bearer tokens.

```bash
cargo install chainlog-server
CHAINLOG_KEY=$(chainlog keygen) \
CHAINLOG_WRITE_TOKEN=write CHAINLOG_READ_TOKEN=read \
chainlog-server
```

See the [repository](https://github.com/rsantacroce/chainlog) and
[`docs/PROTOCOL.md`](https://github.com/rsantacroce/chainlog/blob/main/docs/PROTOCOL.md)
for configuration and the full HTTP API.

License: MIT
