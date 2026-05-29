# chainlog (CLI)

Offline tooling for [chainlog](https://github.com/rsantacroce/chainlog) audit logs.

```bash
cargo install chainlog-cli   # installs the `chainlog` binary

chainlog keygen                         # master key (base64)
chainlog gen-sign-key                   # Ed25519 checkpoint key
chainlog verify ./log                   # prove integrity (no key needed)
chainlog inspect ./log --key "$KEY"     # decrypt + read PII
chainlog checkpoint ./log --sign-key K  # signed checkpoint
chainlog merkle-proof ./log --seq 3     # inclusion proof
chainlog prune ./segs --before-days 365 # retention
chainlog shred ./keys subject-123       # crypto-shred a subject
```

The headline feature is `verify`: an auditor can prove a log was not tampered
with **without any decryption key**.

See the [repository](https://github.com/rsantacroce/chainlog) for details.

License: MIT
