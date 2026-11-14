# Contributing

When contributing to this repository, please first discuss the change you wish to make by creating a new [GitHub issue](https://github.com/affinidi/affinidi-trust-registry-rs/issues/new).

## Development Requirements

### Toolchain

The minimum supported Rust version is the `rust-version` in the root
[`Cargo.toml`](Cargo.toml) (edition 2024); CI builds and lints with the
toolchain it pins in [`.github/workflows/checks.yaml`](.github/workflows/checks.yaml).

### Testing

For the test suites, what each needs and how to run them, see
[testing/README.md](testing/README.md).

### Pre-commit checks

Run what CI runs (`checks.yaml`), with the toolchain it pins:

```bash
# Formatting
cargo fmt --all -- --check

# Lints, every crate, feature and target; warnings are errors
cargo clippy --workspace --all-features --all-targets -- -D warnings

# Documentation; broken intra-doc links are errors
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --all-features

# Tests that need no external services
cargo test -p trust-registry --lib --all-features
cargo test -p trql-client --all-features
cargo test -p trqp
cargo test -p test-trust-registry
```

The workspace denies `unsafe` code and warns on `unwrap()`/`expect()` outside
tests (`[workspace.lints]` in `Cargo.toml`).

### Pull requests

1. Every check in `checks.yaml` passes.
2. A user-visible change adds an entry under `## Unreleased` in
   [CHANGELOG.md](CHANGELOG.md), under the matching sub-heading (`### Breaking`
   for a breaking public-API or wire change). `main` never changes the
   workspace version; see [RELEASES.md](RELEASES.md).
3. A behaviour change comes with a test that fails without it.
4. Explain the *why* in comments where the code cannot: delivery and
   acknowledgement decisions, security checks, and anything a later reader
   would otherwise "simplify" away.
5. The PR description includes the pre-merge checklist of the VTI stack
   development guide (whose rule numbers it cites), checked honestly:

```
- [ ] No new reqwest::Client::new() / bare fetch(); all clients have finite timeouts (R1.2)
- [ ] No lock held across a network await (R1.3)
- [ ] No local state committed before its remote effect, or the flow is resumable with an idempotency key (R2.1)
- [ ] Every retry is bounded + backed off; non-idempotent ops are not blind-retried (R1.4)
- [ ] Accept/poll/listen loops survive transient errors (R1.5)
- [ ] Acks/deletes happen only after durable handoff (R1.6)
- [ ] New/changed wire types: camelCase, deny_unknown_fields where security-relevant, schema registered, all consumers (incl. JS) updated (R3.*)
- [ ] Config absence = most restrictive; fail-closed if enforcement can't start (R5.*)
- [ ] Logs/status claim only what was verified; background-job failures are surfaced (R6.*)
- [ ] "Process dies on the next line" answered for every mutation touched (R2.1)
- [ ] Deviations from this guide flagged explicitly with rule numbers
```

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding comments about code style and indentation: if you find yourself
  making one more than once, open an issue to change the `rustfmt` or Clippy
  configuration instead. Code reviews should be about logic.

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting