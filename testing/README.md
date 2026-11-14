# Testing Guide

How to run the workspace's test suites, what each one needs, and how CI runs
them (`.github/workflows/checks.yaml`).

## The suites

| Suite | Command | Needs |
|---|---|---|
| `trust-registry` unit tests | `cargo test -p trust-registry --lib --all-features` | nothing |
| `trql-client` (unit + `tests/https_binding.rs`) | `cargo test -p trql-client --all-features` | nothing |
| `trqp` | `cargo test -p trqp` | nothing |
| `test-trust-registry` smoke test | `cargo test -p test-trust-registry` | nothing (in-process registry) |
| `trust-registry` `http_integration_test` | `cargo test -p trust-registry --test http_integration_test` | a running registry at `LISTEN_ADDRESS` from `.env.test` |
| `trust-registry` `didcomm_integration_test`, `didcomm_server_test` | `cargo test -p trust-registry --test didcomm_integration_test --test didcomm_server_test` | `.env.test` from `setup-trust-registry … --with-test-identities`, a reachable mediator, and (for `didcomm_integration_test`) a running registry |
| `trust-registry` `redis_integration_test` | `cargo test -p trust-registry --test redis_integration_test` | Redis on `redis://127.0.0.1:6379`; each test is skipped (passes) when Redis is not reachable |
| `trust-registry` `mediator_e2e` | `cargo test -p trust-registry --test mediator_e2e -- --ignored --nocapture` | Docker (starts Redis and the mediator image); `#[ignore]`d by default, see the module docs for its environment variables |
| `test-trust-registry` mediator tests | `cargo test -p test-trust-registry --features tsp -- --include-ignored` (`tsp` implies `mediator`) | Redis on `127.0.0.1:6379` for the in-process test mediator, and a heavy build; the routed round-trips are `#[ignore]`d |

`cargo test -p trust-registry` with no `--test` runs the unit tests and every
integration test above that is not ignored, so it needs a running registry and
mediator.

## Setting up `.env.test`

The integration tests read `.env.test`. Create it with
`setup-trust-registry` (see [Set up Trust Registry](../README.md#set-up-trust-registry)):

```bash
cargo run --bin setup-trust-registry --features dev-tools -- --mediator-did <mediator DID> --did-method peer --with-test-identities
```

It generates test DIDs for the registry and a test client, writes them to
`.env.test` (from `testing/.env.test.example`), and opens their mediator
accounts.

## Storage backend

`TR_STORAGE_BACKEND` selects the registry's backend: `csv` (default), `ddb`
(or `dynamodb`), `redis`, or `fjall` (with the `storage-fjall` feature).
`.env.test` sets it; `run_tests.sh --storage-backend` overrides it.

## Using `run_tests.sh`

`testing/run_tests.sh`, run from the repository root, starts what the chosen
suites need, runs them, stops what it started, and exits with the tests'
status:

```bash
bash testing/run_tests.sh --test-type unit                          # unit tests only, no services
bash testing/run_tests.sh --test-type int                           # HTTP + DIDComm integration tests
bash testing/run_tests.sh --test-type int --storage-backend ddb     # the same against LocalStack DynamoDB
bash testing/run_tests.sh --test-type all                           # cargo test -p trust-registry
bash testing/run_tests.sh --coverage true                           # HTML coverage report
```

| Option | Meaning |
|---|---|
| `--test-type all\|unit\|int` | which suites (default `all`) |
| `--storage-backend csv\|ddb\|redis` | overrides `TR_STORAGE_BACKEND` from `.env.test` |
| `--profile-configs <JSON>` | overrides `PROFILE_CONFIG` from `.env.test` |
| `--coverage true` | run under `cargo llvm-cov --html` (install with `cargo install cargo-llvm-cov`) |

For `int`, `all` and coverage it builds and starts the registry container
(`docker-compose.test.yaml`) and waits until `/health` answers. With the
`ddb` backend it also starts LocalStack (`docker compose --profile dynamodb`),
waits until DynamoDB answers, creates the `DDB_TABLE_NAME` table and seeds
three records in the layout the DynamoDB adapter reads (`PK` = `TR`, `SK` =
`TR#<authority>#<action>#<resource>#<entity>`). It needs Docker, `curl` and,
for `ddb`, the AWS CLI with `DYNAMODB_ENDPOINT` set in `.env.test`.

## Coverage

```bash
cargo install cargo-llvm-cov
cargo llvm-cov -p trust-registry --html
open target/llvm-cov/html/index.html
```

CI measures `cargo llvm-cov --all-features -p trust-registry` against a
running registry and fails below 45 % line coverage
(`--fail-under-lines=45`). `--lcov --output-path lcov.info` writes an LCOV
file instead of HTML.

## What CI runs

`checks.yaml` (every job must pass for `nightly` to advance):

- the shared `pipeline-rust` checks: `cargo fmt --check`, `cargo check` and
  `cargo clippy --no-deps` with default features, `cargo deny`, `cargo audit`;
- `lint`: `cargo clippy --workspace --all-features --all-targets` and the
  feature combinations of `trust-registry`, `trql-client` and
  `test-trust-registry`, all with `-D warnings`; `cargo doc` with
  `RUSTDOCFLAGS=-D warnings`; `shellcheck` on the shell scripts;
- `msrv`: `cargo check --workspace --all-features` on the `rust-version`
  `Cargo.toml` declares;
- `test-features`: the unit tests of `trql-client` with no transport, `didcomm`
  only and `tsp` only, and of `trust-registry` without default features, with
  `storage-fjall`, `tsp` and `vta`;
- `docker`: builds `trust-registry/Dockerfile` and checks the container
  answers `/health`;
- the test suite: the registry is started against the CI mediator, then
  coverage of `trust-registry` (all its non-ignored tests), the `trql-client`
  and `trqp` tests, the `test-trust-registry` smoke test, and a build
  (`--no-run`) of the `test-trust-registry` mediator tests (they need Redis).

The `#[ignore]`d suites (`mediator_e2e`, and every `test-trust-registry`
mediator test, which need Redis) run in `ignored-tests.yml`, daily and on demand (Actions → ignored
tests → Run workflow). It is not a PR gate.
