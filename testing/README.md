# Testing Guide

This guide provides instructions for running tests in the trust-registry project, including unit tests, integration tests, and generating coverage reports.

## Storage Backend Configuration

For choosing the storage backend for any of the tests:

**CSV Storage (default):**

```bash
TR_STORAGE_BACKEND=csv
```

**DynamoDB Storage:**

```bash
TR_STORAGE_BACKEND=ddb
```

## Option 1: Run Tests Using Testing Script

If you have not setup your environment, please refer to [Setup Environment](../README.md#set-up-environment)

### To run all tests (unit and integration):

```bash
bash testing/run_tests.sh --test-type all
```

### Run Unit Tests Only

To run only unit tests:

```bash
bash testing/run_tests.sh --test-type unit
```

### Run Integration Tests Only

To run only integration tests with the CSV storage backend:

```bash
bash testing/run_tests.sh  --test-type int
```

To run only integration tests with the DynamoDB storage backend:

```bash
bash testing/run_tests.sh   --test-type int --storage-backend ddb
```

### Generate Coverage Report

To generate a coverage report:

```bash
bash testing/run_tests.sh --coverage true
```

To view the coverage report:

```bash
open target/llvm-cov/html/index.html
```

## Option 2: Manual Run (No Script)

If you prefer not to use the helper script, you can run tests directly with Cargo. Use the storage backend environment variable from above before running any commands.

### Prerequisites

- For integration tests trust registry instance must be running.
- For DynamoDB tests, a local DynamoDB instance running (see below).

### Run All Tests

```bash
docker compose -f docker-compose.test.yaml up -d
cargo test -p trust-registry
```

### Unit Tests Only

```bash
cargo test --lib -p trust-registry
```

### Integration Tests

```bash
docker compose -f docker-compose.test.yaml up -d

cargo test --test http_integration_test --test didcomm_integration_test --test didcomm_server_test -- --no-capture
```

### Coverage

install cargo-llvm

```bash
# Install once
cargo install cargo-llvm-cov
```

```bash
docker compose -f docker-compose.test.yaml up -d

cargo llvm-cov --html -p trust-registry

open target/llvm-cov/html/index.html
```

Notes:

- If any service-specific tests need a running server, ensure corresponding services are up via `docker compose` before running integration tests.
