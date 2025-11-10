# Testing Guide

This guide provides instructions for running tests in the project, including unit tests, integration tests, and generating coverage reports.

---

## Run All Tests

To run all tests (unit and integration):

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS>
```

To run all tests with the DynamoDB storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --storage-backend ddb
```

---

## Run Unit Tests Only

To run only unit tests with the CSV storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --test_type unit
```

To run only unit tests with the DynamoDB storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --storage-backend ddb --test_type unit
```

---

## Run Integration Tests Only

To run only integration tests with the CSV storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --test_type int
```

To run only integration tests with the DynamoDB storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --storage-backend ddb --test_type int
```

---

## Generate Coverage Report

To generate a coverage report with the DynamoDB storage backend:

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS> --storage-backend ddb --coverage true
```

To see the coverage report run:

```bash
open  target/llvm-cov/html/index.html
```

---

Replace `<PROFILE_CONFIGS>` with the appropriate configuration file path for your environment.
