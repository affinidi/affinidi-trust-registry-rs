# Testing Guide

This guide provides instructions for running tests in the project, including unit tests, integration tests, and generating coverage reports.

---

For choosing the storage backend for any of the tests:
To run all tests with the DynamoDB storage backend:

Change the following env variables:
from:

```
TR_STORAGE_BACKEND=csv
FILE_STORAGE_ENABLED=true
```

to:

```
TR_STORAGE_BACKEND=ddb
FILE_STORAGE_ENABLED=false
```

## Run All Tests

If you have not setup your environment, please refer to [Setup Environment](../README.md#usage)

To run all tests (unit and integration):

```bash
bash run_tests.sh --profile-configs <PROFILE_CONFIGS>
```

---

## Run Unit Tests Only

To run only unit tests with the CSV storage backend:

```bash
bash run_tests.sh  --test-type unit
```

---

## Run Integration Tests Only

To run only integration tests with the CSV storage backend:

```bash
bash run_tests.sh  --test-type int
```

To run only integration tests with the DynamoDB storage backend:

```bash
bash run_tests.sh   --test-type int --storage-backend ddb
```

---

## Generate Coverage Report

To generate a coverage report:

```bash
bash run_tests.sh  --coverage true
```

To see the coverage report run:

```bash
open  target/llvm-cov/html/index.html
```

---
