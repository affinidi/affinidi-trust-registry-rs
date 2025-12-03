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

## Run All Tests

If you have not setup your environment, please refer to [Setup Environment](../README.md#usage)

To run all tests (unit and integration):

```bash
bash testing/run_tests.sh --test-type all
```

## Run Unit Tests Only

To run only unit tests:

```bash
bash testing/run_tests.sh --test-type unit
```

## Run Integration Tests Only

To run only integration tests with the CSV storage backend:

```bash
bash testing/run_tests.sh  --test-type int
```

To run only integration tests with the DynamoDB storage backend:

```bash
bash testing/run_tests.sh   --test-type int --storage-backend ddb
```

## Generate Coverage Report

To generate a coverage report:

```bash
bash testing/run_tests.sh --coverage true
```

To view the coverage report:

```bash
open target/llvm-cov/html/index.html
```
