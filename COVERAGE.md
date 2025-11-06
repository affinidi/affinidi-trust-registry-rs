# Test Coverage for trust-registry-rs

This document explains how to generate and view test coverage reports for the trust-registry-rs project.

## Quick Start

### Generate HTML Coverage Report (Recommended)

```bash
./coverage.sh html
# or
cargo llvm-cov --all-features --workspace --html
```

Then open `target/llvm-cov/html/index.html` in your browser to view the interactive coverage report.

### Generate LCOV Report (CI/CD friendly)

```bash
./coverage.sh lcov
# or
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
```

### Generate JSON Report (Machine readable)

```bash
./coverage.sh json
# or
cargo llvm-cov --all-features --workspace --json --output-path coverage.json
```

### View Coverage in Terminal

```bash
./coverage.sh text
# or
cargo llvm-cov --all-features --workspace
```

## Coverage Commands Reference

| Command                             | Description                              | Output                  |
| ----------------------------------- | ---------------------------------------- | ----------------------- |
| `cargo llvm-cov --workspace`        | Basic coverage for all workspace members | Terminal output         |
| `cargo llvm-cov --workspace --html` | HTML report with interactive interface   | `target/llvm-cov/html/` |
| `cargo llvm-cov --workspace --lcov` | LCOV format (compatible with most tools) | `lcov.info`             |
| `cargo llvm-cov --workspace --json` | Machine-readable JSON format             | `coverage.json`         |

## Advanced Usage

### Coverage for Specific Package

```bash
cargo llvm-cov -p app --html
cargo llvm-cov -p didcomm-server --html
cargo llvm-cov -p http-server --html
```

### Coverage with Specific Features

```bash
cargo llvm-cov --features feature-name --html
```

### Coverage Excluding Tests

```bash
cargo llvm-cov --workspace --html --ignore-filename-regex tests
```

### GitHub Actions Future Integration

Add this to your `.github/workflows/test.yml`:

```yaml
- name: Install cargo-llvm-cov
  run: cargo install cargo-llvm-cov

- name: Generate code coverage
  run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info

- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    file: lcov.info
```

## Coverage Thresholds

You can set minimum coverage requirements:

```bash
# Fail if coverage is below 80%
cargo llvm-cov --workspace --fail-under-lines 80
```
