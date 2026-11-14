#!/usr/bin/env bash
# Run the trust-registry test suites locally. See testing/README.md.
#
# Exits with the status of the test run. Anything this script starts (the
# registry container, LocalStack) is stopped on exit, whatever the outcome.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: testing/run_tests.sh [options]

  --test-type all|unit|int     which suites to run (default: all)
  --storage-backend csv|ddb|redis
                               overrides TR_STORAGE_BACKEND from .env.test
  --profile-configs JSON       overrides PROFILE_CONFIG from .env.test
  --coverage true|false        run under cargo llvm-cov and write an HTML
                               report (default: false)
EOF
}

TEST_TYPE="all"
COVERAGE="false"
ARG_PROFILE_CONFIG=""
ARG_STORAGE_BACKEND=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --profile-configs) ARG_PROFILE_CONFIG="${2:?--profile-configs needs a value}"; shift ;;
        --storage-backend) ARG_STORAGE_BACKEND="${2:?--storage-backend needs a value}"; shift ;;
        --test-type) TEST_TYPE="${2:?--test-type needs a value}"; shift ;;
        --coverage) COVERAGE="${2:?--coverage needs a value}"; shift ;;
        -h | --help) usage; exit 0 ;;
        *) echo "Unknown parameter passed: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$TEST_TYPE" in
    all | unit | int) ;;
    *) echo "Unknown --test-type: $TEST_TYPE. Valid options are 'all', 'unit', 'int'." >&2; exit 2 ;;
esac

REGISTRY_HEALTH_URL="${REGISTRY_HEALTH_URL:-http://127.0.0.1:3232/health}"
READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-120}"
TABLE_REGION="ap-southeast-1"

# Unit tests need no environment; everything else reads .env.test.
if [ "$TEST_TYPE" != "unit" ] || [ "$COVERAGE" == "true" ]; then
    if [ ! -f .env.test ]; then
        echo ".env.test not found. Please run the following command to set up the Trust Registry:" >&2
        echo "  cargo run --bin setup-trust-registry --features dev-tools -- --mediator-did <MEDIATOR_DID> --did-method peer --with-test-identities" >&2
        exit 1
    fi
    # Export everything .env.test sets, so cargo and the AWS CLI see it.
    set -a
    # shellcheck disable=SC1091
    source .env.test
    set +a
fi

# Command-line values win over .env.test.
if [ -n "$ARG_PROFILE_CONFIG" ]; then
    export PROFILE_CONFIG="$ARG_PROFILE_CONFIG"
fi
if [ -n "$ARG_STORAGE_BACKEND" ]; then
    export TR_STORAGE_BACKEND="$ARG_STORAGE_BACKEND"
fi
echo "Using TR_STORAGE_BACKEND=${TR_STORAGE_BACKEND:-csv}"

STARTED_REGISTRY="false"
STARTED_LOCALSTACK="false"
teardown() {
    local status=$?
    if [ "$STARTED_REGISTRY" == "true" ]; then
        docker compose -f docker-compose.test.yaml down || true
    fi
    if [ "$STARTED_LOCALSTACK" == "true" ]; then
        docker compose --profile dynamodb rm -sf localstack || true
    fi
    exit "$status"
}
trap teardown EXIT

# Poll `$@` once a second until it succeeds or READY_TIMEOUT_SECS passes.
wait_for() {
    local what=$1
    shift
    local deadline=$((SECONDS + READY_TIMEOUT_SECS))
    until "$@" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "$what was not ready after ${READY_TIMEOUT_SECS}s." >&2
            return 1
        fi
        sleep 1
    done
    echo "$what is ready."
}

# One trust record in the layout the DynamoDB adapter reads
# (trust-registry/src/domain/key.rs): PK "TR", SK
# "TR#{authority}#{action}#{resource}#{entity}". The identifiers used here
# contain neither `#` nor `%`, so they need no escaping.
put_record() {
    local entity=$1 authority=$2 action=$3 resource=$4 recognized=$5 authorized=$6 record_type=$7
    aws dynamodb put-item \
        --table-name "$DDB_TABLE_NAME" \
        --item "{
            \"PK\": {\"S\": \"TR\"},
            \"SK\": {\"S\": \"TR#${authority}#${action}#${resource}#${entity}\"},
            \"entity_id\": {\"S\": \"${entity}\"},
            \"authority_id\": {\"S\": \"${authority}\"},
            \"action\": {\"S\": \"${action}\"},
            \"resource\": {\"S\": \"${resource}\"},
            \"recognized\": {\"BOOL\": ${recognized}},
            \"authorized\": {\"BOOL\": ${authorized}},
            \"context\": {\"M\": {}},
            \"record_type\": {\"S\": \"${record_type}\"}
        }" \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region "$TABLE_REGION" \
        --no-cli-pager
}

setup_dynamodb() {
    : "${DYNAMODB_ENDPOINT:?DYNAMODB_ENDPOINT must be set (in .env.test) for the ddb backend}"
    : "${DDB_TABLE_NAME:?DDB_TABLE_NAME must be set (in .env.test) for the ddb backend}"
    echo "Starting LocalStack (DynamoDB)..."
    docker compose --profile dynamodb rm -sf localstack >/dev/null 2>&1 || true
    STARTED_LOCALSTACK="true"
    docker compose --profile dynamodb up -d localstack
    wait_for "LocalStack" aws dynamodb list-tables \
        --endpoint-url "$DYNAMODB_ENDPOINT" --region "$TABLE_REGION" --no-cli-pager

    echo "Creating DynamoDB table '$DDB_TABLE_NAME'..."
    aws dynamodb create-table \
        --table-name "$DDB_TABLE_NAME" \
        --attribute-definitions \
            AttributeName=PK,AttributeType=S \
            AttributeName=SK,AttributeType=S \
        --key-schema \
            AttributeName=PK,KeyType=HASH \
            AttributeName=SK,KeyType=RANGE \
        --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region "$TABLE_REGION" \
        --no-cli-pager >/dev/null

    echo "Adding records to DynamoDB table '$DDB_TABLE_NAME'..."
    put_record did:example:entity1 did:example:authority1 action1 resource1 true true authorization
    put_record did:example:entity2 did:example:authority2 action2 resource2 false true authorization
    put_record did:example:entity3 did:example:authority3 action3 resource3 true false authorization
}

start_registry() {
    echo "Starting the registry container..."
    STARTED_REGISTRY="true"
    docker compose -f docker-compose.test.yaml up -d --build
    wait_for "The registry" curl -fsS "$REGISTRY_HEALTH_URL"
}

if [ "$TEST_TYPE" != "unit" ] || [ "$COVERAGE" == "true" ]; then
    if [ "${TR_STORAGE_BACKEND:-csv}" == "ddb" ] || [ "${TR_STORAGE_BACKEND:-csv}" == "dynamodb" ]; then
        setup_dynamodb
    fi
fi

echo "Running cargo tests..."
if [ "$COVERAGE" == "true" ]; then
    start_registry
    cargo llvm-cov --html -p trust-registry
elif [ "$TEST_TYPE" == "all" ]; then
    start_registry
    cargo test -p trust-registry
elif [ "$TEST_TYPE" == "unit" ]; then
    cargo test --lib -p trust-registry
else
    start_registry
    cargo test -p trust-registry --test didcomm_integration_test --test http_integration_test -- --nocapture
fi
# `set -e` exits on a failed test run above with its status; the EXIT trap
# tears down and preserves it.
