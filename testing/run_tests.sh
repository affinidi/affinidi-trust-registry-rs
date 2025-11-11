#!/bin/bash

# Default values
TR_STORAGE_BACKEND="csv"
PROFILE_CONFIGS=""
TEST_TYPE="all"
COVERAGE="false"

# Parse flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --profile-configs) PROFILE_CONFIGS="$2"; shift ;;
        --storage-backend) TR_STORAGE_BACKEND="$2"; shift ;;
        --test-type) TEST_TYPE="$2"; shift ;;
        --coverage) COVERAGE="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Export required environment variables
export TR_STORAGE_BACKEND="$TR_STORAGE_BACKEND"
export PROFILE_CONFIGS="$PROFILE_CONFIGS"

echo "Using TR_STORAGE_BACKEND=$TR_STORAGE_BACKEND"
# echo "Using PROFILE_CONFIGS=$PROFILE_CONFIGS"

cp testing/.env.example .env.test
if [ $? -ne 0 ]; then
    echo "Failed to copy .env.example to .env.test. Please ensure the file exists and the destination is writable."
    exit 1
fi
source .env.test

# Create DynamoDB table if backend is ddb
if [ "$TR_STORAGE_BACKEND" == "ddb" ]; then
    export FILE_STORAGE_ENABLED=false
    # Check if localstack is already built
    if ! docker image inspect localstack_localstack >/dev/null 2>&1; then
        echo "Building localstack..."
        docker compose build localstack
    else
        echo "localstack already built. Skipping build."
       
    fi

    # Check if localstack container exists
    if docker ps -a --filter "name=localstack" | grep -q localstack; then
        echo "Removing existing localstack container..."
        docker rm -f localstack
    fi

    # Start localstack
    echo "Starting localstack..."
    docker compose up -d localstack

    # Wait for localstack to be ready (optional: add health check or sleep)
    sleep 5
    echo "Creating DynamoDB table 'test'..."
    aws dynamodb create-table \
        --table-name test \
        --attribute-definitions \
            AttributeName=PK,AttributeType=S \
            AttributeName=SK,AttributeType=S \
        --key-schema \
            AttributeName=PK,KeyType=HASH \
            AttributeName=SK,KeyType=RANGE \
        --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1 \
        --no-cli-pager

    if [ $? -ne 0 ]; then
        echo "Failed to create DynamoDB table. Exiting."
        exit 1
    fi

    echo "Adding records to DynamoDB table 'test'..."

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity1|did:example:authority1|action1|resource1"}, "SK": {"S": "did:example:entity1|did:example:authority1|action1|resource1"}, "entity_id": {"S": "did:example:entity1"}, "authority_id": {"S": "did:example:authority1"}, "action": {"S": "action1"}, "resource": {"S": "resource1"}, "recognized": {"BOOL": true}, "authorized": {"BOOL": true}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity2|did:example:authority2|action2|resource2"}, "SK": {"S": "did:example:entity2|did:example:authority2|action2|resource2"}, "entity_id": {"S": "did:example:entity2"}, "authority_id": {"S": "did:example:authority2"}, "action": {"S": "action2"}, "resource": {"S": "resource2"}, "recognized": {"BOOL": false}, "authorized": {"BOOL": true}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity3|did:example:authority3|action3|resource3"}, "SK": {"S": "did:example:entity3|did:example:authority3|action3|resource3"}, "entity_id": {"S": "did:example:entity3"}, "authority_id": {"S": "did:example:authority3"}, "action": {"S": "action3"}, "resource": {"S": "resource3"}, "recognized": {"BOOL": true}, "authorized": {"BOOL": false}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    if [ $? -ne 0 ]; then
        echo "Failed to add records to DynamoDB table. Exiting."
        exit 1
    fi
fi

# Run tests
echo "Running cargo tests..."
if [ "$COVERAGE" == "true" ]; then
    cargo llvm-cov --html   -p http-server -p didcomm-server -p app
elif [ "$TEST_TYPE" == "all" ]; then
    cargo test  
elif [ "$TEST_TYPE" == "unit" ]; then
    cargo test --lib
elif [ "$TEST_TYPE" == "int" ]; then
    cargo test --test integration_test
else
    echo "Unknown TEST_TYPE: $TEST_TYPE. Valid options are 'all', 'unit', 'int'."
    exit 1
fi