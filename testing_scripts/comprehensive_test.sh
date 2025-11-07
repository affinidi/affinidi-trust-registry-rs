#!/bin/bash

# Default values
TR_STORAGE_BACKEND="csv"
PROFILE_CONFIGS=""

# Parse flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --profile-configs) PROFILE_CONFIGS="$2"; shift ;;
        --storage-backend) TR_STORAGE_BACKEND="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Export required environment variables
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export DYNAMODB_TABLE_NAME=test
export DYNAMODB_ENDPOINT=http://localhost:4566
export MEDIATOR_DID=did:web:66a6ec69-0646-4a8d-ae08-94e959855fa9.atlas.affinidi.io
export ADMIN_DIDS=did:peer:2.Vz6Mkpun7xEJWBqwtaiHSqfjLe1ejqQ4PAUEas1gjH7VVNxjs.EzQ3shoprXELvJw9ou4VbfrFRx5FZQsP9EB1LMUJaPacDKtiZ8
export CORS_ALLOWED_ORIGINS=http://localhost:3000
export TR_STORAGE_BACKEND="$TR_STORAGE_BACKEND"
export PROFILE_CONFIGS="$PROFILE_CONFIGS"
export FILE_STORAGE_ENABLED=true

echo "Using TR_STORAGE_BACKEND=$TR_STORAGE_BACKEND"
echo "Using PROFILE_CONFIGS=$PROFILE_CONFIGS"



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
        --region ap-southeast-1

    if [ $? -ne 0 ]; then
        echo "Failed to create DynamoDB table. Exiting."
        exit 1
    fi

    echo "Adding records to DynamoDB table 'test'..."

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity1|did:example:authority1|assertion1"}, "SK": {"S": "did:example:entity1|did:example:authority1|assertion1"}, "entity_id": {"S": "did:example:entity1"}, "authority_id": {"S": "did:example:authority1"}, "assertion_id": {"S": "assertion1"}, "recognized": {"BOOL": true}, "assertion_verified": {"BOOL": true}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity2|did:example:authority2|assertion2"}, "SK": {"S": "did:example:entity2|did:example:authority2|assertion2"}, "entity_id": {"S": "did:example:entity2"}, "authority_id": {"S": "did:example:authority2"}, "assertion_id": {"S": "assertion2"}, "recognized": {"BOOL": false}, "assertion_verified": {"BOOL": true}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    aws dynamodb put-item \
        --table-name test \
        --item '{"PK": {"S": "did:example:entity3|did:example:authority3|assertion3"}, "SK": {"S": "did:example:entity3|did:example:authority3|assertion3"}, "entity_id": {"S": "did:example:entity3"}, "authority_id": {"S": "did:example:authority3"}, "assertion_id": {"S": "assertion3"}, "recognized": {"BOOL": true}, "assertion_verified": {"BOOL": false}, "context": {"S": "eyJ0ZXN0IjogImNvbnRleHQifQ=="}}' \
        --endpoint-url "$DYNAMODB_ENDPOINT" \
        --region ap-southeast-1

    if [ $? -ne 0 ]; then
        echo "Failed to add records to DynamoDB table. Exiting."
        exit 1
    fi
fi

# Run tests
echo "Running cargo tests..."
cargo test 