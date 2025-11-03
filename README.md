# Affinidi "Trust Registry"

## Requirements

## Installation

Install rust or validate that it is installed.  

```bash
rustc --version
cargo --version
```

## Usage

### Run locally

Clone env:   

```bash
cp .env.example .env
```

Run http-server (instructions for didcomm-server will be added later):  

```bash
RUST_LOG=info cargo run --bin http-server  
```  
Note: run from root of repo.  

Query data that is stored in `./sample-data/data.csv`

```bash
curl --location 'http://localhost:3232/recognition' \
--header 'Content-Type: application/json' \
--data '{
    "authority_id": "did:example:authority1",
    "entity_id": "did:example:entity1",
    "assertion_id": "assertion1"
}'
```  

Test with defined and non-defined ids.  
Add more records to  `./sample-data/data.csv` (context is base64 encoded VALID JSON).

### Run in docker

#### Build and run

Build:  

```bash
docker buildx build \
  --platform linux/arm64 \
  -f http-server/Dockerfile \
  -t trust-registry-http \
  --load \
  .
```   
Run:  

```bash
docker run \
  -e LISTEN_ADDRESS=0.0.0.0:3232 \
  -e RUST_LOG=debug,http_server=trace \
  -e TR_STORAGE_BACKEND=csv \
  -e FILE_STORAGE_PATH="/usr/local/bin/sample-data/data.csv" \
  -p 3232:3232 \
  trust-registry-http
```

#### docker compose

Review env vars in ./docker-compose.yaml and run:  

```bash
docker compose up --build
```  
In that scenario, sample-data folder is linked as an volume for container, data.csv changes is synced by the container.