# Affinidi "Trust Registry"

## Requirements

## Installation

Install rust or validate that it is installed.  

```bash
rustc --version
cargo --version
```

## Usage

### Run in dev mode

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
