# Running the Test Client

The test client demonstrates how to interact with the Trust Registry using DIDComm for administrative operations (create, read, update, delete, list trust records).

When the test-client is executed, it performs the following steps:

1. Connect to the Trust Registry via DIDComm
2. Perform a series of administrative operations:
   - **Create** a sample trust record.
   - **Read** the created record.
   - **Update** the record with new information.
   - **List** all trust records.
   - **Delete** the trust record.
   - **Read** again to verify deletion.
4. Listen for responses from the Trust Registry

## Prerequisites

Before running the test client, ensure you have:

1. **User Configuration**: A valid `conf/user_config.json` file with admin user profiles and their secrets.
2. **Trust Registry Setup**: Ensure you have configured the Trust Registry with authorised admin DIDs using the `ADMIN_DIDS` environment variable.

## Configuration Variables

The test client requires the following environment variables:

- `TRUST_REGISTRY_DID` - The DID of the Trust Registry to connect to.
- `MEDIATOR_DID` - The DID of the mediator service to send messages.

The test-client loads the configuration in the following order:

1. **Runtime environment variables** to parse the configuration.
2. **`.env` file** in the project root directory of the local Trust Registry setup as a fallback.

**Note:** For `TRUST_REGISTRY_DID`, if not provided at runtime, the test-client will extract the `did` property from the `PROFILE_CONFIG` JSON variable found in the `.env` file.

## Usage

### Option 1: Using Local Trust Registry Setup (Default)

If you have set up a local Trust Registry instance, the required environment variables are typically already configured in the `.env` file at the project root directory.

```bash
cd test-client
cargo run
```

The default run will:
- Parse `TRUST_REGISTRY_DID` from `PROFILE_CONFIG.did` in the `.env` file
- Parse `MEDIATOR_DID` from the `.env` file

### Option 2: Connecting to a Remote Trust Registry

You can connect to a remote Trust Registry by providing environment variables at runtime.

```bash
cd test-client
TRUST_REGISTRY_DID="did:web:..." MEDIATOR_DID="did:web:..." cargo run
```

This approach is useful for:
- Connecting to a remote Trust Registry without local setup.
- Testing against different Trust Registry instances.

## Troubleshooting

- **Authorization errors**: Ensure the DID from `conf/user_config.json` is configured as an authorised admin in the Trust Registry's `ADMIN_DIDS` environment variable.
- **"TRUST_REGISTRY_DID environment variable is not set"**: Either set it at runtime or ensure `PROFILE_CONFIG` exists in your `.env` file.
- **"Unable to find 'SampleTRAdmin' from the user_config.json"**: Check that `conf/user_config.json` contains a user with the alias "SampleTRAdmin".