# Nox · Handle Gateway

[![License](https://img.shields.io/badge/license-BUSL--1.1-blue)](./LICENSE) [![Docs](https://img.shields.io/badge/docs-nox--protocol-purple)](https://docs.iex.ec) [![Discord](https://img.shields.io/badge/chat-Discord-5865F2)](https://discord.com/invite/5TewNUnJHN) [![Ship](https://img.shields.io/github/v/tag/iExec-Nox/nox-handle-gateway?label=ship)](https://github.com/iExec-Nox/nox-handle-gateway/releases)

> REST gateway for encrypted value storage and delegation in the Nox Protocol.

## Table of Contents

- [Nox · Handle Gateway](#nox--handle-gateway)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Getting Started](#getting-started)
  - [Environment Variables](#environment-variables)
    - [Global variables](#global-variables)
    - [Per-chain variables (`CHAINS__<CHAIN_ID>__*`)](#per-chain-variables-chains__chain_id__)
  - [API Reference](#api-reference)
    - [Service Endpoints](#service-endpoints)
      - [`GET /`](#get-)
      - [`GET /health`](#get-health)
      - [`GET /metrics`](#get-metrics)
    - [Handle Endpoints](#handle-endpoints)
      - [`POST /v0/secrets`](#post-v0secrets)
      - [`GET /v0/secrets/{handle}`](#get-v0secretshandle)
      - [`GET /v0/compute/operands`](#get-v0computeoperands)
      - [`POST /v0/compute/results`](#post-v0computeresults)
      - [`POST /v0/public/handles/status`](#post-v0publichandlesstatus)
      - [`GET /v0/public/{handle}`](#get-v0publichandle)
  - [Related Repositories](#related-repositories)
  - [License](#license)

---

## Overview

The Handle Gateway is the off-chain custody layer for encrypted values referenced by on-chain handles. It is the only service that writes ciphertexts to storage and the only service that calls [nox-kms](https://github.com/iExec-Nox/nox-kms) to delegate re-encrypted material. All responses carry an EIP-712 signature so callers can verify origin cryptographically.

**Storing an encrypted value (`POST /v0/secrets`):** A caller submits a plaintext value to be stored confidentially. The gateway encrypts it under the KMS public key using ECIES (secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM), generates a 32-byte handle as the on-chain reference, and returns a signed `HandleProof` that smart contracts can verify to confirm the handle was legitimately created by this gateway.

**Decrypting a value (`GET /v0/secrets/{handle}`):** An authorised party (owner or ACL grantee) retrieves the encrypted material for a handle. The gateway verifies the caller's EIP-712 token, checks on-chain ACL, and delegates to [nox-kms](https://github.com/iExec-Nox/nox-kms) which RSA-OAEP-encrypts the shared secret for the caller's RSA key. The caller decrypts locally; the KMS private key never leaves the KMS.

**Confidential computation (`GET /v0/compute/operands`, `POST /v0/compute/results`):** The off-chain [nox-runner](https://github.com/iExec-Nox/nox-runner) uses these endpoints to fetch encrypted inputs before a computation and publish encrypted outputs after. This enables computation over confidential handles without the runner ever seeing plaintext values.

**Polling handle resolution (`POST /v0/public/handles/status`):** Any caller can check whether a batch of handles is already stored.

**Public decryption (`GET /v0/public/{handle}`):** When the handle owner has granted public decryptability on-chain, anyone can retrieve the plaintext. The gateway delegates to [nox-kms](https://github.com/iExec-Nox/nox-kms) using its own RSA key, decrypts locally, and returns a `DecryptionProof` signed by the gateway that proves the decryption was performed correctly.

---

## Prerequisites

- Rust >= 1.85 (edition 2024)
- An S3-compatible object store (AWS S3 or MinIO) with Object Lock enabled
- Access to an Ethereum RPC endpoint
- A running [nox-kms](https://github.com/iExec-Nox/nox-kms) instance

---

## Getting Started

```bash
git clone https://github.com/iExec-Nox/nox-handle-gateway.git
cd nox-handle-gateway

# Per-chain config — repeat this block for each chain ID you want to serve
export NOX_HANDLE_GATEWAY_CHAINS__421614__RPC_URL="https://..."
export NOX_HANDLE_GATEWAY_CHAINS__421614__NOX_COMPUTE_CONTRACT_ADDRESS="0x..."
export NOX_HANDLE_GATEWAY_CHAINS__421614__WALLET_KEY="0x..."
export NOX_HANDLE_GATEWAY_CHAINS__421614__S3__ACCESS_KEY="..."
export NOX_HANDLE_GATEWAY_CHAINS__421614__S3__SECRET_KEY="..."
export NOX_HANDLE_GATEWAY_CHAINS__421614__S3__REGION="eu-west-3"
export NOX_HANDLE_GATEWAY_CHAINS__421614__S3__BUCKET="handles"

# Build and run
cargo run --release
```

> [!IMPORTANT]
> `<CHAIN_ID>` represents the chain ID (421614 for Arbitrum Sepolia) of the target blockchain network where the `NoxCompute` smart contract has been deployed. The Handle Gateway will be able to encrypt and store handles and serve their crypto material for this `NoxCompute` smart contract deployment.

---

## Environment Variables

Configuration is loaded from environment variables with the `NOX_HANDLE_GATEWAY_` prefix. Nested properties use double underscore (`__`) as separator.

The gateway supports multiple chains simultaneously. Repeat the `CHAINS__<CHAIN_ID>__*` block for every chain the gateway should serve.

### Global variables

| Variable | Description | Required | Default |
| -------- | ----------- | -------- | ------- |
| `NOX_HANDLE_GATEWAY_SERVER__HOST` | Bind address | No | `127.0.0.1` |
| `NOX_HANDLE_GATEWAY_SERVER__PORT` | Port | No | `3000` |
| `NOX_HANDLE_GATEWAY_SERVER__CORS_ALLOWED_HEADERS` | Comma-separated list of allowed CORS request headers | No | `content-type,authorization` |
| `NOX_HANDLE_GATEWAY_DEFAULT_CHAIN_ID` | Fallback chain ID used when `POST /v0/secrets` omits `chain_id` | No | `421614` |
| `NOX_HANDLE_GATEWAY_KMS__URL` | KMS endpoint | No | `http://localhost:9000` |
| `NOX_HANDLE_GATEWAY_KMS__SIGNER_ADDRESS` | Expected KMS signer address | No | `0x000...000` |
| `NOX_HANDLE_GATEWAY_RUNNER_ADDRESS` | Ethereum address of the authorised runner | No | `0x000...000` |

### Per-chain variables (`CHAINS__<CHAIN_ID>__*`)

| Variable | Description | Required | Default |
| -------- | ----------- | -------- | ------- |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__NOX_COMPUTE_CONTRACT_ADDRESS` | NoxCompute contract address for this chain | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__RPC_URL` | Ethereum RPC endpoint for this chain | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__WALLET_KEY` | EIP-712 signing key for this chain (hex, with or without `0x` prefix) | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__BUCKET` | S3 bucket name for this chain | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__ACCESS_KEY` | S3 access key | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__SECRET_KEY` | S3 secret key | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__REGION` | S3 region (`eu-west-3` for AWS Paris; any string for MinIO) | **Yes** | — |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__ENDPOINT_URL` | Custom S3/MinIO endpoint. Absent = AWS standard regional endpoints | No | *(none)* |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__TIMEOUT` | S3 operation timeout (seconds) | No | `30` |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__MAX_CONCURRENT_REQUESTS` | Max S3 requests in-flight concurrently | No | `100` |
| `NOX_HANDLE_GATEWAY_CHAINS__<CHAIN_ID>__S3__OBJECT_LOCK_ENABLED` | Set `false` for buckets without Object Lock (e.g. Sepolia) | No | `true` |

For sensitive values, you can use the `_FILE` suffix to load from a file:

```bash
NOX_HANDLE_GATEWAY_CHAINS__421614__S3__ACCESS_KEY_FILE=/run/secrets/s3_access_key
NOX_HANDLE_GATEWAY_CHAINS__421614__S3__SECRET_KEY_FILE=/run/secrets/s3_secret_key
NOX_HANDLE_GATEWAY_CHAINS__421614__WALLET_KEY_FILE=/run/secrets/wallet_key
```

Logging level is controlled via the `RUST_LOG` environment variable:

```bash
RUST_LOG=info    # Default
RUST_LOG=debug   # Verbose logging
```

---

## API Reference

### Service Endpoints

#### `GET /`

Returns basic service information.

**Response:**

```json
{
  "service": "Handle Gateway",
  "timestamp": "2026-02-25T10:30:00.000Z"
}
```

#### `GET /health`

Health check endpoint for monitoring and orchestration.

**Response:**

```json
{
  "status": "ok"
}
```

#### `GET /metrics`

Prometheus metrics endpoint for observability.

**Response:** Prometheus text format metrics.

---

### Handle Endpoints

All handle endpoints accept an optional `?salt=0x<64-hex-char bytes32>` query parameter. When present, the salt is bound into the Handle Gateway EIP-712 response-signing domain, tying the signed response to that specific request. Defaults to `bytes32(0)` when omitted.

The outer `signature` field present on every response is produced under the following domain:

```text
name: "Handle Gateway"
version: "1"
chainId: <configured_chain_id>
salt: <salt query parameter, or bytes32(0)>
```

Note there is no `verifyingContract` in the response domain. Per-endpoint auth domains are documented separately and have a different structure.

Authenticated endpoints require `Authorization: EIP712 <Base64(JSON)>` and enforce a maximum token validity window of 1 hour.

---

#### `POST /v0/secrets`

Encrypts a value and stores it under a freshly generated handle. Returns a packed `HandleProof` signed under the NoxCompute domain for on-chain verification, wrapped in a Handle Gateway outer signature.

**Query Parameters:**

| Parameter | Description | Required |
| --------- | ----------- | -------- |
| `chain_id` | Chain ID to use for this handle. Must correspond to a configured chain. When absent, the gateway falls back to `DEFAULT_CHAIN_ID` and logs a warning. | No |
| `salt` | 32-byte hex value (`0x` + 64 hex chars) bound into the Handle Gateway EIP-712 response-signing domain. Defaults to `bytes32(0)` when omitted. | No |

**Request Body:**

```json
{
  "value": "0x...",
  "solidityType": "uint256",
  "owner": "0x...",
  "applicationContract": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `value` | Hex-encoded value to encrypt. Must match `solidityType` in size. |
| `solidityType` | Solidity type string: `bool`, `address`, `bytes`, `string`, `uint8`-`uint256`, `int8`-`int256`, `bytes1`-`bytes32` |
| `owner` | Ethereum address of the value owner, embedded in the `HandleProof` |
| `applicationContract` | Ethereum address of the requesting application contract, embedded in the `HandleProof` |

**Success Response (200):**

```json
{
  "payload": {
    "handle": "0x...",
    "proof": "0x..."
  },
  "signature": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `payload.handle` | 32-byte handle hex, with `0x` prefix |
| `payload.proof` | 137-byte packed `HandleProof`: owner (20) \|\| app (20) \|\| createdAt BE (32) \|\| sig (65) |
| `signature` | EIP-712 signature of `payload` by the gateway, under the Handle Gateway domain with salt |

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | `chain_id` is not a configured chain; `value` does not match `solidityType`; `salt` is malformed; or incorrect input data are given through the request |
| `409 Conflict` | Handle already exists in S3 |
| `500 Internal Server Error` | Encryption, signing, or S3 error |

**EIP-712 Domain (for `proof`):**

```text
name: "NoxCompute"
version: "1"
chainId: <configured_chain_id>
verifyingContract: <nox_compute_contract>
```

**EIP-712 Message Type (for `proof`):**

```solidity
struct HandleProof {
    bytes32 handle;
    address owner;
    address app;
    uint256 createdAt;
}
```

---

#### `GET /v0/secrets/{handle}`

Returns re-encrypted crypto material for a handle after verifying the caller's identity and ACL. The caller supplies their RSA public key in the authorization token; the gateway delegates to the KMS which RSA-OAEP-encrypts the shared secret for that key.

**Headers:**

| Header | Description |
| ------ | ----------- |
| `Authorization` | `EIP712 <Base64(JSON)>` — base64-encoded JSON containing `payload` and `signature` |

**Authorization JSON:**

```json
{
  "payload": {
    "userAddress": "0x...",
    "encryptionPubKey": "0x3082...",
    "notBefore": 1700000000,
    "expiresAt": 1700003600
  },
  "signature": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `payload.userAddress` | Ethereum address of the caller (EOA or Smart Account) |
| `payload.encryptionPubKey` | RSA public key in SPKI DER format, hex-encoded with `0x` prefix |
| `payload.notBefore` | Unix timestamp before which the token is not valid |
| `payload.expiresAt` | Unix timestamp after which the token is expired. Maximum window: 1 hour |
| `signature` | EIP-712 signature of `payload` by `userAddress` |

**Success Response (200):**

```json
{
  "payload": {
    "handle": "0x...",
    "ciphertext": "0x...",
    "encryptedSharedSecret": "0x...",
    "iv": "0x..."
  },
  "signature": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `payload.handle` | 32-byte handle hex |
| `payload.ciphertext` | AES-256-GCM ciphertext, hex-encoded |
| `payload.encryptedSharedSecret` | RSA-OAEP-encrypted X-coordinate of the ECDH shared secret, hex-encoded |
| `payload.iv` | AES-GCM nonce (12 bytes), hex-encoded |
| `signature` | EIP-712 signature of `payload` by the gateway, under the Handle Gateway domain with salt |

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | Handle is not valid 32-byte hex; handle encodes an unconfigured chain ID; or `salt` is malformed |
| `401 Unauthorized` | Authorization token missing, malformed, expired, or wrongly signed |
| `403 Forbidden` | Caller does not have viewer access to this handle |
| `404 Not Found` | Handle does not exist in S3 |
| `500 Internal Server Error` | Unexpected S3 or KMS error |
| `503 Service Unavailable` | RPC or KMS unreachable |

**EIP-712 Domain (for authorization `signature`):**

```text
name: "Handle Gateway"
version: "1"
chainId: <configured_chain_id>
verifyingContract: <nox_compute_contract>
```

**EIP-712 Message Type (for authorization `signature`):**

```solidity
struct DataAccessAuthorization {
    address userAddress;
    string encryptionPubKey;
    uint256 notBefore;
    uint256 expiresAt;
}
```

---

#### `GET /v0/compute/operands`

Returns re-encrypted crypto material for a batch of operand handles. Intended for the [nox-runner](https://github.com/iExec-Nox/nox-runner) prior to performing a computation. Verifies that the request originates from the configured runner address.

**Headers:**

| Header | Description |
| ------ | ----------- |
| `Authorization` | `EIP712 <Base64(JSON)>` — base64-encoded JSON containing `payload` and `signature` |

**Authorization JSON:**

```json
{
  "payload": {
    "chainId": 421614,
    "blockNumber": 12345678,
    "caller": "0x...",
    "transactionHash": "0x...",
    "operands": ["0x...", "0x..."],
    "rsaPublicKey": "0x3082..."
  },
  "signature": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `payload.chainId` | Chain ID of the computation |
| `payload.blockNumber` | Block number of the on-chain transaction that triggered the computation |
| `payload.caller` | Ethereum address of the runner |
| `payload.transactionHash` | On-chain transaction hash that triggered the computation |
| `payload.operands` | List of handle hex strings to retrieve |
| `payload.rsaPublicKey` | RSA public key in SPKI DER format, hex-encoded with `0x` prefix |
| `signature` | EIP-712 signature of `payload` by the runner address |

**Success Response (200):**

```json
{
  "payload": {
    "operands": [
      {
        "handle": "0x...",
        "ciphertext": "0x...",
        "encryptedSharedSecret": "0x...",
        "iv": "0x..."
      }
    ]
  },
  "signature": "0x..."
}
```

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | `chainId` in the authorization token does not correspond to a configured chain; one or more operand handles not found in S3; or `salt` is malformed |
| `401 Unauthorized` | Authorization token missing, malformed, or not signed by the configured runner |
| `500 Internal Server Error` | S3 read error, or KMS delegation failed for one or more operands |

**EIP-712 Domain (for authorization `signature`):**

```text
name: "Handle Gateway"
version: "1"
chainId: <configured_chain_id>
```

**EIP-712 Message Type (for authorization `signature`):**

```solidity
struct OperandAccessAuthorization {
    uint256 chainId;
    uint256 blockNumber;
    address caller;
    string transactionHash;
    string[] operands;
    string rsaPublicKey;
}
```

---

#### `POST /v0/compute/results`

Stores computation result handles produced by the [nox-runner](https://github.com/iExec-Nox/nox-runner). Verifies that the request originates from the configured runner address. Returns a summary of created, unchanged, and conflicted handles.

**Headers:**

| Header | Description |
| ------ | ----------- |
| `Authorization` | `EIP712 <Base64(JSON)>` — base64-encoded JSON containing `payload` and `signature` |

**Authorization JSON:**

```json
{
  "payload": {
    "chainId": 421614,
    "blockNumber": 12345678,
    "caller": "0x...",
    "transactionHash": "0x..."
  },
  "signature": "0x..."
}
```

**Request Body:**

```json
[
  {
    "handle": "0x...",
    "handleValueTag": "0x...",
    "ciphertext": "0x...",
    "publicKey": "0x...",
    "nonce": "0x..."
  }
]
```

| Field | Description |
| ----- | ----------- |
| `handle` | 32-byte result handle hex |
| `handleValueTag` | `keccak256(handle \|\| plaintext)` — used to detect duplicate publishes with differing ciphertexts |
| `ciphertext` | AES-256-GCM ciphertext of the result, hex-encoded |
| `publicKey` | Ephemeral EC public key used during encryption, hex-encoded |
| `nonce` | AES-GCM nonce (12 bytes), hex-encoded |

**Success Response (200):**

```json
{
  "payload": {
    "message": "On the W handles submitted to publishing, X were successfully created, Y were unchanged and Z conflicted"
  },
  "signature": "0x..."
}
```

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | `chainId` in the authorization token does not correspond to a configured chain; or `salt` is malformed |
| `401 Unauthorized` | Authorization token missing, malformed, or not signed by the configured runner |
| `500 Internal Server Error` | S3 write failure |

**EIP-712 Domain (for authorization `signature`):**

```text
name: "Handle Gateway"
version: "1"
chainId: <configured_chain_id>
```

**EIP-712 Message Type (for authorization `signature`):**

```solidity
struct ResultPublishingAuthorization {
    uint256 chainId;
    uint256 blockNumber;
    address caller;
    string transactionHash;
}
```

---

#### `POST /v0/public/handles/status`

Reports which handles from a list are already stored in S3. Performs HEAD checks only; never returns encrypted payloads.

The chain is inferred from the first handle in the batch. All handles must belong to the same chain; mixed-chain batches are rejected with `400`.

**Request Body:**

```json
{
  "handles": ["0x...", "0x..."]
}
```

**Success Response (200):**

```json
{
  "payload": {
    "statuses": [
      { "handle": "0x...", "resolved": true },
      { "handle": "0x...", "resolved": false }
    ]
  },
  "signature": "0x..."
}
```

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | Empty handle batch; any handle is not valid 32-byte hex; handles span more than one chain ID; or `salt` is malformed |
| `500 Internal Server Error` | Unexpected S3 error |

---

#### `GET /v0/public/{handle}`

Returns a verifiable decryption proof for a publicly decryptable handle. The gateway decrypts the value locally and packs the plaintext together with an EIP-712 `DecryptionProof` signature.

**Success Response (200):**

```json
{
  "payload": {
    "decryptionProof": "0x..."
  },
  "signature": "0x..."
}
```

| Field | Description |
| ----- | ----------- |
| `payload.decryptionProof` | Packed bytes: sig (65 bytes, EIP-712 `DecryptionProof` under NoxCompute domain) \|\| plaintext (N bytes) |
| `signature` | EIP-712 signature of `payload` by the gateway, under the Handle Gateway domain with salt |

**Error Responses:**

| Status | Description |
| ------ | ----------- |
| `400 Bad Request` | Handle is not valid 32-byte hex; handle encodes an unknown solidity type or unconfigured chain ID; or `salt` is malformed |
| `403 Forbidden` | Handle is not marked as publicly decryptable on-chain |
| `404 Not Found` | Handle does not exist in S3 |
| `500 Internal Server Error` | Crypto or signing failure |
| `503 Service Unavailable` | RPC or KMS unreachable |

**EIP-712 Domain (for `decryptionProof` signature):**

```text
name: "NoxCompute"
version: "1"
chainId: <configured_chain_id>
verifyingContract: <nox_compute_contract>
```

**EIP-712 Message Type (for `decryptionProof` signature):**

```solidity
struct DecryptionProof {
    bytes32 handle;
    bytes decryptedResult;
}
```

---

## Related Repositories

| Repository | Role |
| ---------- | ---- |
| [nox-kms](https://github.com/iExec-Nox/nox-kms) | Key Management Service — performs ECDH/RSA delegation operations for authorized flows |
| [nox-runner](https://github.com/iExec-Nox/nox-runner) | Off-chain computation runner — fetches operands and publishes results via this gateway |

---

## License

The Nox Protocol source code is released under the Business Source License 1.1 (BUSL-1.1).

The license will automatically convert to the MIT License under the conditions described in the [LICENSE](./LICENSE) file.

The full text of the MIT License is provided in the [LICENSE-MIT](./LICENSE-MIT) file.
