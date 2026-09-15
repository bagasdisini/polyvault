# PolyVault

Self-hosted secrets manager written in Go. Uses Shamir's Secret Sharing to split the master key into N shares — require M to reconstruct. No single person can unseal the vault alone. Inspired by HashiCorp Vault's API design and architecture.

## Features

- **Shamir's Secret Sharing** — Master key split into N shares; M-of-N threshold required to unseal. GF(256) arithmetic, Lagrange interpolation.
- **AES-256-GCM encryption** — All secrets encrypted at rest. Random nonce per encryption, no reuse.
- **Transit Encryption** — Encrypt/decrypt data without exposing raw keys (encryption-as-a-service). Supports key rotation and HMAC.
- **Persistence** — Secrets and vault state survive server restarts. File-based atomic storage.
- **HMAC-chained Audit Log** — Every operation logged with chained HMAC-SHA256. Tamper detection: modify or delete any entry and chain breaks.
- **Token Authentication** — Role-based access control policies (read, write, delete, list, admin, transit) implemented in the auth package.
- **HTTP API** — RESTful JSON API for all operations.
- **CLI Client** — Command-line interface that talks to the API.

## Quick Start

### Build

```bash
make build
```

Or manually:

```bash
go build -o polyvault .
```

### Configure

The `init` and `server` command reads `config.json`:

```bash
cp config_example.json config.json
```

### Initialize Vault

```bash
./polyvault init
```

Output:

```
Vault initialized successfully!

Unseal Shares (distribute these to trusted operators):
Share 1: a1b2c3d4e5f6...
Share 2: f6e5d4c3b2a1...
...

IMPORTANT: Store these shares securely!
You will need 3 of 5 shares to unseal the vault.
```

Distribute shares to trusted operators. Each share is a hex-encoded byte slice.

### Start Server

```bash
./polyvault server
```

Server starts on `:8200` by default. Use `--addr` to override:

```bash
./polyvault server --addr :8201
```

Use `--config` to specify a different config file:

```bash
./polyvault server --config /path/to/config.json
```

### Unseal Vault

After the server starts, the vault is sealed. Submit unseal shares via CLI:

```bash
./polyvault unseal <share1_hex> [share2_hex] [share3_hex]...
```

Or via the API one at a time:

```bash
curl -X PUT http://localhost:8200/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"share": "a1b2c3d4e5f6..."}'
```

After the threshold (3 by default) valid shares are submitted, the vault unseals.

### Store Secrets

```bash
curl -X PUT http://localhost:8200/v1/secret/db-password \
  -H "Content-Type: application/json" \
  -d '{"value": "super-secret-password"}'
```

Or with CLI:

```bash
./polyvault put db-password "super-secret-password"
```

### Retrieve Secrets

```bash
curl http://localhost:8200/v1/secret/db-password
```

Or:

```bash
./polyvault get db-password
```

Response:

```json
{
  "key": "db-password",
  "value": "super-secret-password"
}
```

### List Secrets

```bash
curl http://localhost:8200/v1/secret
```

Or:

```bash
./polyvault list
```

Response:

```json
{
  "keys": ["db-password", "api-key", "tls-cert"]
}
```

### Delete Secrets

```bash
curl -X DELETE http://localhost:8200/v1/secret/db-password
```

Or:

```bash
./polyvault delete db-password
```

### Seal Vault

```bash
curl -X PUT http://localhost:8200/v1/sys/seal
```

The vault seals immediately. The master key is zeroed from memory. You must unseal again with shares to access secrets.

### Check Status

```bash
curl http://localhost:8200/v1/sys/seal-status
```

Or:

```bash
./polyvault status
```

Response:

```json
{
  "sealed": false,
  "state": "unsealed",
  "initialized": true
}
```

## Transit Encryption

The transit engine lets services encrypt/decrypt data without seeing encryption keys. Vault manages the keys.

### Create Transit Key

```bash
curl -X POST http://localhost:8200/v1/transit/keys/my-key \
  -H "Content-Type: application/json" \
  -d '{"type": "aes256-gcm96"}'
```

If the type is omitted, `aes256-gcm96` is used by default.

### Encrypt

```bash
curl -X POST http://localhost:8200/v1/transit/encrypt/my-key \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "sensitive data"}'
```

Response:

```json
{
  "ciphertext": "AVyZ/L94/VkSguvuM7bm..."
}
```

### Decrypt

```bash
curl -X POST http://localhost:8200/v1/transit/decrypt/my-key \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "AVyZ/L94/VkSguvuM7bm..."}'
```

Response:

```json
{
  "plaintext": "sensitive data"
}
```

## API Reference

### System Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/sys/health` | Health check. Returns `{"status": "ok"}` |
| `GET` | `/v1/sys/seal-status` | Vault status (sealed/unsealed, initialized) |
| `POST` | `/v1/sys/init` | Initialize vault. Returns Shamir shares |
| `PUT` | `/v1/sys/unseal` | Submit one unseal share |
| `PUT` | `/v1/sys/seal` | Seal the vault |

### Secrets Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/secret` | List all secret keys |
| `GET` | `/v1/secret/{key}` | Get secret value |
| `PUT` | `/v1/secret/{key}` | Store or update secret |
| `DELETE` | `/v1/secret/{key}` | Delete secret |

### Transit Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/transit/keys/{key}` | Create encryption key |
| `POST` | `/v1/transit/encrypt/{key}` | Encrypt plaintext |
| `POST` | `/v1/transit/decrypt/{key}` | Decrypt ciphertext |

### Common Response Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad request (missing fields, invalid format) |
| `404` | Secret not found |
| `409` | Conflict (vault already initialized, key already exists) |
| `503` | Vault sealed — must unseal first |

### Headers

All responses include:
- `X-Request-ID` — unique request identifier (generated if not provided)
- `Access-Control-Allow-Origin: *` — CORS enabled

## CLI Reference

```
polyvault <command> [arguments]

Commands:
  server [--addr :8200] [--config config.json]
                      Start the vault server
  init                Initialize a new vault (uses config.json)
  unseal <shares...>  Unseal the vault with shares
  status              Show vault status
  put <key> <value>   Store a secret
  get <key>           Retrieve a secret
  delete <key>        Delete a secret
  list                List all secrets
  help                Show this help
```

CLI commands (`put`, `get`, `delete`, `list`, `status`) require a running server. They make HTTP requests to `http://localhost:8200`.

## Configuration

```json
{
  "server": {
    "addr": ":8200",
    "read_timeout": "10s",
    "write_timeout": "10s",
    "idle_timeout": "30s"
  },
  "vault": {
    "threshold": 3,
    "total": 5,
    "data_dir": "./vault-data"
  },
  "audit": {
    "enabled": true,
    "file": "./vault-data/audit.log"
  },
  "auth": {
    "enabled": true,
    "token_ttl": "24h"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `server.addr` | `:8200` | Listen address |
| `server.read_timeout` | `10s` | HTTP read timeout |
| `server.write_timeout` | `10s` | HTTP write timeout |
| `server.idle_timeout` | `30s` | HTTP idle timeout |
| `vault.threshold` | `3` | Minimum shares to unseal |
| `vault.total` | `5` | Total shares generated |
| `vault.data_dir` | `./vault-data` | Data directory |
| `storage.type` | `file` | Storage backend (`file` or `sqlite`) |
| `storage.dir` | `./vault-data/storage` | Storage directory |
| `audit.enabled` | `true` | Enable audit logging |
| `audit.file` | `./vault-data/audit.log` | Audit log path |
| `audit.key` | `""` | HMAC key for audit log verification |
| `auth.enabled` | `true` | Enable token authentication |
| `auth.token_ttl` | `24h` | Token lifetime |
| `auth.admin_token` | `""` | Optional pre-configured admin token |

## How Shamir's Secret Sharing Works

1. **Init**: Generate a 32-byte master key with `crypto/rand`. Split it into N shares using polynomial interpolation over GF(256). Each byte of the secret is independently shared.

2. **Unseal**: Collect M shares. Reconstruct the master key using Lagrange interpolation. Verify against the stored SHA-256 hash.

3. **Seal**: Zero the master key from memory. The vault returns to the sealed state.

4. **Encrypt/Decrypt**: The master key is used for AES-256-GCM. Each encryption generates a random nonce. Format: `nonce || ciphertext || tag`.

Security properties:
- Fewer than M shares reveal zero information about the secret.
- Each share is random-looking — cannot tell if it is valid without other shares.
- The master key is never stored in plaintext — only a SHA-256 hash is persisted.

## Audit Log

Every operation is logged with HMAC-chained entries:

```json
{
  "id": 1,
  "timestamp": "2026-08-26T12:00:00Z",
  "event_type": "secret.write",
  "actor": "api",
  "resource": "db-password",
  "action": "put",
  "success": true,
  "previous": "0000000000000000000000000000000000000000000000000000000000000000",
  "hmac": "a1b2c3d4..."
}
```

Each entry's HMAC includes the previous entry's HMAC. Deleting or modifying any entry breaks the chain. Verification:

```go
entries := parseAuditLog("vault-data/audit.log")
err := audit.Verify(key, entries)
// err != nil means tampering detected
```

## Development

### Run Tests

```bash
make test
```

### Run Short Tests

```bash
make test-short
```

### Run Benchmarks

```bash
make bench
```

### Test Coverage

```bash
make test-coverage
```

### Lint

```bash
make lint
```

### Tidy Dependencies

```bash
make tidy
```

### Clean Build Artifacts

```bash
make clean
```

## Security Considerations

- Master key generated from `crypto/rand` (CSPRNG).
- Secrets encrypted with AES-256-GCM (authenticated encryption).
- Random nonce per encryption — no nonce reuse.
- Master key zeroed on seal.
- Audit log HMAC-chained for tamper detection.
- File storage uses atomic writes (write-to-temp + rename).
- Vault state is persisted — secrets survive restarts.
- Shamir shares are never stored — must be provided by operators.

## Limitations

- Single-node only — no clustering or replication.
- File-based storage — not suitable for high-throughput workloads.
- Token authentication is implemented in the auth package but not yet enforced by the HTTP API — endpoints are currently open.
- No TLS — must be terminated by a reverse proxy.
- No dynamic secrets (short-lived DB credentials).
- No JWT/mTLS/AppRole auth backends.

## License

This project is licensed under the [MIT License](LICENSE).
