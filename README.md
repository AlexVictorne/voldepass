# Voldepass

Zero-knowledge password manager: REST server (Go, chi, PostgreSQL) + CLI/TUI client
with client-side end-to-end encryption. The server never sees plaintext passwords,
payloads, or the encryption key that protects them.

## Architecture

Hexagonal (ports & adapters). `internal/domain` holds framework-free entities; each
side (`server`, `client`) layers config → storage/transport → auth → service →
transport/CLI on top of it.

```
cmd/
  server/          entrypoint: config → app.New → HTTP server + background jobs
  client/          entrypoint: cobra root command (CLI + TUI)
internal/
  domain/          entities, errors, Sync API DTOs — no internal imports
  server/
    config/        layered config (defaults → JSON → env → flags)
    storage/
      postgres/    pgx/v5 repositories + embedded golang-migrate migrations
      inmem/       in-memory repositories (used in server/service unit tests)
    auth/          JWT, challenge store, refresh token rotation
    service/       AuthService, VaultService, SyncService (business logic)
    rest/          chi router, handlers, middleware
    app/           wiring: config → storage → services → router, graceful shutdown
  client/
    config/        layered config (client-side)
    crypto/        Argon2id, AES-256-GCM, HMAC auth, TOTP, export bundle, password tools
    transport/     retryablehttp client: two-phase login, auto-refresh, TLS pinning
    storage/       in-memory + encrypted-file local storage (atomic writes)
    service/       AuthFlow, VaultManager, Syncer, Session (client orchestration)
    cli/           cobra commands
    tui/           bubbletea screens (login/list/detail)
test/
  integration/     -tags=integration, real PostgreSQL via testcontainers
  e2e/             -tags=e2e, binary build + smoke checks
```

## Cryptographic model

Master password never leaves the client and never touches the wire.

1. **Key derivation (Argon2id).** From `(masterPassword, kdfSalt)` the client derives
   two independent keys via domain-separated Argon2id calls: `authKey` (used only for
   authentication) and `encKey` (used only to wrap/unwrap the data key).
2. **Key wrapping.** A random 256-bit `dataKey` encrypts every vault record
   (AES-256-GCM, random nonce per record). `dataKey` is wrapped with `encKey`
   (`wrappedDataKey = AES-GCM(encKey, dataKey)`) and stored on the server as part of
   the user's profile — this is what lets a second device unlock the vault after
   logging in, without ever sending `dataKey` or the password itself.
3. **Challenge-response authentication.** Login is two HTTP calls:
   `POST /login/challenge {login}` → server returns a one-time `serverNonce` (with TTL,
   consumed on first use) plus the profile (`kdfSalt`, `kdfParams`, `wrappedDataKey`).
   The client computes `authMsg = HMAC-SHA256(authKey, serverNonce)` and sends
   `POST /login {login, authMsg}`. The raw password and `authKey` never cross the wire;
   a captured `authMsg` cannot be replayed because the nonce is single-use.
4. **Session tokens.** Successful login returns a short-lived JWT access token (~15m)
   and an opaque refresh token (~30d, rotated on every use; reuse of an already-rotated
   refresh token revokes the whole token family — theft detection).

## Sync protocol

`GET /api/v1/sync?since=<version>` returns all records changed after `version`.
`POST /api/v1/sync` (header `Idempotency-Key`) pushes a batch of locally changed
records; each carries `base_version` for optimistic locking. The server responds per
record with `applied` (new version) or `conflict` (returns the current server record).

The client `Syncer` (`internal/client/service/syncer.go`) implements:

- **Pull → merge.** Non-dirty local records fast-forward to the server version.
  A local record that is both dirty and touched remotely is preserved as a
  **conflict copy** (new ID) while the server version becomes canonical — no data is
  silently discarded.
- **Push idempotency.** The idempotency key for a push batch is persisted to local
  storage *before* the request is sent, so a retry after a crash reuses the same key
  and the server returns the cached result instead of double-applying.
- **Chunking.** Large batches are split (configurable, default 100 records/request).
- **Convergence loop.** Pull → push repeats (bounded, default 5 iterations) until no
  conflicts remain or the bound is hit; any records still dirty afterward are returned
  to the caller for manual resolution.

## Building

```sh
make build            # both binaries into ./bin
make build-server
make build-client
```

Cross-compilation matrix (linux/darwin/windows, amd64):

```sh
make build-all-platforms
```

Version and build date are injected via `-ldflags` and printed by
`voldepass-server` on startup and `voldepass-client version`.

## Running the server

```sh
make up                     # docker compose: PostgreSQL 16
export VOLDEPASS_JWT_SECRET=$(openssl rand -hex 32)
./bin/voldepass-server
```

Configuration is layered `defaults → JSON file (-config) → env (VOLDEPASS_*) → flags`,
identically on client and server. See `internal/server/config/config.go` and
`internal/client/config/config.go` for the full field list.

## Using the CLI

```sh
export VOLDEPASS_LOGIN=alice
./bin/voldepass-client register            # prompts for master password
./bin/voldepass-client add --type text --content "note" --meta "personal"
./bin/voldepass-client list
./bin/voldepass-client sync
./bin/voldepass-client otp get --id <record-id>
./bin/voldepass-client export --output backup.gkenc
./bin/voldepass-client import --input backup.gkenc
./bin/voldepass-client generate --length 24
./bin/voldepass-client tui                  # interactive terminal UI
```

Every vault-touching command re-authenticates via challenge-response and derives
`dataKey` fresh for that invocation; nothing sensitive is cached across CLI processes
except the encrypted local file.

## Testing

Five levels, matching the pyramid from fast/cheap to slow/expensive:

```sh
make lint              # golangci-lint + go vet + govulncheck + go mod verify
make test              # unit + functional, -race, coverage ≥70% gate
make test-integration  # real PostgreSQL via testcontainers (requires Docker)
make test-e2e          # binary build + smoke checks
make test-all          # everything above
```

Functional-level tests (services, REST handlers, CLI commands) run against
full in-memory stacks — not mocks — so `AuthService`, `VaultService`, `SyncService`,
the chi router, and the CLI's cobra commands are exercised end-to-end without a real
database or network.

## Limitations of the zero-knowledge model

These are accepted trade-offs of the v1 design, not oversights:

- **No password recovery.** The server cannot recover or reset the master password.
  Losing it means losing the vault (no server-side escrow of `dataKey` exists by
  design). `export`/`import` bundles are the only backup mechanism.
- **Metadata leakage.** The server cannot read record content, but it does see
  ciphertext size, record type, and modification timestamps/frequency — usage
  pattern analysis is possible from that. Per-record `meta` is separately encrypted
  but its existence and size are still visible.
- **Server stores the pieces needed for challenge-response and multi-device sync**
  (`authKey` verifier, `wrappedDataKey`, `kdfSalt`). This is a deliberate trade-off
  (see architecture doc in the original design notes) to support login from a second
  device without any out-of-band exchange. A database leak enables offline brute-force
  against the master password; Argon2id parameters are the primary mitigation.
  A verifier-less scheme (SRP) that removes this trade-off entirely is out of scope
  for v1.
- **Replay protection, not leak protection.** Challenge-response stops a captured
  `authMsg` from being reused, but it does not protect against a compromised database
  being brute-forced offline.
- **Key material lives in process memory for the session.** `authKey`/`encKey`/`dataKey`
  are held in memory only as long as needed and are explicitly zeroed on graceful
  shutdown (`Session.Close`), but Go's garbage collector gives no guarantee against
  copies elsewhere on the heap/stack; defending against memory-dump attacks is out of
  scope.
- **Trust in the client binary is required.** The security model holds only as long as
  the client binary itself has not been tampered with — supply-chain integrity of the
  client is outside this project's scope.

## Roadmap (not in v1)

- Master password change (architecture already supports it: re-wrap `dataKey`,
  update the profile — no need to re-encrypt existing records).
- Cursor-based pagination for `GET /sync` (currently returns the full delta).
- SRP-based authentication to remove the `authKey` verifier from server storage.
- Audit log of security-relevant events.
- Multiple local profiles per client installation.
- Local proxy mode for browser/launcher integrations.
