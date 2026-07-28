-- Таблица пользователей и их криптографических профилей.
CREATE TABLE IF NOT EXISTS users (
    id              UUID        PRIMARY KEY,
    login           VARCHAR(200) NOT NULL UNIQUE,
    auth_verifier   BYTEA       NOT NULL,
    kdf_salt        BYTEA       NOT NULL,
    kdf_params      JSONB       NOT NULL,
    wrapped_data_key BYTEA      NOT NULL,
    profile_version INT         NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Таблица зашифрованных записей хранилища.
CREATE TABLE IF NOT EXISTS records (
    id              UUID        PRIMARY KEY,
    owner_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            SMALLINT    NOT NULL,
    encrypted_meta  BYTEA,
    meta_nonce      BYTEA,
    ciphertext      BYTEA       NOT NULL,
    nonce           BYTEA       NOT NULL,
    version         BIGINT      NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted         BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_records_owner_version ON records (owner_id, version);

-- Таблица ключей идемпотентности для Push-операций синхронизации.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    id          BIGSERIAL   PRIMARY KEY,
    owner_id    UUID        NOT NULL,
    key         VARCHAR(200) NOT NULL,
    result      BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_id, key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys (created_at);

-- Таблица refresh-токенов с поддержкой ротации и детекта кражи.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);
