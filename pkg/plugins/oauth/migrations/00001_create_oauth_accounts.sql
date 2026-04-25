-- +goose Up
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT        NOT NULL,
    provider_id TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(provider, provider_id)
);

CREATE INDEX IF NOT EXISTS oauth_accounts_user_id_idx ON oauth_accounts(user_id);

-- +goose Down
DROP INDEX IF EXISTS oauth_accounts_user_id_idx;
DROP TABLE IF EXISTS oauth_accounts;
