-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id         TEXT        PRIMARY KEY,
    email      TEXT        NOT NULL UNIQUE,
    name       TEXT        NOT NULL DEFAULT '',
    avatar_url TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    meta       JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_token_idx   ON sessions(token);

-- +goose Down
DROP INDEX IF EXISTS sessions_token_idx;
DROP INDEX IF EXISTS sessions_user_id_idx;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
