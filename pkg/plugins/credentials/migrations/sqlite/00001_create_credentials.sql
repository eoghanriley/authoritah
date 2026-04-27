-- +goose Up
CREATE TABLE IF NOT EXISTS user_credentials (
    user_id    TEXT     PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash       TEXT     NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- +goose Down
DROP TABLE IF EXISTS user_credentials;