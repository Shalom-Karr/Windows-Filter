-- skfilter SQLite schema. Idempotent — applied on every Open().

CREATE TABLE IF NOT EXISTS settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash       BLOB,         -- NULL when first-run not done
    session_signing_key BLOB NOT NULL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    domain           TEXT NOT NULL UNIQUE,
    ips_csv          TEXT NOT NULL DEFAULT '',
    last_resolved_at DATETIME,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor        TEXT,
    action       TEXT NOT NULL,
    payload_json TEXT
);

-- Seed an empty settings row + generate a signing key on first open.
INSERT OR IGNORE INTO settings (id, session_signing_key) VALUES (1, randomblob(32));
