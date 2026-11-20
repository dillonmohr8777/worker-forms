-- forms Worker D1 schema. Apply: wrangler d1 execute forms --remote --file schema.sql
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site TEXT NOT NULL,
  form TEXT NOT NULL DEFAULT '',
  page TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL,
  ip_hash TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT '',
  spam INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  notified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sub_rate ON submissions (ip_hash, site, created_at);
CREATE INDEX IF NOT EXISTS idx_sub_notify ON submissions (notified_at, spam);
