CREATE TABLE IF NOT EXISTS acme_account (
  id TEXT PRIMARY KEY DEFAULT 'default',
  account_key_pem TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
