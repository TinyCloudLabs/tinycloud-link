CREATE TABLE IF NOT EXISTS names (
  name TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  lan_ips JSONB NOT NULL,
  sequence BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  stored_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_names_subject ON names(subject);
