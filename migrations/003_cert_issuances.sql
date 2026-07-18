CREATE TABLE IF NOT EXISTS cert_issuances (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cert_issuances_name_issued_at
  ON cert_issuances(name, issued_at);
