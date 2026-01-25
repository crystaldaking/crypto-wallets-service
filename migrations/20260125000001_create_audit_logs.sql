CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action VARCHAR(50) NOT NULL,
    wallet_id UUID,
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_wallet_id ON audit_logs(wallet_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
