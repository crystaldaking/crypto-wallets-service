-- Add indexes for performance optimization
-- Created: 2026-02-21

-- Index for looking up addresses by wallet_id (common query pattern)
CREATE INDEX IF NOT EXISTS idx_derived_addresses_wallet_id 
ON derived_addresses(wallet_id);

-- Index for looking up addresses by address value (e.g., when resolving address to wallet)
CREATE INDEX IF NOT EXISTS idx_derived_addresses_address 
ON derived_addresses(address);

-- Composite index for common lookup pattern: wallet + network + index
CREATE INDEX IF NOT EXISTS idx_derived_addresses_wallet_network_index 
ON derived_addresses(wallet_id, network, address_index);

-- Index for audit logs by wallet_id (for wallet history queries)
CREATE INDEX IF NOT EXISTS idx_audit_logs_wallet_id 
ON audit_logs(wallet_id);

-- Index for audit logs by timestamp (for time-range queries)
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at 
ON audit_logs(created_at DESC);

-- Foreign key constraint for audit_logs (if not already present)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'fk_audit_logs_wallet'
    ) THEN
        ALTER TABLE audit_logs 
        ADD CONSTRAINT fk_audit_logs_wallet 
        FOREIGN KEY (wallet_id) REFERENCES master_wallets(id)
        ON DELETE SET NULL;
    END IF;
END $$;
