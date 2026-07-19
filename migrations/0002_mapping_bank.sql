ALTER TABLE login_bindings
ADD COLUMN bank_id TEXT NOT NULL DEFAULT 'legacy';
