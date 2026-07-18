-- Enable foreign key support in SQLite (run this on every database connection)
PRAGMA foreign_keys = ON;

-- 1. KEYS TABLE
-- Stores private and public keys, identifying their type and associated metadata.
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                -- User-friendly alias/name for the key pair
    algorithm TEXT NOT NULL,                  -- "rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519"
    private_key_pem TEXT NOT NULL,            -- PEM-encoded private key
    public_key_pem TEXT NOT NULL,             -- PEM-encoded public key
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. CERTIFICATES TABLE
-- Stores x509 certificate data, links back to its signing key, and tracks revocation status.
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number TEXT NOT NULL UNIQUE,       -- Hex or decimal representation of the Serial Number
    common_name TEXT NOT NULL,                -- Subject Common Name (CN)
    type TEXT NOT NULL,                       -- 'CA', 'INTERMEDIATE', 'LEAF'

    -- Foreign Key to the key pair used by this certificate
    key_name TEXT NOT NULL,

    -- Self-referencing Foreign Key to track the issuer (NULL if self-signed Root CA)
    issuer_certificate_serial_number TEXT,

    -- Validity dates
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,

    -- Revocation status (Critical for generating CRLs)
    is_revoked INTEGER DEFAULT 0,             -- Boolean (0 = active, 1 = revoked)
    revocation_reason INTEGER,                -- RFC 5280 CRLReason code (e.g., 1 = keyCompromise, 4 = superseded)
    revocation_time DATETIME,                 -- Timestamp of when it was revoked

    -- PEM Encoded Certificate Data
    certificate_pem TEXT NOT NULL,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    FOREIGN KEY (key_name) REFERENCES keys(name) ON DELETE RESTRICT,
    FOREIGN KEY (issuer_certificate_serial_number) REFERENCES certificates(serial_number) ON DELETE SET NULL,
    CHECK (type IN ('CA', 'INTERMEDIATE', 'LEAF')),
    CHECK (is_revoked IN (0, 1))
);

-- Indexes for performance (especially useful when your database grows)
CREATE INDEX IF NOT EXISTS idx_certs_serial ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certificates(is_revoked);
