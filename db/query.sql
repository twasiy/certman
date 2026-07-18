-- name: CreateKeyPair :one
INSERT INTO keys (
    name,
    algorithm,
    private_key_pem,
    public_key_pem
) VALUES (
    ?, ?, ?, ?
)
RETURNING *;

-- name: CreateCertificate :one
INSERT INTO certificates (
    serial_number,
    common_name,
    type,
    key_name,
    issuer_certificate_serial_number,
    not_before,
    not_after,
    certificate_pem
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: TotalCerts :one
SELECT COUNT(*) AS total_count FROM certificates;

-- name: TotalKeys :one
SELECT COUNT(*) AS total_keys FROM keys;

-- name: ListCertificates :many
SELECT serial_number, common_name FROM certificates LIMIT ? OFFSET ?;

-- name: ListKeys :many
SELECT name FROM keys LIMIT ? OFFSET ?;


-- name: GetCertBySN :one
SELECT * FROM certificates WHERE serial_number = ?;

-- name: GetCertByCN :one
SELECT * FROM certificates WHERE common_name = ?;

-- name: GetKeyByName :one
SELECT * FROM keys WHERE name = ?;
