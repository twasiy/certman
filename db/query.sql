-- name: CreateKeyPair :one
INSERT INTO keys (
    name,
    algorithm,
    private_key_pem,
    public_key_pem
) VALUES (
    sqlc.arg('name'),
    sqlc.arg('algorithm'),
    sqlc.arg('private_key_pem'),
    sqlc.arg('public_key_pem')
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
    sqlc.arg('serial_number'),
    sqlc.arg('common_name'),
    sqlc.arg('type'),
    sqlc.arg('key_name'),
    sqlc.arg('issuer_certificate_serial_number'),
    sqlc.arg('not_before'),
    sqlc.arg('not_after'),
    sqlc.arg('certificate_pem')
)
RETURNING *;

-- name: TotalCertificates :one
SELECT COUNT(*) AS total_count FROM certificates;

-- name: TotalKeys :one
SELECT COUNT(*) AS total_keys FROM keys;

-- name: ListCertificates :many
SELECT serial_number, common_name
FROM certificates
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListKeys :many
SELECT name
FROM keys
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: GetCertificateBySN :one
SELECT * FROM certificates WHERE serial_number = sqlc.arg('serial_number');

-- name: GetCertificateByCN :one
SELECT * FROM certificates WHERE common_name = sqlc.arg('common_name');

-- name: GetKeyByName :one
SELECT * FROM keys WHERE name = sqlc.arg('name');

-- name: UpdateCertificate :one
UPDATE certificates
SET
  common_name = COALESCE(sqlc.narg('common_name'), common_name),
  type = COALESCE(sqlc.narg('type'), type),
  key_name = COALESCE(sqlc.narg('key_name'), key_name),
  issuer_certificate_serial_number = COALESCE(sqlc.narg('issuer_certificate_serial_number'), issuer_certificate_serial_number),
  not_before = COALESCE(sqlc.narg('not_before'), not_before),
  not_after = COALESCE(sqlc.narg('not_after'), not_after),
  certificate_pem = COALESCE(sqlc.narg('certificate_pem'), certificate_pem)
WHERE serial_number = sqlc.arg('serial_number')
RETURNING *;


-- name: RevokeCertificate :one
UPDATE certificates
SET
    is_revoked = COALESCE(sqlc.arg('is_revoked'), is_revoked),
    revocation_reason = COALESCE(sqlc.arg('revocation_reason'), revocation_reason),
    revocation_time = COALESCE(sqlc.arg('revocation_time'), revocation_time)
WHERE serial_number = sqlc.arg('serial_number')
RETURNING *;
