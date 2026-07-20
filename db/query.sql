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
    issuer_serial_number,
    skid,
    akid,
    not_before,
    not_after,
    certificate_pem
) VALUES (
    sqlc.arg('serial_number'),
    sqlc.arg('common_name'),
    sqlc.arg('type'),
    sqlc.arg('key_name'),
    sqlc.arg('issuer_serial_number'),
    sqlc.arg('skid'),
    sqlc.arg('akid'),
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
SELECT serial_number, common_name, type, not_after, is_revoked
FROM certificates
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListKeys :many
SELECT name, algorithm, created_at
FROM keys
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: GetCertificateBySN :one
SELECT * FROM certificates WHERE serial_number = sqlc.arg('serial_number');

-- name: GetCertificateByCN :one
SELECT * FROM certificates WHERE common_name = sqlc.arg('common_name');

-- name: GetCertificateBySKID :one
SELECT * FROM certificates WHERE skid = sqlc.arg('skid');

-- name: GetKeyByName :one
SELECT * FROM keys WHERE name = sqlc.arg('name');

-- name: UpdateCertificate :one
UPDATE certificates
SET
  common_name = COALESCE(sqlc.narg('common_name'), common_name),
  type = COALESCE(sqlc.narg('type'), type),
  key_name = COALESCE(sqlc.narg('key_name'), key_name),
  issuer_serial_number = COALESCE(sqlc.narg('issuer_serial_number'), issuer_serial_number),
  skid = COALESCE(sqlc.narg('skid'), skid),
  akid = COALESCE(sqlc.narg('akid'), akid),
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

-- name: GetRevokedCertificates :many
SELECT * FROM certificates
WHERE
    issuer_serial_number = sqlc.arg('issuer_serial_number')
AND is_revoked = 1;

-- name: CreateCRL :one
INSERT INTO crls (
    name,
    crl_number,
    issuer_serial_number,
    this_update,
    next_update,
    crl_pem
) VALUES (
    sqlc.arg('name'),
    sqlc.arg('crl_number'),
    sqlc.arg('issuer_serial_number'),
    sqlc.arg('this_update'),
    sqlc.arg('next_update'),
    sqlc.arg('crl_pem')
)
RETURNING *;

-- name: GetLatestCRLNumber :one
SELECT crl_number FROM crls WHERE issuer_serial_number = sqlc.arg('issuer_serial_number') ORDER BY created_at DESC LIMIT 1;

-- name: GetAllCRL :many
SELECT * FROM crls WHERE issuer_serial_number = sqlc.arg('issuer_serial_number');

-- name: GetCRLByName :one
SELECT * FROM crls WHERE name = sqlc.arg('name');
