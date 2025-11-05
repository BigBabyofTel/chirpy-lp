-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, password_hash)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    sqlc.arg(email),
    sqlc.arg(password_hash)
) 
RETURNING *;

-- name: CreateChirp :one
INSERT INTO chirps (id, body, created_at, updated_at, user_id)
VALUES (gen_random_uuid(), $1, NOW(), NOW(), $2)
RETURNING *;

-- name: GetAllChirps :many
SELECT id, created_at, updated_at, body, user_id FROM chirps
ORDER BY created_at ASC;

-- name: GetChirpByID :one
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE id = $1;

-- name: GetChirp :one
SELECT * FROM chirps
WHERE sqlc.arg(id) = chirps.user_id;

-- name: GetUser :one
SELECT id, created_at, updated_at, email, password_hash, is_chirpy_red
FROM users
WHERE email = sqlc.arg(email)
LIMIT 1;

-- name: Reset :exec
DELETE FROM users;

-- name: AddRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (sqlc.arg(token), NOW(), NOW(), sqlc.arg(user_id), NOW() + INTERVAL '60 days', NULL)
RETURNING *;

-- name: GetRefreshToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at
FROM refresh_tokens
WHERE token = sqlc.arg(token)
LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET updated_at = NOW(), revoked_at = NOW(), token = ''
WHERE token = sqlc.arg(token);

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE id = sqlc.arg(user_id);
