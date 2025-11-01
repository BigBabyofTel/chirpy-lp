-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    sqlc.arg(email)
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

-- name: Reset :exec
DELETE FROM users;