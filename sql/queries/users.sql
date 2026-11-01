-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid ( ), NOW ( ), NOW ( ), $1, $2
)
RETURNING *;

-- name: PatchUser :one
UPDATE users
SET
    updated_at = NOW(),
    email = $2,
    hashed_password = $3
WHERE id = $1
RETURNING *;

-- name: UpdateUserChirpyRed :exec
UPDATE users
SET is_chirpy_red = $2
WHERE id = $1;

-- name: GetUser :one
SELECT * FROM users
WHERE email = $1 LIMIT 1;

-- name: DeleteUsers :exec
DELETE FROM users;