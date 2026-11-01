-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid ( ), NOW ( ), NOW ( ), $1, $2
)
RETURNING *;

-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1;

-- name: ListChirps :many
SELECT *
FROM chirps
WHERE
    (sqlc.narg('author_id')::uuid IS NULL
        OR user_id = sqlc.narg('author_id'))
ORDER BY created_at DESC;

-- name: GetChirp :one
SELECT * FROM chirps
WHERE id = $1 LIMIT 1;