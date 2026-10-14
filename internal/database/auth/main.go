package auth

import "github.com/alexedwards/argon2id"

func HashPassword(password string) (string, error) {
	params := &argon2id.Params{
		Memory:      64 * 1024, // 64 MiB, in KiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16, // bytes
		KeyLength:   32, // bytes
	}

	return argon2id.CreateHash(password, params)
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
