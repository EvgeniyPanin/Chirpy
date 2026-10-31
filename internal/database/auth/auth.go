package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/alexedwards/argon2id"
)

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

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	})

	return token.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "HS256" {
			return nil, errors.New("invalid signing method")
		}

		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	userId, err := token.Claims.GetSubject()

	if err != nil {
		return uuid.Nil, err
	}

	UUID, err := uuid.Parse(userId)

	if err != nil {
		return uuid.Nil, err
	}

	return UUID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	headerVal := headers.Get("Authorization")

	if strings.Compare(headerVal, "") == 0 {
		return "", errors.New("Token not found")
	}

	return strings.TrimPrefix(headerVal, "Bearer "), nil
}
