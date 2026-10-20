package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	_, err := MakeJWT(uuid.New(), "secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()

	valid, err := MakeJWT(userID, "secret", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	expired, err := MakeJWT(userID, "secret", -time.Minute)
	if err != nil {
		t.Fatalf("MakeJWT: %v", err)
	}

	wrongAlg, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   userID.String(),
	}).SignedString([]byte("secret"))

	if err != nil {
		t.Fatalf("sign HS512 token: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		secret  string
		want    uuid.UUID
		wantErr bool
	}{
		{"valid", valid, "secret", userID, false},
		{"wrong secret", valid, "other", uuid.Nil, true},
		{"expired", expired, "secret", uuid.Nil, true},
		{"wrong signing method", wrongAlg, "secret", uuid.Nil, true},
		{"malformed", "garbage", "secret", uuid.Nil, true},
		{"empty", "", "secret", uuid.Nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateJWT(tt.token, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	password := "correct horse battery staple"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("expected different hashes for the same password (salt), got %s twice", hash1)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "correct horse battery staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{"correct password", password, hash, true, false},
		{"wrong password", "wrong", hash, false, false},
		{"empty password", "", hash, false, false},
		{"invalid hash", password, "not-a-hash", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
