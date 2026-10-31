package auth

import (
	"net/http"
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

func TestBearerToken(t *testing.T) {
	t.Run("extracts valid token", func(t *testing.T) {
		got, _ := GetBearerToken(http.Header{"Authorization": []string{"Bearer token"}})
		want := "token"

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("returns an error if there is no Authorization header", func(t *testing.T) {
		_, err := GetBearerToken(http.Header{})

		if err == nil {
			t.Errorf("Expected an error with invalid token")
		}
	})
	t.Run("returns an error with empty Authorization header", func(t *testing.T) {
		_, err := GetBearerToken(http.Header{"Authorization": []string{""}})

		if err == nil {
			t.Errorf("Expected an error with invalid token")
		}
	})
}
