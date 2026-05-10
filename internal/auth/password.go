// Package auth wraps password hashing (bcrypt) and cookie sessions
// (gorilla/sessions). The HTTP layer depends only on this package for both.
package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is fixed at 12 — slow enough to deter offline brute force on a
// single hash without making login painful on a workstation.
const bcryptCost = 12

// HashPassword returns a bcrypt hash for the plaintext password.
func HashPassword(plain string) ([]byte, error) {
	if plain == "" {
		return nil, fmt.Errorf("auth.HashPassword: empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("auth.HashPassword: %w", err)
	}
	return h, nil
}

// VerifyPassword reports whether plain matches hash. Constant-time at the
// bcrypt level.
func VerifyPassword(hash []byte, plain string) bool {
	if len(hash) == 0 || plain == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(plain)) == nil
}
