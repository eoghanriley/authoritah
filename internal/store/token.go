// Package store provides internal helpers for session and token management.
// This is not part of the public API.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateToken returns a cryptographically secure random hex string (64 chars).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateID returns a random 32-char hex ID suitable for primary keys.
func GenerateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
