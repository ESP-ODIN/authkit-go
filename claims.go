// Package authkit authenticates ODIN users using Auth's public RS256 JWKS.
package authkit

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims preserves Auth's JWT contract. ID is Auth's USER.id, not sub.
type Claims struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	jwt.RegisteredClaims
}
