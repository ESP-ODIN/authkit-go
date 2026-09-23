package authkit

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (a *Authenticator) verify(ctx context.Context, raw string) (Identity, error) {
	claims := new(Claims)
	token, err := a.parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("authkit: expected RS256")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("authkit: missing kid")
		}
		return a.keys.key(ctx, kid)
	})
	if err != nil {
		return Identity{}, err
	}
	if !token.Valid || claims.ID == uuid.Nil || claims.IssuedAt == nil {
		return Identity{}, fmt.Errorf("authkit: invalid identity or missing iat")
	}
	return Identity{ID: claims.ID, Email: claims.Email}, nil
}
