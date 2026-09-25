package authkit

import (
	"context"
	"github.com/google/uuid"
)

// Identity is the authenticated user. Resource authorization belongs to the service.
type Identity struct {
	ID    uuid.UUID
	Email string
}

type identityKey struct{}

// IdentityFromContext returns the identity installed by RequireAuth.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}
