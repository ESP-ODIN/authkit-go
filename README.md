# authkit-go

Go authentication library for ODIN microservices. Validates RS256 JWTs issued by
Auth using its public JWKS and exposes the user's identity through `net/http` middleware.

## Installation

Requires Go 1.22 or later.

```sh
go get github.com/ESP-ODIN/authkit-go
```

## Usage

Import `authkit "github.com/ESP-ODIN/authkit-go"`, then protect your routes:

```go
authenticator, err := authkit.New(authkit.Config{
    JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
    Issuer:   "https://auth.example.com", // Must match Auth's iss exactly.
    Audience: "odin-api",               // Must appear in the token's aud.
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("GET /me", authenticator.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    identity, ok := authkit.IdentityFromContext(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    fmt.Fprintln(w, identity.ID)
})))
```

Reuse one authenticator across routes. `JWKSURL`, `Issuer`, and `Audience` are
required; `HTTPClient` is optional. Use HTTPS in production.
See [example_test.go](example_test.go) for a complete integration example.

## Behavior

- Accepts `Authorization: Bearer <JWT>` and requires RS256, a valid signature,
  `kid`, a nonzero UUID `id`, `exp`, `iss`, `aud`, and `iat`.
- Exposes `Identity.ID` and `Identity.Email`. The ID comes from Auth's `USER.id`,
  never `sub`. Use it for ownership checks; permissions remain your service's responsibility.
- Rejects expired tokens and future `iat`/`nbf` values without clock skew tolerance.
  Keep service clocks synchronized.
- Authentication failures return **401** with `WWW-Authenticate: Bearer`.
- Fetches and caches public keys on first use. An unknown `kid` triggers a refresh,
  subject to a 30-second cooldown between refresh attempts.

For key rotation, use a new `kid` and keep old keys published until their tokens
expire. There is no periodic refresh or individual token revocation; removing a
key from JWKS does not immediately invalidate cached keys.

## Tests

```sh
go test ./...
go vet ./...
go test -race ./...
```
