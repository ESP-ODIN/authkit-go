package authkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func privateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwk(k *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
}

func validClaims() Claims {
	return Claims{ID: uuid.New(), Email: "user@example.test", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "odin-auth", Audience: jwt.ClaimStrings{"odin-api"},
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}}
}

func signed(t *testing.T, claims Claims, kid any, method jwt.SigningMethod, key any) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != nil {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newAuth(t *testing.T, server *httptest.Server) *Authenticator {
	t.Helper()
	a, err := New(Config{JWKSURL: server.URL, Issuer: "odin-auth", Audience: "odin-api", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMiddleware(t *testing.T) {
	key, other := privateKey(t), privateKey(t)
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk(key, "key-1")}})
	}))
	defer server.Close()
	a := newAuth(t, server)
	claims := validClaims()
	valid := signed(t, claims, "key-1", jwt.SigningMethodRS256, key)
	for _, scheme := range []string{"Bearer", "bearer"} {
		r := httptest.NewRequest("POST", "/posts", nil)
		r.Header.Set("Authorization", scheme+" "+valid)
		w := httptest.NewRecorder()
		a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := IdentityFromContext(r.Context())
			if !ok || identity.ID != claims.ID || identity.Email != claims.Email {
				t.Errorf("incorrect identity: %+v", identity)
			}
			w.WriteHeader(http.StatusCreated)
		})).ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("valid token: %d %s", w.Code, w.Body.String())
		}
		if _, ok := IdentityFromContext(r.Context()); ok {
			t.Fatal("original context modified")
		}
	}
	if fetches.Load() != 1 {
		t.Fatal("cache did not reuse key")
	}
	tests := []struct {
		name, header string
		mutate       func(*Claims)
		kid          any
		method       jwt.SigningMethod
		signingKey   any
	}{
		{name: "absent", header: ""}, {name: "basic", header: "Basic abc"},
		{name: "empty bearer", header: "Bearer"}, {name: "extra fields", header: "Bearer abc def"},
		{name: "malformed", header: "Bearer broken"},
		{name: "HS256", kid: "key-1", method: jwt.SigningMethodHS256, signingKey: []byte("secret")},
		{name: "none", kid: "key-1", method: jwt.SigningMethodNone, signingKey: jwt.UnsafeAllowNoneSignatureType},
		{name: "RS512", kid: "key-1", method: jwt.SigningMethodRS512, signingKey: key},
		{name: "bad signature", kid: "key-1", signingKey: other},
		{name: "expired", kid: "key-1", mutate: func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }},
		{name: "missing exp", kid: "key-1", mutate: func(c *Claims) { c.ExpiresAt = nil }},
		{name: "issuer", kid: "key-1", mutate: func(c *Claims) { c.Issuer = "wrong" }},
		{name: "missing issuer", kid: "key-1", mutate: func(c *Claims) { c.Issuer = "" }},
		{name: "audience", kid: "key-1", mutate: func(c *Claims) { c.Audience = jwt.ClaimStrings{"wrong"} }},
		{name: "missing audience", kid: "key-1", mutate: func(c *Claims) { c.Audience = nil }},
		{name: "missing kid"}, {name: "numeric kid", kid: 123}, {name: "empty kid", kid: ""},
		{name: "unknown kid", kid: "missing"},
		{name: "nil ID", kid: "key-1", mutate: func(c *Claims) { c.ID = uuid.Nil }},
		{name: "sub cannot replace ID", kid: "key-1", mutate: func(c *Claims) { c.ID = uuid.Nil; c.Subject = uuid.NewString() }},
		{name: "missing iat", kid: "key-1", mutate: func(c *Claims) { c.IssuedAt = nil }},
		{name: "future iat", kid: "key-1", mutate: func(c *Claims) { c.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour)) }},
		{name: "future nbf", kid: "key-1", mutate: func(c *Claims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if header == "" && tc.name != "absent" {
				c := claims
				if tc.mutate != nil {
					tc.mutate(&c)
				}
				method := tc.method
				if method == nil {
					method = jwt.SigningMethodRS256
				}
				sk := tc.signingKey
				if sk == nil {
					sk = key
				}
				header = "Bearer " + signed(t, c, tc.kid, method, sk)
			}
			r := httptest.NewRequest("POST", "/posts", nil)
			r.Header.Set("Authorization", header)
			w := httptest.NewRecorder()
			a.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated handler called") })).ServeHTTP(w, r)
			if w.Code != 401 || w.Body.String() != "Unauthorized\n" || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("unexpected rejection: %d %q", w.Code, w.Body.String())
			}
		})
	}
	if fetches.Load() != 2 {
		t.Fatalf("unknown kid should refresh once; fetches=%d", fetches.Load())
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+valid)
	r.Header.Add("Authorization", "Bearer "+valid)
	w := httptest.NewRecorder()
	a.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("duplicate headers accepted") })).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestConcurrentCacheAndRotation(t *testing.T) {
	key, rotated := privateKey(t), privateKey(t)
	var fetches atomic.Int32
	var rotation atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		keys := []any{jwk(key, "old")}
		if rotation.Load() {
			keys = append(keys, jwk(rotated, "new"))
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer server.Close()
	a := newAuth(t, server)
	run := func(raw string, wantOK bool) {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := a.verify(context.Background(), raw)
				if (err == nil) != wantOK {
					t.Errorf("verify error: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	old := signed(t, validClaims(), "old", jwt.SigningMethodRS256, key)
	run(old, true)
	if fetches.Load() != 1 {
		t.Fatalf("initial fetches: %d", fetches.Load())
	}
	rotation.Store(true)
	run(signed(t, validClaims(), "new", jwt.SigningMethodRS256, rotated), true)
	if fetches.Load() != 2 {
		t.Fatalf("rotation fetches: %d", fetches.Load())
	}
	run(old, true)
	run(signed(t, validClaims(), "unknown", jwt.SigningMethodRS256, key), false)
	if fetches.Load() != 2 {
		t.Fatal("unknown-key flood bypassed cooldown")
	}
	// Advance the internal refresh timestamp without sleeping.
	a.keys.mu.Lock()
	a.keys.lastRefresh = time.Now().Add(-refreshInterval)
	a.keys.mu.Unlock()
	run(signed(t, validClaims(), "unknown", jwt.SigningMethodRS256, key), false)
	if fetches.Load() != 3 {
		t.Fatalf("concurrent refreshes: %d", fetches.Load())
	}
}

func TestConfig(t *testing.T) {
	for _, cfg := range []Config{
		{}, {JWKSURL: "/relative", Issuer: "i", Audience: "a"},
		{JWKSURL: "ftp://auth/jwks", Issuer: "i", Audience: "a"},
		{JWKSURL: "https://user:password@auth/jwks", Issuer: "i", Audience: "a"},
		{JWKSURL: "https://auth/jwks#fragment", Issuer: "i", Audience: "a"},
		{JWKSURL: "https://auth/jwks", Issuer: " ", Audience: "a"},
		{JWKSURL: "https://auth/jwks", Issuer: "i", Audience: " "},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("accepted config: %+v", cfg)
		}
	}
	if _, err := New(Config{JWKSURL: "https://auth.invalid/jwks", Issuer: "i", Audience: "a"}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidJWKS(t *testing.T) {
	key := privateKey(t)
	encode := func(keys ...map[string]string) string {
		b, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	bad := func(field, value string) string { k := jwk(key, "key"); k[field] = value; return encode(k) }
	for name, body := range map[string]string{
		"malformed": "{", "trailing": "{\"keys\":[]} {}", "empty": "{\"keys\":[]}",
		"oversized":   strings.Repeat(" ", maxJWKSBytes+1),
		"duplicate":   encode(jwk(key, "key"), jwk(key, "key")),
		"missing kid": bad("kid", ""), "wrong type": bad("kty", "EC"),
		"wrong use": bad("use", "enc"), "wrong alg": bad("alg", "HS256"),
		"bad n": bad("n", "%%%"), "bad e": bad("e", "%%%"),
		"weak modulus": bad("n", "Aw"), "even exponent": bad("e", "Ag"),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			a := newAuth(t, server)
			if _, err := a.verify(context.Background(), signed(t, validClaims(), "key", jwt.SigningMethodRS256, key)); err == nil {
				t.Fatal("invalid JWKS accepted")
			}
		})
	}
}

func TestFetchFailurePreservesCache(t *testing.T) {
	key := privateKey(t)
	var fail atomic.Bool
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "private detail", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk(key, "key")}})
	}))
	defer server.Close()
	a := newAuth(t, server)
	valid := signed(t, validClaims(), "key", jwt.SigningMethodRS256, key)
	if _, err := a.verify(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	unknown := signed(t, validClaims(), "new", jwt.SigningMethodRS256, key)
	for i := 0; i < 5; i++ {
		if _, err := a.verify(context.Background(), unknown); err == nil {
			t.Fatal("failed refresh accepted")
		}
	}
	if _, err := a.verify(context.Background(), valid); err != nil {
		t.Fatal("cached key lost", err)
	}
	if calls.Load() != 2 {
		t.Fatal("failure retries not throttled")
	}
	// A cold-cache failure must also fail closed and throttle retries.
	b := newAuth(t, server)
	for i := 0; i < 5; i++ {
		if _, err := b.verify(context.Background(), valid); err == nil {
			t.Fatal("unavailable JWKS accepted")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("initial failures not throttled")
	}
}

func TestFetchTimeoutAndWaitCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	a := newAuth(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := a.keys.key(ctx, "key"); done <- err }()
	<-started
	waitCtx, waitCancel := context.WithCancel(context.Background())
	waitCancel()
	if _, err := a.keys.key(waitCtx, "key"); err != context.Canceled {
		t.Fatalf("wait cancellation: %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("timeout ignored")
	}
}
