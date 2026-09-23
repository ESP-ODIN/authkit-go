package authkit

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const refreshInterval = 30 * time.Second
const maxJWKSBytes = 1 << 20

type keyCache struct {
	url         string
	client      *http.Client
	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	inflight    chan struct{}
	lastRefresh time.Time // Unknown-key refresh attempts, including failures.
}

func (c *keyCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	if key := c.keys[kid]; key != nil {
		c.mu.Unlock()
		return key, nil
	}
	if done := c.inflight; done != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
		}
		c.mu.Lock()
		key := c.keys[kid]
		c.mu.Unlock()
		if key == nil {
			return nil, fmt.Errorf("authkit: unknown kid after JWKS fetch")
		}
		return key, nil
	}
	if !c.lastRefresh.IsZero() && time.Since(c.lastRefresh) < refreshInterval {
		c.mu.Unlock()
		return nil, fmt.Errorf("authkit: unknown kid; refresh throttled")
	}
	initial := c.keys == nil
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()
	keys, err := c.fetch(ctx)
	c.mu.Lock()
	if err == nil {
		c.keys = keys
	}
	// A successful initial load permits one immediate refresh for rotation.
	if !initial || err != nil {
		c.lastRefresh = time.Now()
	}
	key := c.keys[kid]
	c.inflight = nil
	close(done)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("authkit: unknown kid")
	}
	return key, nil
}

func (c *keyCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authkit: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authkit: JWKS HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("authkit: JWKS too large")
	}
	var document struct {
		Keys []struct{ Kty, Use, Alg, Kid, N, E string }
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("authkit: invalid JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range document.Keys {
		if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
			continue
		}
		if jwk.Kid == "" {
			return nil, fmt.Errorf("authkit: empty JWKS kid")
		}
		if _, exists := keys[jwk.Kid]; exists {
			return nil, fmt.Errorf("authkit: duplicate JWKS kid")
		}
		n, nerr := base64.RawURLEncoding.Strict().DecodeString(jwk.N)
		e, eerr := base64.RawURLEncoding.Strict().DecodeString(jwk.E)
		if nerr != nil || eerr != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 || n[0] == 0 || e[0] == 0 {
			return nil, fmt.Errorf("authkit: invalid RSA parameters")
		}
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e).Uint64()
		if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || modulus.Bit(0) == 0 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return nil, fmt.Errorf("authkit: unsupported RSA parameters")
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("authkit: no usable RSA signing keys")
	}
	return keys, nil
}
