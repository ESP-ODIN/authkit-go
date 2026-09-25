package authkit

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config contains explicit settings supplied by the consuming service.
type Config struct {
	JWKSURL  string
	Issuer   string
	Audience string
	// HTTPClient optionally supplies the transport. Each fetch also has a
	// five-second deadline. Configure this client before calling New.
	HTTPClient *http.Client
}

// Authenticator validates JWTs and protects net/http handlers.
// It must be constructed with New and may be shared by concurrent handlers.
type Authenticator struct {
	parser *jwt.Parser
	keys   *keyCache
}

// New validates configuration without contacting Auth. Keys are fetched lazily.
func New(cfg Config) (*Authenticator, error) {
	u, err := url.Parse(cfg.JWKSURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("authkit: JWKSURL must be an absolute HTTP(S) URL without credentials or fragment")
	}
	if strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("authkit: Issuer and Audience are required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Authenticator{
		parser: jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithIssuer(cfg.Issuer), jwt.WithAudience(cfg.Audience), jwt.WithIssuedAt(), jwt.WithStrictDecoding()),
		keys:   &keyCache{url: cfg.JWKSURL, client: client},
	}, nil
}
