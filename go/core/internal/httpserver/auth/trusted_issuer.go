package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/kagent-dev/kagent/go/pkg/logging"
)

const trustedIssuerClockSkew = 30 * time.Second

// TrustedIssuer verifies bearer JWTs signed by one OIDC issuer for a fixed set
// of audiences.
type TrustedIssuer struct {
	issuer    string
	jwksURL   string
	keys      *jwk.AutoRefresh
	audiences []string
}

// NewTrustedIssuer loads the issuer's discovery document and signing keys. The
// context owns key refreshes; callers must cancel it when the issuer is unused.
func NewTrustedIssuer(ctx context.Context, client *http.Client, issuer string, audiences []string) (*TrustedIssuer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request for issuer %s: %w", issuer, err)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery for issuer %s: %w", issuer, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch discovery for issuer %s: HTTP %d", issuer, response.StatusCode)
	}
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery for issuer %s: %w", issuer, err)
	}
	if discovery.Issuer != issuer {
		return nil, fmt.Errorf("discovery for issuer %s names issuer %q", issuer, discovery.Issuer)
	}
	if !strings.HasPrefix(discovery.JWKSURI, "https://") {
		return nil, fmt.Errorf("discovery for issuer %s has a non-HTTPS jwks_uri", issuer)
	}
	keys := jwk.NewAutoRefresh(ctx)
	// Refresh on a fixed interval so that unknown token kids cannot trigger requests.
	keys.Configure(discovery.JWKSURI, jwk.WithHTTPClient(client), jwk.WithRefreshInterval(time.Minute))
	if _, err := keys.Refresh(ctx, discovery.JWKSURI); err != nil {
		return nil, fmt.Errorf("failed to load signing keys for issuer %s: %w", issuer, err)
	}
	refreshErrors := make(chan jwk.AutoRefreshError, 1)
	keys.ErrorSink(refreshErrors)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-refreshErrors:
				logging.FromContext(ctx).ErrorContext(ctx, "failed to refresh trusted issuer signing keys", "issuer", issuer, "error", err.Error)
			}
		}
	}()
	return &TrustedIssuer{issuer: issuer, jwksURL: discovery.JWKSURI, keys: keys, audiences: audiences}, nil
}

// verify checks the signature, issuer, audience, and lifetime of raw and returns its claims.
func (i *TrustedIssuer) verify(ctx context.Context, raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		keys, err := i.keys.Fetch(ctx, i.jwksURL)
		if err != nil {
			return nil, err
		}
		key, ok := keys.LookupKeyID(kid)
		if !ok || (key.Algorithm() != "" && key.Algorithm() != token.Method.Alg()) || (key.KeyUsage() != "" && key.KeyUsage() != "sig") {
			return nil, fmt.Errorf("signing key %q is not trusted", kid)
		}
		var publicKey any
		if err := key.Raw(&publicKey); err != nil {
			return nil, err
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(i.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(trustedIssuerClockSkew))
	if err != nil {
		return nil, err
	}
	audiences, err := claims.GetAudience()
	if err != nil || !slices.ContainsFunc(audiences, func(audience string) bool { return slices.Contains(i.audiences, audience) }) {
		return nil, fmt.Errorf("token has no accepted audience")
	}
	return claims, nil
}
