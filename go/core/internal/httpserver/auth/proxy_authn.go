package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

var ErrUnauthenticated = errors.New("unauthenticated: missing or invalid Authorization header")

type ProxyAuthenticator struct {
	userIDClaim string
	// issuers holds the trusted issuers by issuer URL. When it is empty, claims
	// are decoded without verification and the proxy must have verified them.
	issuers map[string]*TrustedIssuer
}

func NewProxyAuthenticator(userIDClaim string, issuers ...*TrustedIssuer) *ProxyAuthenticator {
	if userIDClaim == "" {
		userIDClaim = "sub"
	}
	byURL := make(map[string]*TrustedIssuer, len(issuers))
	for _, issuer := range issuers {
		byURL[issuer.issuer] = issuer
	}
	return &ProxyAuthenticator{userIDClaim: userIDClaim, issuers: byURL}
}

func (a *ProxyAuthenticator) Authenticate(ctx context.Context, reqHeaders http.Header, query url.Values) (auth.Session, error) {
	if len(reqHeaders.Values("Authorization")) != 1 {
		return nil, ErrUnauthenticated
	}
	authHeader := reqHeaders.Get("Authorization")

	tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return nil, ErrUnauthenticated
	}

	// Kubernetes credentials are independently verified by ServiceAccountProvider.
	rawClaims, err := a.claims(ctx, tokenString)
	if err != nil {
		return nil, ErrUnauthenticated
	}

	// Direct user call: identity comes from the OIDC JWT claims.
	userID, _ := rawClaims[a.userIDClaim].(string)
	if userID == "" && a.userIDClaim != "sub" {
		userID, _ = rawClaims["sub"].(string)
	}
	if userID == "" {
		return nil, ErrUnauthenticated
	}
	expiresAt, err := jwtExpiration(rawClaims)
	if err != nil {
		return nil, err
	}
	issuer, _ := rawClaims["iss"].(string)
	return &SimpleSession{
		P: auth.Principal{
			ID:     auth.PrincipalID("trusted-proxy:"+issuer, userID),
			Claims: rawClaims,
		},
		bearerCredential: bearerCredential{authHeader: authHeader, expiresAt: expiresAt},
	}, nil
}

func (a *ProxyAuthenticator) UpstreamAuth(r *http.Request, session auth.Session, destinationSessionID string) error {
	return auth.ForwardCredential(r, session)
}

// claims verifies the token against its trusted issuer. Without trusted issuers,
// the configured proxy must verify the token before forwarding it.
func (a *ProxyAuthenticator) claims(ctx context.Context, tokenString string) (map[string]any, error) {
	claims, err := parseJWTPayload(tokenString)
	if err != nil || len(a.issuers) == 0 {
		return claims, err
	}
	iss, _ := claims["iss"].(string)
	issuer, ok := a.issuers[iss]
	if !ok {
		return nil, ErrUnauthenticated
	}
	return issuer.verify(ctx, tokenString)
}

// parseJWTPayload parses JWT claims without signature verification. Callers must
// establish trust through the configured proxy or an independent verifier.
func parseJWTPayload(tokenString string) (map[string]any, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil {
		return nil, err
	}
	return claims, nil
}
