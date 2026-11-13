package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	authimpl "github.com/kagent-dev/kagent/go/core/internal/httpserver/auth"
	"github.com/kagent-dev/kagent/go/core/internal/jwttest"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

const proxyAudience = "kagent"

func TestTrustedIssuerVerification(t *testing.T) {
	t.Run("Given a trusted issuer, when a caller sends a token it signed for a kagent audience, assert that the caller is authenticated as its subject", func(t *testing.T) {
		issuer := jwttest.New(t)
		provider := authimpl.NewProxyAuthenticator("email", trustedIssuer(t, issuer))
		claims := userClaims(issuer.URL)
		claims["aud"] = []string{"other", proxyAudience}

		session, err := provider.Authenticate(t.Context(), bearer(issuer.Token(t, claims)), nil)

		require.NoError(t, err)
		require.Equal(t, auth.PrincipalID("trusted-proxy:"+issuer.URL, "alice@example.com"), session.Principal().ID)
		require.Equal(t, "alice", session.Principal().Claims["sub"])
	})

	scenarios := []struct {
		name  string
		token func(t *testing.T, trusted, untrusted *jwttest.Issuer) string
	}{
		{"Given a trusted issuer, when a caller sends a token signed by another key with the trusted key ID, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			token := jwt.NewWithClaims(jwt.SigningMethodES256, userClaims(trusted.URL))
			token.Header["kid"] = "test-key"
			raw, err := token.SignedString(key)
			require.NoError(t, err)
			return raw
		}},
		{"Given a trusted issuer, when a caller sends an unsigned token naming that issuer, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			return createTestJWT(userClaims(trusted.URL))
		}},
		{"Given a trusted issuer, when a caller sends a token from an issuer outside the allowlist, assert that the caller is rejected", func(t *testing.T, _, untrusted *jwttest.Issuer) string {
			return untrusted.Token(t, userClaims(untrusted.URL))
		}},
		{"Given a trusted issuer, when a caller sends a token signed by it that names another issuer, assert that the caller is rejected", func(t *testing.T, trusted, untrusted *jwttest.Issuer) string {
			return trusted.Token(t, userClaims(untrusted.URL))
		}},
		{"Given a trusted issuer, when a caller sends a token for another audience, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			claims := userClaims(trusted.URL)
			claims["aud"] = []string{"kagent-runtime"}
			return trusted.Token(t, claims)
		}},
		{"Given a trusted issuer, when a caller sends a token without an audience, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			claims := userClaims(trusted.URL)
			delete(claims, "aud")
			return trusted.Token(t, claims)
		}},
		{"Given a trusted issuer, when a caller sends an expired token, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			claims := userClaims(trusted.URL)
			claims["iat"] = time.Now().Add(-time.Hour).Unix()
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
			return trusted.Token(t, claims)
		}},
		{"Given a trusted issuer, when a caller sends a token without an expiry, assert that the caller is rejected", func(t *testing.T, trusted, _ *jwttest.Issuer) string {
			claims := userClaims(trusted.URL)
			delete(claims, "exp")
			return trusted.Token(t, claims)
		}},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			trusted, untrusted := jwttest.New(t), jwttest.New(t)
			provider := authimpl.NewProxyAuthenticator("", trustedIssuer(t, trusted))

			session, err := provider.Authenticate(t.Context(), bearer(scenario.token(t, trusted, untrusted)), nil)

			require.ErrorIs(t, err, authimpl.ErrUnauthenticated)
			require.Nil(t, session)
		})
	}

	t.Run("Given a trusted issuer and service-account authentication, when a workload sends a Kubernetes token, assert that TokenReview authenticates it", func(t *testing.T) {
		issuer := jwttest.New(t)
		reviews := fake.NewClientset()
		reviews.PrependReactor("create", "tokenreviews", func(kubetesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
				Authenticated: true, Audiences: []string{"kagent-invocation"},
				User: authenticationv1.UserInfo{Username: "system:serviceaccount:kagent:caller", UID: "sa-uid"},
			}}, nil
		})
		provider := authimpl.NewServiceAccountProvider(authimpl.NewProxyAuthenticator("", trustedIssuer(t, issuer)), reviews.AuthenticationV1().TokenReviews(), "cluster")
		token := createTestJWT(map[string]any{"sub": "system:serviceaccount:kagent:caller", "exp": time.Now().Add(time.Hour).Unix()})

		session, err := provider.Authenticate(t.Context(), bearer(token), nil)

		require.NoError(t, err)
		require.Equal(t, auth.PrincipalID("kubernetes:cluster", "sa-uid"), session.Principal().ID)
	})

	t.Run("Given an issuer whose discovery names another issuer, when the authenticator starts, assert that startup fails", func(t *testing.T) {
		issuer := jwttest.New(t)

		_, err := authimpl.NewTrustedIssuer(t.Context(), issuerClient(t, issuer), issuer.URL+"/", []string{proxyAudience})

		require.ErrorContains(t, err, "names issuer")
	})
}

func trustedIssuer(t *testing.T, issuer *jwttest.Issuer) *authimpl.TrustedIssuer {
	t.Helper()
	trusted, err := authimpl.NewTrustedIssuer(t.Context(), issuerClient(t, issuer), issuer.URL, []string{proxyAudience})
	require.NoError(t, err)
	return trusted
}

func issuerClient(t *testing.T, issuer *jwttest.Issuer) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(issuer.CAFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pem))
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}

func userClaims(issuer string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": issuer, "aud": []string{proxyAudience}, "sub": "alice", "email": "alice@example.com",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}
