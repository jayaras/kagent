package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/kagent-dev/kagent/go/adk/pkg/models"
	"github.com/kagent-dev/kagent/go/adk/pkg/sts"
	configv1 "github.com/kagent-dev/kagent/go/api/gen/kagent/config/v1"
)

const exchangeCaller = "caller-token"

func TestMCPTokenExchange(t *testing.T) {
	t.Run("Given two token-exchange MCP servers, when a caller reaches each one, assert that each receives a token issued for its own resource and never the caller's token", func(t *testing.T) {
		fixture := newExchangeFixture(t, http.StatusOK)
		first, second := fixture.server(t), fixture.server(t)
		ctx := fixture.callerContext(exchangeCaller)

		fixture.send(t, ctx, first, []string{"first-audience"})
		fixture.send(t, ctx, first, []string{"first-audience"})
		fixture.send(t, ctx, second, nil)

		require.Equal(t, []string{"Bearer issued-for:" + first.URL, "Bearer issued-for:" + first.URL}, fixture.received(first.URL))
		require.Equal(t, []string{"Bearer issued-for:" + second.URL}, fixture.received(second.URL))
		require.Equal(t, []stsRequest{
			{resource: first.URL, audience: "first-audience", subject: exchangeCaller},
			{resource: second.URL, subject: exchangeCaller},
		}, fixture.exchanges, "a cached token is reused for the same server and caller")
	})

	failures := []struct {
		name   string
		status int
		caller string
		noSTS  bool
	}{
		{name: "Given a token-exchange MCP server, when the STS rejects the exchange, assert that the request is not sent", status: http.StatusBadRequest, caller: exchangeCaller},
		{name: "Given a token-exchange MCP server, when a request has no caller token, assert that the request is not sent", status: http.StatusOK},
		{name: "Given a token-exchange MCP server without an STS, when a caller sends a request, assert that the request is not sent", status: http.StatusOK, caller: exchangeCaller, noSTS: true},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			fixture := newExchangeFixture(t, failure.status)
			if failure.noSTS {
				fixture.exchanger = nil
			}
			server := fixture.server(t)

			err := fixture.roundTrip(t, fixture.callerContext(failure.caller), server, nil)

			require.Error(t, err)
			require.Empty(t, fixture.received(server.URL))
		})
	}
}

type stsRequest struct{ resource, audience, subject string }

type exchangeFixture struct {
	exchanger TokenExchanger
	mu        sync.Mutex
	exchanges []stsRequest
	requests  map[string][]string
}

// newExchangeFixture starts an STS that issues "issued-for:<resource>" tokens
// and answers token requests with status.
func newExchangeFixture(t *testing.T, status int) *exchangeFixture {
	t.Helper()
	f := &exchangeFixture{requests: map[string][]string{}}
	var tokenServer *httptest.Server
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": tokenServer.URL, "token_endpoint": tokenServer.URL + "/token"})
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid exchange", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.exchanges = append(f.exchanges, stsRequest{resource: r.Form.Get("resource"), audience: r.Form.Get("audience"), subject: r.Form.Get("subject_token")})
		f.mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, `{"error":"invalid_target"}`, status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "issued-for:" + r.Form.Get("resource"), "issued_token_type": string(sts.TokenTypeJWT), "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(tokenServer.Close)
	integration, err := sts.NewSTSIntegration(tokenServer.URL, "", nil, nil, 5, true, false)
	require.NoError(t, err)
	f.exchanger = sts.NewTokenPropagationPlugin(integration, slog.New(slog.DiscardHandler), nil, nil).ExchangeFor
	return f
}

// server starts an MCP endpoint that records the Authorization of each request.
func (f *exchangeFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests[server.URL] = append(f.requests[server.URL], r.Header.Get("Authorization"))
		f.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	return server
}

// callerContext carries the caller's token both where the executor stores it
// and on the A2A call, so token propagation would forward it if it could.
func (f *exchangeFixture) callerContext(caller string) context.Context {
	headers := map[string][]string{}
	if caller != "" {
		headers["Authorization"] = []string{"Bearer " + caller}
	}
	ctx := models.WithSessionID(a2aCtx(headers), "session")
	if caller != "" {
		ctx = context.WithValue(ctx, models.BearerTokenKey, caller)
	}
	return ctx
}

// roundTrip sends one request through the transport CreateToolsets builds for
// a token-exchange server, with token propagation and allowed headers enabled.
func (f *exchangeFixture) roundTrip(t *testing.T, ctx context.Context, server *httptest.Server, audiences []string) error {
	t.Helper()
	params := mcpServerParams{
		URL: server.URL, ServerType: "http", PropagateToken: true, AllowedHeaders: []string{"Authorization"},
		TokenExchange: tokenExchange(&configv1.ADKMCPTokenExchange{Resources: []string{server.URL}, Audiences: audiences}, f.exchanger),
	}
	transport, err := createTransport(ctx, params)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, nil)
	require.NoError(t, err)
	resp, err := transport.(*mcpsdk.StreamableClientTransport).HTTPClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (f *exchangeFixture) send(t *testing.T, ctx context.Context, server *httptest.Server, audiences []string) {
	t.Helper()
	require.NoError(t, f.roundTrip(t, ctx, server, audiences))
}

func (f *exchangeFixture) received(url string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[url]
}
