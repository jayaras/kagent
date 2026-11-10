package a2a

import (
	"strings"
	"testing"

	a2atype "github.com/a2aproject/a2a-go/v2/a2a"
	adkagent "google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/runner"
	adksession "google.golang.org/adk/v2/session"
	"google.golang.org/genai"

	kagenta2a "github.com/kagent-dev/kagent/go/api/a2a"
)

// A caller's DataPart in a user message reaches the model, as in the Python adapter. A2A
// defines DataPart as structured content a client can send. An untyped one arrives as JSON
// text; one with a part type the adapter doesn't know goes through ADK's default.
func TestCallerDataPartReachesTheModel(t *testing.T) {
	const marker = "pull request 3618 is low risk"
	data := map[string]any{"results": []any{map[string]any{"number": 3618, "summary": marker}}}
	tests := []struct {
		name string
		part *a2atype.Part
	}{
		{name: "untyped DataPart, as an A2A client sends it", part: convDataPart(data, nil)},
		{name: "DataPart with an unknown part type", part: convDataPart(data, map[string]any{kagenta2a.PartTypeMetadataKey: "client_data"})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			rec := &geminiAPIRecorder{}
			a, err := llmagent.New(llmagent.Config{Name: "data", Model: rec})
			if err != nil {
				t.Fatal(err)
			}
			sessions := adksession.InMemoryService()
			r, err := runner.New(runner.Config{AppName: "test", Agent: a, SessionService: sessions})
			if err != nil {
				t.Fatal(err)
			}
			sess, err := sessions.Create(ctx, &adksession.CreateRequest{AppName: "test", UserID: "user"})
			if err != nil {
				t.Fatal(err)
			}
			// Build the content the way adka2a's toGenAIContent does with kagent's
			// converter: a nil result is skipped.
			msg := &genai.Content{Role: genai.RoleUser}
			for _, p := range []*a2atype.Part{a2atype.NewTextPart("Write release notes from the results in the data."), tt.part} {
				converted, err := a2aPartConverter(ctx, nil, p)
				if err != nil {
					t.Fatal(err)
				}
				if converted != nil {
					msg.Parts = append(msg.Parts, converted)
				}
			}
			for _, err := range r.Run(ctx, "user", sess.Session.ID(), msg, adkagent.RunConfig{}) {
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(rec.requests) != 1 {
				t.Fatalf("model called %d times, want 1", len(rec.requests))
			}
			if seen := requestText(rec.requests[0].Contents); !strings.Contains(seen, marker) {
				t.Errorf("the model never saw the data part; its user content was:\n%s", seen)
			}
		})
	}
}

// requestText is every text part and inline text blob the model receives, as one string.
// ADK's default DataPart conversion is a text/plain blob of the JSON.
func requestText(contents []*genai.Content) string {
	var b strings.Builder
	for _, c := range contents {
		for _, p := range c.Parts {
			b.WriteString(p.Text)
			if p.InlineData != nil && strings.HasPrefix(p.InlineData.MIMEType, "text/") {
				b.Write(p.InlineData.Data)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
