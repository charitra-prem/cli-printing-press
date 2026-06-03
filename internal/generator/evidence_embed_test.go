package generator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

// TestSanitizeEvidence_RedactsAuthSecretValues verifies that auth-secret
// classed slots are scrubbed from both Exemplars and Slot.Value before the
// sanitized form is handed to the embed step. Non-auth values pass through.
func TestSanitizeEvidence_RedactsAuthSecretValues(t *testing.T) {
	t.Parallel()

	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{
			{
				Method:         "POST",
				BaseURL:        "https://api.example.com",
				NormalizedPath: "/v1/items",
				Exemplars: []wireevidence.Exemplar{
					{
						URL:       "https://api.example.com/v1/items",
						Headers:   map[string]string{"Accept": "application/json", "Authorization": "Bearer eyJabc.def.ghi"},
						BodyMulti: map[string]string{"token": "xoxc-1-2-3", "locale": "en-US"},
					},
				},
				Slots: []wireevidence.Slot{
					{Location: wireevidence.LocationHeader, Name: "Accept", Classification: wireevidence.ClassProtocolConstant, Constant: true, Value: "application/json"},
					{Location: wireevidence.LocationHeader, Name: "Authorization", Classification: wireevidence.ClassAuthSecret, Constant: true},
					{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret, Constant: true},
					{Location: wireevidence.LocationBodyMulti, Name: "locale", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "en-US"},
				},
			},
		},
	}

	sanitized := sanitizeEvidence(doc)
	require.NotNil(t, sanitized)
	require.Len(t, sanitized.Requests, 1)
	req := sanitized.Requests[0]

	// Exemplar values: auth-secret slots get placeholders, others stay verbatim.
	assert.Equal(t, "application/json", req.Exemplars[0].Headers["Accept"])
	assert.Equal(t, "${AUTHORIZATION}", req.Exemplars[0].Headers["Authorization"])
	assert.Equal(t, "${TOKEN}", req.Exemplars[0].BodyMulti["token"])
	assert.Equal(t, "en-US", req.Exemplars[0].BodyMulti["locale"])

	// Slot.Value for auth-secret slots gets a placeholder so the embedded
	// document also doesn't leak the env name's resolved value.
	slotByName := map[string]wireevidence.Slot{}
	for _, s := range req.Slots {
		slotByName[s.Location+":"+s.Name] = s
	}
	assert.Equal(t, "${AUTHORIZATION}", slotByName[wireevidence.LocationHeader+":Authorization"].Value)
	assert.Equal(t, "${TOKEN}", slotByName[wireevidence.LocationBodyMulti+":token"].Value)

	// Non-auth slots are untouched.
	assert.Equal(t, "application/json", slotByName[wireevidence.LocationHeader+":Accept"].Value)
	assert.Equal(t, "en-US", slotByName[wireevidence.LocationBodyMulti+":locale"].Value)

	// Original document untouched: caller still writes un-redacted to disk.
	assert.Equal(t, "Bearer eyJabc.def.ghi", doc.Requests[0].Exemplars[0].Headers["Authorization"])
	assert.Equal(t, "xoxc-1-2-3", doc.Requests[0].Exemplars[0].BodyMulti["token"])
}

// TestEmitRequestEvidenceGo_CompilableLiteral writes the sanitized bytes as a
// Go source file and verifies the file parses as a valid []byte literal
// (avoids regressions where a stray backtick would close the raw string).
func TestEmitRequestEvidenceGo_CompilableLiteral(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Include a backtick in the payload to exercise the escape path: JSON
	// allows raw backticks in string values, so a captured header could in
	// principle contain one.
	payload := []byte("{\"x\":\"a`b\"}\n")
	require.NoError(t, emitRequestEvidenceGo(dir, payload))

	written, err := os.ReadFile(filepath.Join(dir, "internal", "client", "request_evidence.gen.go"))
	require.NoError(t, err)
	got := string(written)
	assert.Contains(t, got, "package client")
	assert.Contains(t, got, "var requestEvidenceJSON = []byte(`")
	// The backtick must be split so the raw string compiles.
	assert.NotContains(t, got, "`{\"x\":\"a`b\"")
}

// TestOverlayEvidenceBaseURLs_PerEndpointHost pins that PR 5's overlay
// rewrites endpoint.BaseURL from the captured evidence, so a multi-host
// capture routes per-endpoint at request time without relying on PR 2's
// preserve-hosts toggle re-firing at print time.
func TestOverlayEvidenceBaseURLs_PerEndpointHost(t *testing.T) {
	t.Parallel()

	apiSpec := &spec.APISpec{
		Name:       "twohost",
		BaseURL:    "https://api.example.com",
		SpecSource: "sniffed",
		Resources: map[string]spec.Resource{
			"items": {
				Endpoints: map[string]spec.Endpoint{
					"list_items": {Method: "GET", Path: "/v1/items"},
				},
			},
			"profiles": {
				Endpoints: map[string]spec.Endpoint{
					"list_profiles": {Method: "GET", Path: "/v1/profiles"},
				},
			},
		},
	}
	g := &Generator{Spec: apiSpec}

	doc := &wireevidence.Document{
		Requests: []wireevidence.RequestEvidence{
			{Method: "GET", BaseURL: "https://api.example.com", NormalizedPath: "/v1/items"},
			{Method: "GET", BaseURL: "https://partner.example.net", NormalizedPath: "/v1/profiles"},
		},
	}
	overlayEvidenceBaseURLs(g, doc)

	assert.Equal(t, "https://api.example.com", apiSpec.Resources["items"].Endpoints["list_items"].BaseURL,
		"primary-host endpoint base URL is overlayed even when it matches the API root, so downstream codegen treats both endpoints uniformly")
	assert.Equal(t, "https://partner.example.net", apiSpec.Resources["profiles"].Endpoints["list_profiles"].BaseURL,
		"secondary-host endpoint must inherit its captured host from the evidence sidecar")
}

func TestSpecSourceIsSniffed(t *testing.T) {
	t.Parallel()
	assert.True(t, specSourceIsSniffed("sniffed"))
	assert.True(t, specSourceIsSniffed("browser-sniffed"))
	assert.True(t, specSourceIsSniffed("  Sniffed "))
	assert.False(t, specSourceIsSniffed("official"))
	assert.False(t, specSourceIsSniffed(""))
}

// TestAuthSecretEnvName_MatchesPR3 keeps the PR 5 evidence redaction env-name
// rule aligned with the PR 3 body-field env-name rule so a body field
// already routed through PR 3 reads the same env at request time after PR 5
// embeds its sidecar entry.
func TestAuthSecretEnvName_MatchesPR3(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"token", "TOKEN"},
		{"x-csrf-token", "X_CSRF_TOKEN"},
		{"Authorization", "AUTHORIZATION"},
		{"slack-token", "SLACK_TOKEN"},
		{"  ", "AUTH_SECRET"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, authSecretEnvName(c.in))
		})
	}
}

// TestApplyRequestEvidence_NonSniffedNoOp ensures generation for an
// official/community/docs spec source is byte-identical to pre-PR-5 behavior:
// no request_evidence.gen.go is written and endpoint BaseURLs are untouched.
func TestApplyRequestEvidence_NonSniffedNoOp(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sidecar := filepath.Join(dir, "spec-request-evidence.json")
	data, err := json.Marshal(&wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{
			{Method: "GET", BaseURL: "https://different.example.com", NormalizedPath: "/v1/items"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sidecar, data, 0o600))

	apiSpec := &spec.APISpec{
		Name:       "official",
		BaseURL:    "https://api.example.com",
		SpecSource: "official",
		Resources: map[string]spec.Resource{
			"items": {
				Endpoints: map[string]spec.Endpoint{
					"list_items": {Method: "GET", Path: "/v1/items"},
				},
			},
		},
	}
	outDir := t.TempDir()
	g := &Generator{Spec: apiSpec, OutputDir: outDir, RequestEvidencePath: sidecar}

	require.NoError(t, g.applyRequestEvidence())
	assert.Empty(t, apiSpec.Resources["items"].Endpoints["list_items"].BaseURL,
		"non-sniffed sources must not have BaseURL overlayed from the sidecar")
	_, statErr := os.Stat(filepath.Join(outDir, "internal", "client", "request_evidence.gen.go"))
	assert.True(t, os.IsNotExist(statErr),
		"request_evidence.gen.go must not be written for non-sniffed sources")
}

// TestApplyRequestEvidence_SniffedEmits writes a sniffed-source sidecar with
// an auth-secret slot, runs applyRequestEvidence, and verifies the embed file
// is created with redacted secret values and the endpoint BaseURL overlay.
func TestApplyRequestEvidence_SniffedEmits(t *testing.T) {
	t.Parallel()

	const secret = "xoxc-shouldnotappear"
	dir := t.TempDir()
	sidecar := filepath.Join(dir, "spec-request-evidence.json")
	data, err := json.Marshal(&wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{
			{
				Method:         "POST",
				BaseURL:        "https://partner.example.net",
				NormalizedPath: "/v1/items",
				Exemplars: []wireevidence.Exemplar{{
					URL:       "https://partner.example.net/v1/items",
					BodyMulti: map[string]string{"token": secret},
				}},
				Slots: []wireevidence.Slot{
					{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret, Constant: true},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sidecar, data, 0o600))

	apiSpec := &spec.APISpec{
		Name:       "sniffed",
		BaseURL:    "https://api.example.com",
		SpecSource: "sniffed",
		Resources: map[string]spec.Resource{
			"items": {
				Endpoints: map[string]spec.Endpoint{
					"create_items": {Method: "POST", Path: "/v1/items"},
				},
			},
		},
	}
	outDir := t.TempDir()
	g := &Generator{Spec: apiSpec, OutputDir: outDir, RequestEvidencePath: sidecar}

	require.NoError(t, g.applyRequestEvidence())

	assert.Equal(t, "https://partner.example.net", apiSpec.Resources["items"].Endpoints["create_items"].BaseURL,
		"sniffed endpoint must pick up the captured host from the sidecar")

	written, err := os.ReadFile(filepath.Join(outDir, "internal", "client", "request_evidence.gen.go"))
	require.NoError(t, err)
	got := string(written)
	assert.Contains(t, got, "package client")
	assert.NotContains(t, got, secret, "embedded JSON must not contain the original auth-secret value")
	assert.Contains(t, got, "${TOKEN}", "auth-secret slots must redact to ${ENV_NAME} placeholders")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(got), "`)"),
		"emitted file must end with the raw-string close so the Go source is parseable")
}
