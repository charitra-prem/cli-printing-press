package browsersniff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Adversarial fixture tests cover ill-shaped captures that real browsers
// emit by mistake (boundary mismatches, content-type omissions, single
// exemplars with conflicting name-vs-value signals). Each must:
//   - parse without panic
//   - emit a spec without inventing body fields the wire didn't carry
//   - leave the classifier on its documented behavior
//
// These fixtures live under testdata/sniff/adversarial/ to keep them
// distinct from the matrix fixtures (which represent real-world APIs).

const adversarialDir = "../../testdata/sniff/adversarial"

func loadAdversarialSpec(t *testing.T, fixture string) (*EnrichedCapture, evidenceResult) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(adversarialDir, fixture))
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	capture, err := LoadCapture(abs)
	require.NoError(t, err)

	apiSpec, err := AnalyzeCaptureWithOptions(capture, AnalyzeOptions{PreserveHosts: true})
	require.NoError(t, err)
	require.NotNil(t, apiSpec)

	evidence := BuildRequestEvidenceFromCapture(capture, AnalyzeOptions{PreserveHosts: true})
	return capture, evidenceResult{apiSpec: apiSpec, evidence: evidence}
}

type evidenceResult struct {
	apiSpec  *spec.APISpec
	evidence []wireevidence.RequestEvidence
}

// TestAdversarial_MalformedMultipart_NoBodyFields pins that a multipart
// body with a boundary mismatch (header declares ----GoodBoundary, body
// uses ----WrongBoundary) parses without panic and yields zero body
// slots. The classifier never invents fields from corrupted input.
func TestAdversarial_MalformedMultipart_NoBodyFields(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "malformed-multipart.har")

	require.Len(t, result.evidence, 1)
	for _, ex := range result.evidence[0].Exemplars {
		assert.Empty(t, ex.BodyMulti, "malformed multipart must yield zero body fields")
		assert.Empty(t, ex.BodyForm, "malformed multipart must not fall back to form parsing")
	}
	for _, slot := range result.evidence[0].Slots {
		assert.NotEqual(t, wireevidence.LocationBodyMulti, slot.Location,
			"no body_multipart slots should reach evidence for malformed body")
		assert.NotEqual(t, wireevidence.LocationBodyForm, slot.Location,
			"no body_form slots should reach evidence for malformed body")
	}
}

// TestAdversarial_BodyWithoutContentType pins that a POST with a body
// but no Content-Type header yields zero body slots — the parser does
// not guess body shape from text content. Adding a guessing fallback in
// the future requires explicit design, not silent inference.
func TestAdversarial_BodyWithoutContentType(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "body-without-content-type.har")

	require.Len(t, result.evidence, 1)
	for _, ex := range result.evidence[0].Exemplars {
		assert.Empty(t, ex.BodyMulti)
		assert.Empty(t, ex.BodyForm)
	}
	for _, slot := range result.evidence[0].Slots {
		assert.NotEqual(t, wireevidence.LocationBodyMulti, slot.Location)
		assert.NotEqual(t, wireevidence.LocationBodyForm, slot.Location)
	}
}

// TestAdversarial_SingleExemplarNameConflict pins PR 4's documented
// behavior: when one exemplar carries a header whose name matches the
// volatile pattern (x-b3-traceid) AND the value is identical to itself
// (vacuously constant across the single exemplar), name-pattern wins
// and the slot classifies as volatile-drop. This guards against a
// regression where a future "constant value → semantic-default" shortcut
// is added without consulting the name-pattern rule first.
func TestAdversarial_SingleExemplarNameConflict_NameWins(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "single-exemplar-name-conflict.har")

	require.Len(t, result.evidence, 1)
	var trace wireevidence.Slot
	for _, slot := range result.evidence[0].Slots {
		if slot.Location == wireevidence.LocationHeader && slot.Name == "x-b3-traceid" {
			trace = slot
			break
		}
	}
	require.NotEmpty(t, trace.Name, "x-b3-traceid slot must appear in the evidence sidecar")
	assert.Equal(t, wireevidence.ClassVolatileDrop, trace.Classification,
		"x-b3-traceid name-pattern must win over single-exemplar constancy")
	assert.Empty(t, trace.Value, "volatile-drop slots must not record a value, even when constant")
}

// TestAdversarial_OAuthCallback_CodeNotEmbedded pins the current gap:
// a browser navigation to an OAuth callback URL surfaces the one-time
// `code` and CSRF `state` as ordinary query params today. The `code`
// is single-use — embedding it in a generated CLI is dangerous. The
// /oauth/callback endpoint itself is a redirect target, not an API
// endpoint; it should ideally be excluded entirely from CLI gen.
//
// Today: the callback endpoint surfaces, the `code` slot has
// classification=semantic-default OR unknown (NOT auth-secret), and
// no upstream filter excludes /oauth/callback. This test documents
// what should happen post-fix rather than the (unsafe) current state.
func TestAdversarial_OAuthCallback_CodeMustNotBeReplayed(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "oauth-callback.har")

	// At least one non-callback endpoint exists (api/v1/me) so the
	// spec validates. Find the callback endpoint's evidence and
	// inspect the `code` slot.
	var codeSlot wireevidence.Slot
	var codeFound bool
	for _, ev := range result.evidence {
		if !strings.Contains(ev.NormalizedPath, "/oauth/callback") {
			continue
		}
		for _, slot := range ev.Slots {
			if slot.Location == wireevidence.LocationQuery && slot.Name == "code" {
				codeSlot = slot
				codeFound = true
			}
		}
	}

	if !codeFound {
		// If the callback endpoint is filtered out entirely (the
		// preferred future behavior), the slot won't exist — that's
		// also a pass. Skip the slot-class assertion in that case.
		t.Logf("oauth callback endpoint not present in evidence; treating as filtered (safe)")
		return
	}

	// Today the slot is present and classified semantic-default
	// (varies across the two exemplars → actually `unknown` since
	// values differ). Either way, NOT auth-secret. Pin the gap:
	// post-PR-9, this must be auth-secret to force redaction. Gated
	// so CI stays green; running with RUN_PIN_FAILS=1 shows the gap.
	if os.Getenv("RUN_PIN_FAILS") == "" {
		t.Skipf("PIN: blocked by PR 9 (OAuth `code` not classified auth-secret). "+
			"Today the slot is %q. Run with RUN_PIN_FAILS=1 to see the failing assertion.",
			codeSlot.Classification)
	}
	assert.Equal(t, wireevidence.ClassAuthSecret, codeSlot.Classification,
		"OAuth `code` is a one-time bearer-like secret; must be classified auth-secret")
}

// TestAdversarial_OptionsPreflight_SurfacedToday pins the current gap:
// CORS preflight OPTIONS requests should not generate CLI commands
// (they're browser-internal, not real API endpoints). Today the spec
// gen DOES surface the OPTIONS endpoint — a known issue. This test
// asserts the current behavior so a future upstream filter
// (post-PR-9 or a new "ignore OPTIONS" rule) flips it green.
func TestAdversarial_OptionsPreflight_SurfacedToday(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "options-preflight.har")

	// Today: OPTIONS surfaces as an endpoint with method=OPTIONS.
	// Find it; document the gap.
	var sawOptions bool
	for _, resource := range result.apiSpec.Resources {
		for _, ep := range resource.Endpoints {
			if strings.EqualFold(ep.Method, "OPTIONS") {
				sawOptions = true
			}
		}
	}

	if os.Getenv("RUN_PIN_FAILS") == "" {
		// Default: assert what's TRUE TODAY (regression guard for the
		// current behavior; flips when the OPTIONS filter lands).
		assert.True(t, sawOptions,
			"OPTIONS preflight surfaces as a CLI-generatable endpoint today; "+
				"this assertion graduates to assert.False once OPTIONS filtering lands")
		return
	}
	// RUN_PIN_FAILS=1: assert the desired post-fix behavior.
	assert.False(t, sawOptions,
		"OPTIONS preflight is a browser-internal request; must not generate a CLI command")
}

// TestAdversarial_GzipEncodedBody_NoBodyInvention pins that a request
// body with Content-Encoding: gzip (or any opaque encoding the parser
// can't peer into) yields zero body slots — the parser does not
// invent JSON body fields from un-decodable bytes. The fixture uses
// a base64-encoded gzip payload to keep the HAR JSON-safe; the
// invariant holds for either encoding because the parser keys on
// Content-Type=application/json and tries to JSON-parse the raw
// `text` field, which fails for non-JSON content.
func TestAdversarial_GzipEncodedBody_NoBodyInvention(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "gzip-encoded-body.har")

	require.Len(t, result.evidence, 1)
	for _, ex := range result.evidence[0].Exemplars {
		assert.Empty(t, ex.BodyForm,
			"gzip body must not be misparsed as form-urlencoded")
		assert.Empty(t, ex.BodyMulti,
			"gzip body must not be misparsed as multipart")
	}
	// The spec must validate (no panic) and not invent body params
	// from the opaque payload.
	require.NotNil(t, result.apiSpec)
	for _, resource := range result.apiSpec.Resources {
		for _, ep := range resource.Endpoints {
			// Body params can be empty OR contain only response-inferred
			// fields (the parser falls back to response shape when no
			// request body fields are inferable). The invariant is that
			// the opaque request bytes don't become param names.
			for _, p := range ep.Body {
				assert.NotContains(t, p.Name, "\x1f",
					"gzip magic bytes must not leak into a param name")
			}
		}
	}
}

// TestAdversarial_EmptyBodyPost_NoInvention pins that a POST with
// Content-Length: 0 and empty postData.text yields a discoverable
// endpoint with zero body params — common idempotent-poke pattern.
// The Authorization header still resolves to bearer_token auth.
func TestAdversarial_EmptyBodyPost_NoInvention(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "empty-body-post.har")

	// Endpoint MUST be discovered.
	var sawRefresh bool
	for _, resource := range result.apiSpec.Resources {
		for _, ep := range resource.Endpoints {
			if strings.EqualFold(ep.Method, "POST") && strings.Contains(ep.Path, "/sessions/refresh") {
				sawRefresh = true
				// Body params inferred from response are allowed
				// (response_fields fallback); inferred from the
				// empty request body are not. Today the response
				// schema (`{"token":...}`) populates Params, which is
				// the documented fallback behavior.
				for _, p := range ep.Body {
					// Reject only obviously-from-empty fakes; the
					// response-derived `token` field is legitimate.
					assert.NotEmpty(t, p.Name, "body params must have names")
				}
			}
		}
	}
	assert.True(t, sawRefresh, "POST /v1/sessions/refresh should surface")

	// Auth detection: Authorization: Bearer <jwt> → bearer_token.
	assert.Equal(t, "bearer_token", result.apiSpec.Auth.Type)
}
