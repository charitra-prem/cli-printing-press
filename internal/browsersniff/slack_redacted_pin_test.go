package browsersniff

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
)

// skipUnlessRunPinFails skips the test unless RUN_PIN_FAILS=1 is set in
// the environment. This keeps default `go test ./...` green (CI still
// passes) while letting the agent implementing PR N exercise the real
// assertion via `RUN_PIN_FAILS=1 go test ./internal/browsersniff/ -run
// TestPin_PRN`. The skip message documents the gap and the roadmap
// reference; the test body asserts the desired post-fix behavior.
func skipUnlessRunPinFails(t *testing.T, pr, gap string) {
	t.Helper()
	if os.Getenv("RUN_PIN_FAILS") == "" {
		t.Skipf("PIN: blocked by %s (%s). "+
			"Run with RUN_PIN_FAILS=1 to see the failing assertion. "+
			"See docs/brainstorms/2026-06-04-request-evidence-pr7-roadmap.md",
			pr, gap)
	}
}

// The tests in this file pin the five gaps surfaced by the 2026-06-04
// live Slack test (see docs/brainstorms/2026-06-04-request-evidence-
// pr7-roadmap.md). Each test runs against testdata/sniff/slack-redacted.
// har — a 5-entry, fully-redacted fixture that captures the wire shapes
// PRs 7-12 must handle. Tests are t.Skip'd today so CI stays green;
// the implementing agent removes the skip when starting the matching
// PR and the test must pass as part of that PR's acceptance.

const slackRedactedFixturePath = "../../testdata/sniff/slack-redacted.har"

func loadSlackRedactedSpec(t *testing.T) *spec.APISpec {
	t.Helper()
	abs, err := filepath.Abs(slackRedactedFixturePath)
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	capture, err := LoadCapture(abs)
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	apiSpec, err := AnalyzeCaptureWithOptions(capture, AnalyzeOptions{PreserveHosts: true})
	if err != nil {
		t.Fatalf("analyzing fixture: %v", err)
	}
	// Mirror the CLI pipeline (see request_evidence_matrix_test.go): the
	// reachability pass promotes cookie-auth on browser-clearance captures
	// and is where Auth.CookieDomain comes from for Slack-shaped fixtures.
	if trafficAnalysis, terr := AnalyzeTraffic(capture); terr == nil {
		ApplyReachabilityDefaults(apiSpec, trafficAnalysis)
	}
	return apiSpec
}

// PR 7 — body-field projection through the HAR path.
//
// The captured multipart POST /api/conversations.history body carries
// `token`, `channel`, `limit`, `oldest`, `cached_latest_updates` and
// 10 more form fields. They must reach spec.Endpoint.Body with
// ContentLocation: body_multipart and (for the xoxc-... token) the
// Classification: auth-secret tag. Today nothing reaches Endpoint.Body
// because parser.go::convertHAREntry doesn't synthesize RequestBody
// from HAR postData.text on the live HAR path.
func TestPin_PR7_BodyFieldsProjectedFromMultipartHARPath(t *testing.T) {
	t.Parallel()

	apiSpec := loadSlackRedactedSpec(t)
	endpoint := findEndpoint(t, apiSpec, "conversations.history", "POST", "/api/conversations.history")

	wantFields := []string{"token", "channel", "limit", "oldest"}
	have := map[string]spec.Param{}
	for _, p := range endpoint.Body {
		have[p.Name] = p
	}
	for _, name := range wantFields {
		p, ok := have[name]
		if !ok {
			t.Errorf("Endpoint.Body missing %q (have %v)", name, bodyParamNames(endpoint.Body))
			continue
		}
		if p.ContentLocation != spec.ParamLocationBodyMultipart {
			t.Errorf("Endpoint.Body[%q].ContentLocation = %q, want %q",
				name, p.ContentLocation, spec.ParamLocationBodyMultipart)
		}
	}

	tokenParam, ok := have["token"]
	if ok && tokenParam.Classification != spec.ParamClassAuthSecret {
		t.Errorf("Body[token].Classification = %q, want %q (xoxc-... is auth-secret-shaped)",
			tokenParam.Classification, spec.ParamClassAuthSecret)
	}
}

// PR 8 — reserved-name auto-rename.
//
// browser-sniff emits a `cache:` resource for /cache/<workspace>/
// permissions/info. generate then hard-errors at parse time because
// "cache" collides with the reserved press template. Either browser-
// sniff should auto-rename to cache_resource (collision-aware), or
// spec.applyReservedResourceParentPrefixes should handle bare reserved
// resources as a fallback before validateReservedNames.
func TestPin_PR8_ReservedCacheResourceAutoRenamed(t *testing.T) {
	t.Parallel()

	apiSpec := loadSlackRedactedSpec(t)
	if _, hit := apiSpec.Resources["cache"]; hit {
		t.Errorf("Resources still contains reserved-name %q; expected auto-rename to %q",
			"cache", "cache_resource")
	}
	if _, ok := apiSpec.Resources["cache_resource"]; !ok {
		t.Errorf("Resources missing %q after auto-rename (have %v)",
			"cache_resource", resourceNames(apiSpec))
	}
}

// PR 9 — volatile-slot suppression upstream of spec emission.
//
// The fixture's POST /api/conversations.history has volatile query
// params (_x_b3_traceid, _x_csid, _x_id, _x_version_ts, fp, etc.).
// They should be tagged volatile-drop by the classifier and kept in
// the evidence sidecar for audit, but NOT projected into
// Endpoint.Params, so they never become CLI flags / MCP tools / etc.
func TestPin_PR9_VolatileSlotsSuppressedFromEndpointParams(t *testing.T) {
	skipUnlessRunPinFails(t, "PR 9", "volatile-slot suppression upstream")
	t.Parallel()

	apiSpec := loadSlackRedactedSpec(t)
	endpoint := findEndpoint(t, apiSpec, "conversations.history", "POST", "/api/conversations.history")

	volatileNames := []string{
		"_x_b3_sampled", "_x_b3_spanid", "_x_b3_traceid",
		"_x_csid", "_x_id", "_x_version_ts",
		"_x_desktop_ia", "_x_frontend_build_type", "_x_gantry",
		"_x_num_retries", "fp",
	}
	have := map[string]struct{}{}
	for _, p := range endpoint.Params {
		have[p.Name] = struct{}{}
	}
	for _, n := range volatileNames {
		if _, hit := have[n]; hit {
			t.Errorf("Endpoint.Params still contains volatile slot %q; classifier "+
				"identified it as volatile-drop but specgen projected it anyway", n)
		}
	}
}

// PR 10 — cookie-domain inference via publicsuffix.
//
// detectCapturedAuth binds CookieDomain to .edgeapi.slack.com — one
// captured subdomain. The Slack session cookie is shared across
// *.slack.com; press-auth's Chrome jar lookup needs the registrable
// root. publicsuffix.EffectiveTLDPlusOne already imported by
// analysis.go:1311; apply the same reduction here.
func TestPin_PR10_CookieDomainReducedToRegistrableRoot(t *testing.T) {
	t.Parallel()

	apiSpec := loadSlackRedactedSpec(t)
	got := apiSpec.Auth.CookieDomain
	want := ".slack.com"
	if got != want {
		t.Errorf("Auth.CookieDomain = %q, want %q (registrable root via "+
			"publicsuffix.EffectiveTLDPlusOne)", got, want)
	}
}

// PR 11 (foreshadow) — the redacted fixture is the regression bed
// for the overlayEvidenceRequestShape pass. Once PR 7 + PR 9 + PR 11
// land, this test pins that the generator's in-memory spec, after
// applyRequestEvidence, has the right per-endpoint shape sourced from
// the sidecar (not just BaseURL). The actual assertion lives in
// internal/generator/slack_redacted_pin_test.go because that's where
// the generator-side overlay runs; this file only covers the upstream
// (browsersniff) projection.

// ====================================================================
// Cross-fixture safety tests. These catch the failure mode where a
// "fix for Slack" silently misclassifies a non-Slack API. PR 9 and
// PR 10 are the two PRs that carry over-correction risk; each gets a
// paired test against the synthetic tickets fixture.
// ====================================================================

const ticketsSyntheticFixturePath = "../../testdata/sniff/tickets-synthetic.har"

func loadTicketsSyntheticSpec(t *testing.T) *spec.APISpec {
	t.Helper()
	abs, err := filepath.Abs(ticketsSyntheticFixturePath)
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	capture, err := LoadCapture(abs)
	if err != nil {
		t.Fatalf("loading fixture: %v", err)
	}
	apiSpec, err := AnalyzeCaptureWithOptions(capture, AnalyzeOptions{PreserveHosts: true})
	if err != nil {
		t.Fatalf("analyzing fixture: %v", err)
	}
	if trafficAnalysis, terr := AnalyzeTraffic(capture); terr == nil {
		ApplyReachabilityDefaults(apiSpec, trafficAnalysis)
	}
	return apiSpec
}

// PR 9 safety — synthetic ticketing API. Volatile-by-constancy params
// (request_id, trace_id, correlation_id vary per request → drop) must
// be dropped here too, BUT semantically-meaningful params with names
// that overlap Slack's volatile vocabulary (app_name, mode) must be
// KEPT. If PR 9's classifier identifies volatile by name pattern only
// (e.g. "any _x_app_name is volatile-drop"), this test fires because
// app_name in this fixture is a meaningful semantic-default that
// shouldn't disappear from the CLI.
func TestPin_PR9_Safety_SyntheticAPIKeepsSemanticParams(t *testing.T) {
	skipUnlessRunPinFails(t, "PR 9 (safety)", "synthetic API keeps semantic params")
	t.Parallel()

	apiSpec := loadTicketsSyntheticSpec(t)
	endpoint := findEndpoint(t, apiSpec, "tickets", "POST", "/v1/tickets/create")

	mustKeep := []string{"app_name", "mode"}
	have := map[string]struct{}{}
	for _, p := range endpoint.Params {
		have[p.Name] = struct{}{}
	}
	for _, n := range mustKeep {
		if _, hit := have[n]; !hit {
			t.Errorf("Endpoint.Params lost %q in synthetic non-Slack fixture; "+
				"classifier over-triggered on name pattern alone", n)
		}
	}

	// And the genuinely-volatile ones (vary per request, names match
	// universal tracing convention) must still drop.
	mustDrop := []string{"request_id", "trace_id", "correlation_id"}
	for _, n := range mustDrop {
		if _, hit := have[n]; hit {
			t.Errorf("Endpoint.Params kept %q in synthetic fixture; "+
				"per-request varying values should be volatile-drop", n)
		}
	}
}

// PR 9 safety — body fields stay required. The synthetic fixture's
// multipart body has title, body, priority, category. None overlap
// Slack vocabulary, so a name-pattern classifier shouldn't trigger.
// If PR 9 accidentally extends a too-broad name pattern to body
// fields, mandatory user-supplied params would silently vanish.
func TestPin_PR9_Safety_SyntheticBodyFieldsPreserved(t *testing.T) {
	skipUnlessRunPinFails(t, "PR 9 (safety)", "synthetic body fields preserved")
	t.Parallel()

	apiSpec := loadTicketsSyntheticSpec(t)
	endpoint := findEndpoint(t, apiSpec, "tickets", "POST", "/v1/tickets/create")

	want := []string{"title", "body", "priority", "category"}
	have := map[string]struct{}{}
	for _, p := range endpoint.Body {
		have[p.Name] = struct{}{}
	}
	for _, n := range want {
		if _, hit := have[n]; !hit {
			t.Errorf("Endpoint.Body missing %q in synthetic fixture (have %v); "+
				"PR 9 classifier dropped a meaningful body field",
				n, bodyParamNames(endpoint.Body))
		}
	}
}

// PR 10 safety — synthetic fixture's host (api.tickets.example) is
// already a registrable root; publicsuffix reduction must be a no-op.
// If the reducer is too eager (e.g. drops the api. subdomain on
// anything api-prefixed), this fires.
func TestPin_PR10_Safety_AlreadyRegistrableRootIsNoop(t *testing.T) {
	t.Parallel()

	apiSpec := loadTicketsSyntheticSpec(t)
	got := apiSpec.Auth.CookieDomain
	// Synthetic uses bearer auth, so CookieDomain is empty — no
	// reduction to perform. Test fails if PR 10's reducer somehow
	// invents a domain for a non-cookie-auth capture.
	if got != "" {
		t.Errorf("Auth.CookieDomain = %q on bearer-auth synthetic fixture; "+
			"want empty (PR 10's reducer must skip non-cookie auth)", got)
	}
}

// PR 7 safety — body extraction works for non-multipart and non-Slack
// shapes too. Today both fixtures' body fields don't reach Endpoint.Body
// via the HAR path; PR 7 must fix both.
func TestPin_PR7_Safety_SyntheticBodyAlsoProjected(t *testing.T) {
	t.Parallel()

	apiSpec := loadTicketsSyntheticSpec(t)
	endpoint := findEndpoint(t, apiSpec, "tickets", "POST", "/v1/tickets/create")

	if len(endpoint.Body) == 0 {
		t.Fatalf("Endpoint.Body is empty for synthetic multipart endpoint; "+
			"PR 7 only fixed the Slack-shaped case (test exists to catch that). "+
			"Have %d Params: %v", len(endpoint.Params), paramNamesFromParams(endpoint.Params))
	}
}

func paramNamesFromParams(params []spec.Param) []string {
	out := make([]string, 0, len(params))
	for _, p := range params {
		out = append(out, fmt.Sprintf("%s(%s)", p.Name, p.ContentLocation))
	}
	return out
}

// --- helpers ----------------------------------------------------------

func findEndpoint(t *testing.T, apiSpec *spec.APISpec, resourceName, method, path string) spec.Endpoint {
	t.Helper()
	res, ok := apiSpec.Resources[resourceName]
	if !ok {
		t.Fatalf("Resources missing %q (have %v)", resourceName, resourceNames(apiSpec))
	}
	for _, ep := range res.Endpoints {
		if strings.EqualFold(ep.Method, method) && ep.Path == path {
			return ep
		}
	}
	t.Fatalf("resource %q has no %s %s endpoint", resourceName, method, path)
	return spec.Endpoint{}
}

func bodyParamNames(params []spec.Param) []string {
	out := make([]string, 0, len(params))
	for _, p := range params {
		out = append(out, p.Name)
	}
	return out
}

func resourceNames(apiSpec *spec.APISpec) []string {
	out := make([]string, 0, len(apiSpec.Resources))
	for k := range apiSpec.Resources {
		out = append(out, k)
	}
	return out
}
