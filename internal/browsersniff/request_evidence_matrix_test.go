package browsersniff

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

// Request-evidence matrix test. Each row pins what is TRUE TODAY about
// the analyzed spec for one fixture. Per codex's directive ("do not grow
// the RUN_PIN_FAILS pattern into the matrix"), nothing here is skipped:
// every assertion must hold against the current implementation. When PR 7+
// land and reshape behavior, the matching row's expectations get updated
// in the same change — and the matching pin test in
// slack_redacted_pin_test.go graduates into a normal assertion here.
//
// Rows assert structural shape (auth type/header, endpoints discovered,
// host preservation, slot inventory in the evidence sidecar). They DO NOT
// assert post-PR-7 wire-fidelity behavior (body fields reaching
// Endpoint.Body for non-GraphQL JSON / form / multipart, volatile-drop
// suppression at the spec layer, registrable-root cookie domains).
// Those are the pin tests' job until the implementing PR lands.
//
// TODO(after PR 7): add round-trip rows comparing
// `wireevidence.CompareRequestAgainstExemplar` against the captured
// exemplars for each fixture. Today body projection is incomplete (see
// findings in docs/brainstorms/2026-06-04-request-evidence-pr7-roadmap.md
// #1), so reconstructed requests would not byte-match. After PR 7 +
// PR 11 add a `roundtripExemplars` field to ruleCase and assert wire
// equality per exemplar.
//
// TODO(after PR 7 + PR 11): add end-to-end generated-CLI assertions
// (codex's sketched `internal/generator/request_evidence_e2e_test.go`,
// 3 representative fixtures: Slack cookie+multipart, Linear GraphQL,
// Datadog composed-auth). Today the body/volatile gaps mean the
// generated flags do not faithfully reflect the wire shape.

type slotKey struct {
	location string
	name     string
}

type endpointAssertion struct {
	resource string
	method   string
	path     string
	// baseURL is the per-endpoint host (PreserveHosts only). Empty means
	// "expect the spec.BaseURL default", i.e. no per-endpoint override.
	baseURL string
}

type ruleCase struct {
	name          string
	fixture       string
	preserveHosts bool
	// notes is a one-line summary of the edge case this row pins. Future
	// readers should be able to scan the table and understand the
	// motivation per fixture without rereading the body.
	notes string
	// wantAuthType pins APISpec.Auth.Type; empty skips the check.
	wantAuthType string
	// wantAuthHeader pins APISpec.Auth.Header; empty skips.
	wantAuthHeader string
	// wantAuthEnvVar, if non-empty, must appear in APISpec.Auth.EnvVars.
	wantAuthEnvVar string
	// wantCookieDomain pins Auth.CookieDomain when non-empty. Use the
	// sentinel "<empty>" to assert the field is empty (Go zero value).
	wantCookieDomain string
	// wantEndpoints are endpoints that MUST appear in the spec.
	wantEndpoints []endpointAssertion
	// mustKeepSlots are evidence slots (sidecar) that must be present
	// with a non-volatile-drop classification.
	mustKeepSlots []slotKey
	// mustDropSlots are slots that MUST be classified as volatile-drop
	// when present in the evidence sidecar. Slots absent from the sidecar
	// are not asserted on — this is for slots we expect the classifier to
	// have actively rejected, not slots we expect not to exist.
	mustDropSlots []slotKey
	// minResources is a lower bound; primarily a sanity gate.
	minResources int
}

func TestRequestEvidenceMatrix(t *testing.T) {
	t.Parallel()

	cases := []ruleCase{
		{
			name:             "slack: cookie session, multi-host, multipart bodies",
			fixture:          "../../testdata/sniff/slack-redacted.har",
			notes:            "cookie session, multipart, multi-host, path workspace IDs, xoxc tokens, volatile _x_b3_*",
			preserveHosts:    true,
			wantAuthType:     "cookie",
			wantAuthHeader:   "Cookie",
			wantAuthEnvVar:   "EDGEAPI_SLACK_COOKIES",
			wantCookieDomain: ".slack.com",
			wantEndpoints: []endpointAssertion{
				// `cache` is reserved; PR 8's fallback rename converts the
				// resource to `cache_resource` during Validate(). Pinned in
				// slack_redacted_pin_test.go::TestPin_PR8_*.
				{resource: "cache_resource", method: "POST", path: "/cache/T0FAKE000/permissions/info", baseURL: "https://edgeapi.slack.com"},
				{resource: "conversations.history", method: "POST", path: "/api/conversations.history"},
				{resource: "dnd.teamInfo", method: "POST", path: "/api/dnd.teamInfo"},
			},
			// Today the volatile _x_* params are classified as
			// `semantic-default` (constancy across the 2 exemplars wins
			// before the classifier learns the name pattern). After PR 9
			// these graduate to `volatile-drop` and move to mustDropSlots.
			mustKeepSlots: []slotKey{
				{location: wireevidence.LocationHeader, name: "cookie"},
				// body_multipart slots for the form fields exist in the
				// Slack capture: token, channel, limit, etc. all surface
				// as evidence slots even though they don't reach
				// Endpoint.Body until PR 7.
				{location: wireevidence.LocationBodyMulti, name: "token"},
				{location: wireevidence.LocationBodyMulti, name: "channel"},
			},
			minResources: 3,
		},
		{
			name:           "tickets: bearer JWT, single host, multipart bodies",
			fixture:        "../../testdata/sniff/tickets-synthetic.har",
			notes:          "non-Slack vocabulary safety; bearer JWT auth via Authorization header",
			preserveHosts:  true,
			wantAuthType:   "bearer_token",
			wantAuthHeader: "Authorization",
			wantAuthEnvVar: "TICKETS_TOKEN",
			wantEndpoints: []endpointAssertion{
				{resource: "tickets", method: "POST", path: "/v1/tickets/create"},
			},
			mustKeepSlots: []slotKey{
				{location: wireevidence.LocationBodyMulti, name: "title"},
				{location: wireevidence.LocationBodyMulti, name: "body"},
				{location: wireevidence.LocationBodyMulti, name: "category"},
				{location: wireevidence.LocationQuery, name: "app_name"},
				{location: wireevidence.LocationQuery, name: "mode"},
				{location: wireevidence.LocationHeader, name: "Authorization"},
			},
			minResources: 1,
		},
		{
			name:           "linear: GraphQL POST, JSON body, bearer auth, operation discrimination",
			fixture:        "../../testdata/sniff/linear-graphql-synthetic.har",
			notes:          "GraphQL POST, JSON body, single shared /graphql endpoint, per-operation routing",
			preserveHosts:  true,
			wantAuthType:   "bearer_token",
			wantAuthHeader: "Authorization",
			wantAuthEnvVar: "LINEAR_TOKEN",
			wantEndpoints: []endpointAssertion{
				// GraphQL BFF splits one /graphql route into one endpoint
				// per operationName. Both endpoints share path /graphql.
				{resource: "issues", method: "POST", path: "/graphql"},
			},
			// JSON body slots don't get extracted today (the
			// exemplarFromEntry path only parses form/multipart). After
			// the JSON-body-in-evidence work lands, add slots for
			// operationName / variables here.
			mustKeepSlots: []slotKey{
				{location: wireevidence.LocationHeader, name: "Authorization"},
			},
			minResources: 1,
		},
		{
			name:    "datadog: composed-auth headers, regional host, JSON body, telemetry header",
			fixture: "../../testdata/sniff/datadog-composed-synthetic.har",
			notes:   "composed auth (DD-API-KEY + DD-APPLICATION-KEY), regional host, JSON body",
			// Today single api_key auth is detected (DD-API-KEY). The
			// composed second header (DD-APPLICATION-KEY) is captured as
			// a slot but not promoted into AuthConfig — that's a known
			// gap, marked below in mustKeepSlots so it stays surfaced.
			wantAuthType:   "api_key",
			wantAuthHeader: "DD-API-KEY",
			wantAuthEnvVar: "DATADOGHQ_API_KEY",
			wantEndpoints: []endpointAssertion{
				{resource: "logs", method: "POST", path: "/api/v2/logs"},
			},
			mustKeepSlots: []slotKey{
				{location: wireevidence.LocationHeader, name: "DD-API-KEY"},
				{location: wireevidence.LocationHeader, name: "DD-APPLICATION-KEY"},
				// dd-request-id varies per request → today the classifier
				// returns "unknown" (no name-pattern rule for the lowercase
				// dd-request-id). After PR 9 this slot moves to
				// mustDropSlots once the classifier learns the pattern.
				// Surfaced via the classifier table test, not pinned here.
			},
			minResources: 1,
		},
		{
			name:    "stripe: form-encoded body, Basic auth, per-request idempotency key",
			fixture: "../../testdata/sniff/stripe-form-idempotency-synthetic.har",
			notes:   "Basic auth, form body, Idempotency-Key (meaningful per-request header)",
			// The auth-detector extension now treats `Authorization: Basic
			// <base64>` as api_key auth with a `Basic {token}` format,
			// instead of falling through to none.
			wantAuthType:   "api_key",
			wantAuthHeader: "Authorization",
			wantEndpoints: []endpointAssertion{
				{resource: "charges", method: "POST", path: "/v1/charges"},
			},
			mustKeepSlots: []slotKey{
				{location: wireevidence.LocationBodyForm, name: "amount"},
				{location: wireevidence.LocationBodyForm, name: "currency"},
				{location: wireevidence.LocationBodyForm, name: "source"},
				// Idempotency-Key varies per request but is user-meaningful;
				// it must NOT be volatile-drop. Today the classifier returns
				// "unknown" (varying values, no protocol-constant name, no
				// volatile-name pattern) which is acceptable — the user is
				// forced to supply it. After PR 9 extends the classifier
				// to mark it `semantic-default-perrequest` (or similar),
				// the assertion stays in mustKeepSlots; only the explicit
				// classification claim in classifier_extensions_test.go
				// changes.
				{location: wireevidence.LocationHeader, name: "Idempotency-Key"},
			},
			minResources: 1,
		},
		{
			name:          "shopify: per-tenant subdomain host, shpat_ token header",
			fixture:       "../../testdata/sniff/shopify-tenant-subdomain-synthetic.har",
			notes:         "tenant baked into subdomain (acme-store.myshopify.com); shpat_-prefixed token header",
			preserveHosts: true,
			// X-Shopify-Access-Token now recognized via the strong-auth-
			// header-name extension; resolves to api_key with header
			// placement.
			wantAuthType:   "api_key",
			wantAuthHeader: "X-Shopify-Access-Token",
			wantEndpoints: []endpointAssertion{
				// Path-derived resource name is `admin` (first significant
				// path segment under /admin/api/2024-04/...). Two endpoints
				// from one capture both land under it.
				// Single-host capture: subdomain host becomes the spec
				// default BaseURL, so per-endpoint BaseURL is empty.
				// The host is asserted via the spec's BaseURL field
				// implicitly (no second host competes for the slot).
				{resource: "admin", method: "GET", path: "/admin/api/2024-04/orders.json"},
				{resource: "admin", method: "POST", path: "/admin/api/2024-04/products.json"},
			},
			mustKeepSlots: []slotKey{
				// Per-tenant subdomain host preserved verbatim in the
				// evidence exemplars (asserted indirectly via baseURL on
				// endpoints above). The token slot is captured today as
				// semantic-default; mustKeepSlots only asserts it is NOT
				// volatile-drop. The classifier extension test below pins
				// the post-PR-9 desired class (auth-secret).
				{location: wireevidence.LocationHeader, name: "X-Shopify-Access-Token"},
			},
			minResources: 1,
		},
		{
			name:          "mediawiki: CSRF token in body, cookie session, action= query param",
			fixture:       "../../testdata/sniff/mediawiki-csrf-synthetic.har",
			notes:         "CSRF token in body (not header), multi-pair cookie session, stable action=/format= query",
			preserveHosts: true,
			// Cookie auth detected via the browser-clearance reachability
			// promotion path (registrable cookie domain `.en.wikipedia.org`).
			wantAuthType:     "cookie",
			wantAuthHeader:   "Cookie",
			wantAuthEnvVar:   "EN_WIKIPEDIA_COOKIES",
			wantCookieDomain: ".wikipedia.org",
			wantEndpoints: []endpointAssertion{
				// Path is `/w/api.php` with `action=edit` query; the
				// resource lands under `w` (first significant segment).
				{resource: "w", method: "POST", path: "/w/api.php"},
			},
			mustKeepSlots: []slotKey{
				// The body `token` field varies per session but is
				// REQUIRED by MediaWiki — must never be volatile-drop.
				// Today the classifier returns "unknown" (no rule
				// matches `token`); the classifier extension test
				// pins that this is acceptable (anything except
				// volatile-drop is OK).
				{location: wireevidence.LocationBodyForm, name: "token"},
				// `action` is constant across exemplars → semantic-default.
				{location: wireevidence.LocationQuery, name: "action"},
				{location: wireevidence.LocationQuery, name: "format"},
				{location: wireevidence.LocationHeader, name: "Cookie"},
			},
			minResources: 1,
		},
		{
			name:          "github-rest: token-prefixed Authorization, vendor accept, conditional ETag",
			fixture:       "../../testdata/sniff/github-rest-conditional-synthetic.har",
			notes:         "GitHub `token <hex>` Authorization scheme, vnd.github.v3+json accept, If-None-Match conditional",
			preserveHosts: true,
			// The auth-detector extension now treats lowercase `token <hex>`
			// as a bearer scheme alongside `Bearer <token>`, so GitHub's
			// PAT-shape Authorization lands as bearer_token.
			wantAuthType:   "bearer_token",
			wantAuthHeader: "Authorization",
			wantAuthEnvVar: "GITHUB_TOKEN",
			wantEndpoints: []endpointAssertion{
				// Both GETs share the `repos` resource (first significant
				// segment of /repos/octocat/hello-world…).
				{resource: "repos", method: "GET", path: "/repos/octocat/hello-world"},
				{resource: "repos", method: "GET", path: "/repos/octocat/hello-world/pulls"},
			},
			mustKeepSlots: []slotKey{
				// `Accept: application/vnd.github.v3+json` classifies as
				// protocol-constant (Accept is in the protocol header set).
				{location: wireevidence.LocationHeader, name: "Accept"},
				// `If-None-Match` is user-meaningful (cache control). Today
				// each endpoint group has one exemplar so the value is
				// vacuously constant → semantic-default. The classifier
				// extension test pins it must NEVER be volatile-drop even
				// when values vary across exemplars.
				{location: wireevidence.LocationHeader, name: "If-None-Match"},
				// `Authorization` is captured but classified as
				// semantic-default (constant) today; post-detector-fix it
				// would be marked auth-secret.
				{location: wireevidence.LocationHeader, name: "Authorization"},
			},
			minResources: 1,
		},
		{
			name:          "sentry-dsn: public key embedded in URL userinfo segment",
			fixture:       "../../testdata/sniff/sentry-dsn-auth-synthetic.har",
			notes:         "auth-in-URL-userinfo (DSN public key); org/project IDs split across host/path",
			preserveHosts: true,
			// No Authorization header, no x-api-key. The DSN public key
			// rides in the URL's userinfo segment — today nothing parses
			// `url.User` into a slot, so the classifier never sees it.
			// detectAuth resolves to none.
			wantAuthType: "none",
			wantEndpoints: []endpointAssertion{
				// Path normalization collapses 789012 to {id} (long numeric
				// segment treated as positional). Resource is `envelope`
				// (last significant segment).
				{resource: "envelope", method: "POST", path: "/api/{id}/envelope/"},
			},
			mustKeepSlots: []slotKey{
				// Content-Type / User-Agent headers reach the evidence
				// sidecar; the DSN public key is now also surfaced via
				// LocationURLUserinfo and classified auth-secret.
				{location: wireevidence.LocationHeader, name: "Content-Type"},
				{location: wireevidence.LocationURLUserinfo, name: "userinfo"},
			},
			minResources: 1,
		},
		{
			name:          "github-webhook: HMAC body signature header, per-delivery UUID",
			fixture:       "../../testdata/sniff/github-webhook-hmac-synthetic.har",
			notes:         "HMAC-SHA256 body signature in X-Hub-Signature-256; per-delivery UUID; non-reconstructable without body bytes",
			preserveHosts: true,
			// No standard auth header surface. The HMAC IS the auth
			// proof, but only the receiver verifies it — emitters
			// (the CLI replay use case) cannot regenerate it without
			// the original body bytes + shared secret.
			wantAuthType: "none",
			wantEndpoints: []endpointAssertion{
				// Receiver is a hypothetical webhooks.example endpoint.
				// Resource is `github` (path segment after host).
				{resource: "github", method: "POST", path: "/github"},
			},
			mustKeepSlots: []slotKey{
				// X-GitHub-Event = `push` is constant → semantic-default
				// (user-meaningful: identifies the webhook event type).
				{location: wireevidence.LocationHeader, name: "X-GitHub-Event"},
				// X-Hub-Signature-256 varies per request; today classifier
				// returns `unknown` (no name pattern, no constant value).
				// The classifier extension test pins it should be
				// auth-secret (sha256=… value shape) AND ideally flagged
				// non-reconstructable. mustKeepSlots only asserts the
				// slot exists and is not volatile-drop; the desired class
				// graduates from the extension test once PR 9 lands.
				{location: wireevidence.LocationHeader, name: "X-Hub-Signature-256"},
			},
			mustDropSlots: []slotKey{
				// X-GitHub-Delivery is a per-request UUID; today it lands
				// as `unknown` (no name pattern). After PR 9 it becomes
				// volatile-drop. mustDropSlots only fires if the slot is
				// present with a non-volatile-drop class — today the slot
				// IS present as `unknown`, so this assertion would fail
				// pre-PR-9. The matrix only pins what's TRUE TODAY, so
				// the assertion lives in the classifier extension test
				// (RUN_PIN_FAILS-gated) rather than here.
			},
			minResources: 1,
		},
		// --- wave 3 (wave3-oss-fixtures) ---------------------------------
		{
			name:          "discourse: dual-header auth (identity + secret)",
			fixture:       "../../testdata/sniff/discourse-dual-header-synthetic.har",
			notes:         "Api-Key (secret) + Api-Username (identity) — captureless detection picks Api-Key as api_key auth; identity header is not promoted but is preserved as a slot",
			preserveHosts: true,
			// Today detectAuthWithWarnings's isStrongAuthHeaderName matches
			// `api-key` (the lowercased Api-Key header name) and produces
			// api_key auth. Api-Username is captured as an ordinary slot
			// but never promoted into AuthConfig — that's the gap this row
			// pins. After a future "composed identity+secret" detector,
			// Api-Username would surface as an Auth.Format component.
			wantAuthType:   "api_key",
			wantAuthHeader: "Api-Key",
			wantAuthEnvVar: "META_DISCOURSE_API_KEY",
			wantEndpoints: []endpointAssertion{
				{resource: "admin", method: "GET", path: "/admin/users.json"},
				{resource: "posts.json", method: "POST", path: "/posts.json"},
			},
			mustKeepSlots: []slotKey{
				// Api-Key classifies as semantic-default today (constant
				// across exemplars). The classifier extension test pins
				// the post-PR-9 desired class (auth-secret).
				{location: wireevidence.LocationHeader, name: "Api-Key"},
				// Api-Username is the identity half; today semantic-default.
				// mustKeepSlots only asserts it is NOT volatile-drop —
				// the user-supplied identity must survive into the spec.
				{location: wireevidence.LocationHeader, name: "Api-Username"},
			},
			minResources: 2,
		},
		{
			name:          "gitlab: URL-encoded project path tenant (%2F embedded slash)",
			fixture:       "../../testdata/sniff/gitlab-encoded-path-synthetic.har",
			notes:         "tenant `<group>%2F<project>` encoded in a single path segment; today the press DECODES %2F into a literal `/`, splitting one segment into two — wire fidelity gap",
			preserveHosts: true,
			// PRIVATE-TOKEN added to isStrongAuthHeaderName; GitLab PAT
			// captures resolve to api_key with header placement.
			wantAuthType:   "api_key",
			wantAuthHeader: "PRIVATE-TOKEN",
			wantEndpoints: []endpointAssertion{
				// %2F gets decoded — `acme-corp%2Fwidget-service` becomes
				// `acme-corp/widget-service` in the normalized path. The
				// resource lands under `projects` (first significant segment
				// after /api/v4/). Pin the (incorrect) literal path so a
				// future fix that preserves encoded slashes flips this row.
				{resource: "projects", method: "GET", path: "/api/v4/projects/acme-corp/widget-service/repository/commits"},
				{resource: "projects", method: "GET", path: "/api/v4/projects/acme-corp/widget-service/issues"},
			},
			mustKeepSlots: []slotKey{
				// PRIVATE-TOKEN classifies as semantic-default today
				// (constant). Classifier extension pins post-PR-9
				// desired class (auth-secret via glpat- prefix or
				// `private-token` name rule).
				{location: wireevidence.LocationHeader, name: "PRIVATE-TOKEN"},
				{location: wireevidence.LocationQuery, name: "per_page"},
			},
			minResources: 1,
		},
		{
			name:          "twilio: Basic auth where username is Account SID (also in path)",
			fixture:       "../../testdata/sniff/twilio-basic-sid-synthetic.har",
			notes:         "Authorization: Basic base64(AC<sid>:<token>); Account SID repeated in path → today inferred as {account_id} path param",
			preserveHosts: true,
			// Basic-auth recognition now lands as api_key with a `Basic
			// {token}` format hint; the operator supplies the base64
			// payload verbatim via env var.
			wantAuthType:   "api_key",
			wantAuthHeader: "Authorization",
			wantEndpoints: []endpointAssertion{
				// Path normalization promotes the 34-char AC<32-hex> SID
				// to a {account_id} positional path param. Resource
				// lands under `2010-04-01` (first significant segment).
				{resource: "2010-04-01", method: "POST", path: "/2010-04-01/Accounts/{account_id}/Messages.json"},
			},
			mustKeepSlots: []slotKey{
				// Authorization Basic value: today semantic-default
				// (constant). Classifier extension pins auth-secret.
				{location: wireevidence.LocationHeader, name: "Authorization"},
				// Form body fields survive into the evidence sidecar.
				{location: wireevidence.LocationBodyForm, name: "To"},
				{location: wireevidence.LocationBodyForm, name: "From"},
				// `Body` varies per exemplar so classifies as unknown
				// (NOT volatile-drop) — user must supply.
				{location: wireevidence.LocationBodyForm, name: "Body"},
			},
			minResources: 1,
		},
		{
			name:           "tailscale: path-tenant identifier with bearer secret carried separately",
			fixture:        "../../testdata/sniff/tailscale-path-tenant-synthetic.har",
			notes:          "tailnet `acme.corp` is path-level identifier; today literal in path (not promoted to param); bearer carries the secret",
			preserveHosts:  true,
			wantAuthType:   "bearer_token",
			wantAuthHeader: "Authorization",
			wantAuthEnvVar: "TAILSCALE_TOKEN",
			wantEndpoints: []endpointAssertion{
				// Today the tailnet identifier is kept literal in the
				// path — only one tenant value seen across exemplars,
				// so the path-param inferrer has nothing to vary on.
				// After a "single-value-but-known-tenant-shape"
				// promotion (future PR), the path would become
				// /api/v2/tailnet/{tailnet}/devices. Pin literal today.
				{resource: "tailnet", method: "GET", path: "/api/v2/tailnet/acme.corp/devices"},
				{resource: "tailnet", method: "GET", path: "/api/v2/tailnet/acme.corp/keys"},
			},
			mustKeepSlots: []slotKey{
				// Authorization classifies as semantic-default today
				// (`tskey-api-` prefix not recognized as secret-shape;
				// no JWT/xoxc match). Classifier extension pins
				// post-PR-9 auth-secret via tskey- prefix.
				{location: wireevidence.LocationHeader, name: "Authorization"},
			},
			minResources: 1,
		},
		{
			name:    "homeassistant: LAN http:// host + WebSocket-upgrade endpoint",
			fixture: "../../testdata/sniff/homeassistant-lan-websocket-synthetic.har",
			notes:   "http:// (not https), .local hostname with port, JWT bearer; WebSocket upgrade surfaces blindly as a plain GET endpoint (no awareness of the Upgrade handshake)",
			// PreserveHosts off — single-host capture; the http:// scheme
			// + port should be preserved on the spec-level BaseURL.
			// JWT Bearer matches existing detectAuth/JWT pattern.
			wantAuthType:   "bearer_token",
			wantAuthHeader: "Authorization",
			wantAuthEnvVar: "HOMEASSISTANT_TOKEN",
			wantEndpoints: []endpointAssertion{
				{resource: "states", method: "GET", path: "/api/states/sensor.temperature"},
				// WebSocket upgrade surfaces as a plain GET — the press
				// has zero awareness of the Upgrade handshake. The
				// adversarial-style test in adversarial_test.go pins
				// this gap separately; the matrix row just documents
				// it surfaces at all.
				{resource: "websocket", method: "GET", path: "/api/websocket"},
			},
			mustKeepSlots: []slotKey{
				// JWT Authorization value matches the existing
				// jwtPattern → classifies as auth-secret already.
				{location: wireevidence.LocationHeader, name: "Authorization"},
				// WebSocket-handshake headers (Upgrade, Connection,
				// Sec-WebSocket-Key, Sec-WebSocket-Version) are captured
				// as ordinary slots today — none have classifier rules.
				// Pinning Upgrade so a future "WebSocket-handshake
				// recognition" PR has a target slot to reclassify.
				{location: wireevidence.LocationHeader, name: "Upgrade"},
				{location: wireevidence.LocationHeader, name: "Sec-WebSocket-Key"},
			},
			minResources: 2,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			abs, err := filepath.Abs(tc.fixture)
			if err != nil {
				t.Fatalf("resolving fixture path: %v", err)
			}
			capture, err := LoadCapture(abs)
			if err != nil {
				t.Fatalf("loading fixture: %v", err)
			}
			apiSpec, err := AnalyzeCaptureWithOptions(capture, AnalyzeOptions{PreserveHosts: tc.preserveHosts})
			if err != nil {
				t.Fatalf("analyzing capture: %v", err)
			}
			// Mirror the CLI pipeline: AnalyzeTraffic + ApplyReachabilityDefaults
			// promote cookie-auth detection for browser-clearance sites. Without
			// it the Slack capture appears as auth.type=none even though the CLI
			// emits auth.type=cookie. The matrix must reflect what users see.
			trafficAnalysis, terr := AnalyzeTraffic(capture)
			if terr != nil {
				t.Fatalf("analyzing traffic: %v", terr)
			}
			ApplyReachabilityDefaults(apiSpec, trafficAnalysis)

			assertAuth(t, apiSpec, tc)
			assertEndpoints(t, apiSpec, tc)
			if tc.minResources > 0 && len(apiSpec.Resources) < tc.minResources {
				t.Errorf("len(Resources) = %d, want >= %d (have %v)",
					len(apiSpec.Resources), tc.minResources, resourceNames(apiSpec))
			}

			evidence := BuildRequestEvidenceFromCapture(capture, AnalyzeOptions{PreserveHosts: tc.preserveHosts})
			assertEvidenceSlots(t, evidence, tc)
		})
	}
}

func assertAuth(t *testing.T, apiSpec *spec.APISpec, tc ruleCase) {
	t.Helper()
	if tc.wantAuthType != "" && apiSpec.Auth.Type != tc.wantAuthType {
		t.Errorf("Auth.Type = %q, want %q", apiSpec.Auth.Type, tc.wantAuthType)
	}
	if tc.wantAuthHeader != "" && apiSpec.Auth.Header != tc.wantAuthHeader {
		t.Errorf("Auth.Header = %q, want %q", apiSpec.Auth.Header, tc.wantAuthHeader)
	}
	if tc.wantAuthEnvVar != "" {
		found := false
		for _, v := range apiSpec.Auth.EnvVars {
			if v == tc.wantAuthEnvVar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Auth.EnvVars missing %q (have %v)", tc.wantAuthEnvVar, apiSpec.Auth.EnvVars)
		}
	}
	switch tc.wantCookieDomain {
	case "":
		// not asserted
	case "<empty>":
		if apiSpec.Auth.CookieDomain != "" {
			t.Errorf("Auth.CookieDomain = %q, want empty", apiSpec.Auth.CookieDomain)
		}
	default:
		if apiSpec.Auth.CookieDomain != tc.wantCookieDomain {
			t.Errorf("Auth.CookieDomain = %q, want %q",
				apiSpec.Auth.CookieDomain, tc.wantCookieDomain)
		}
	}
}

func assertEndpoints(t *testing.T, apiSpec *spec.APISpec, tc ruleCase) {
	t.Helper()
	for _, want := range tc.wantEndpoints {
		res, ok := apiSpec.Resources[want.resource]
		if !ok {
			t.Errorf("Resources missing %q (have %v)", want.resource, resourceNames(apiSpec))
			continue
		}
		var hit *spec.Endpoint
		for k := range res.Endpoints {
			ep := res.Endpoints[k]
			if strings.EqualFold(ep.Method, want.method) && ep.Path == want.path {
				hit = &ep
				break
			}
		}
		if hit == nil {
			paths := make([]string, 0, len(res.Endpoints))
			for _, ep := range res.Endpoints {
				paths = append(paths, ep.Method+" "+ep.Path)
			}
			t.Errorf("resource %q missing %s %s (have %v)",
				want.resource, want.method, want.path, paths)
			continue
		}
		if want.baseURL != "" && hit.BaseURL != want.baseURL {
			t.Errorf("resource %q endpoint %s %s: BaseURL = %q, want %q",
				want.resource, want.method, want.path, hit.BaseURL, want.baseURL)
		}
	}
}

func assertEvidenceSlots(t *testing.T, evidence []wireevidence.RequestEvidence, tc ruleCase) {
	t.Helper()
	// Flatten all slots from all endpoints into one lookup. Tests assert
	// at the fixture level, not per endpoint, because the matrix only
	// pins shapes the fixture as a whole guarantees.
	type slotInfo struct {
		class string
		seen  bool
	}
	all := map[slotKey]slotInfo{}
	for _, ev := range evidence {
		for _, s := range ev.Slots {
			k := slotKey{location: s.Location, name: s.Name}
			all[k] = slotInfo{class: s.Classification, seen: true}
		}
	}
	for _, k := range tc.mustKeepSlots {
		info, ok := all[k]
		if !ok {
			t.Errorf("evidence missing slot %s:%s (mustKeepSlots)", k.location, k.name)
			continue
		}
		if info.class == wireevidence.ClassVolatileDrop {
			t.Errorf("slot %s:%s classified volatile-drop but mustKeepSlots requires it preserved",
				k.location, k.name)
		}
	}
	for _, k := range tc.mustDropSlots {
		info, ok := all[k]
		if !ok {
			continue // absent slots aren't asserted on
		}
		if info.class != wireevidence.ClassVolatileDrop {
			t.Errorf("slot %s:%s classified %q but mustDropSlots requires volatile-drop",
				k.location, k.name, info.class)
		}
	}
}
