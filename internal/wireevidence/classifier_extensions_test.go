package wireevidence

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// classifier_extensions_test.go pins the slot vocabulary real APIs add
// once the matrix grows beyond Slack + tickets. Per codex's strongest
// opinion, the matrix itself should not pin "what's TRUE TODAY plus
// what we wish were true" — it pins today's behavior. Future rules
// live here, gated by RUN_PIN_FAILS until PR 9 lands the matching
// classifier extension. This is the ONE exception to the
// "don't grow the RUN_PIN_FAILS pattern" rule: classifier rules that
// haven't been written yet have nowhere else to live.
//
// Once a rule lands in classifier.go, delete the skipUnlessRunPinFails
// call from that subtest — the assertion graduates into a normal table
// row. The test file itself stays as the single home for the classifier's
// real-API vocabulary, distinct from evidence_test.go (which tests the
// five-class decision tree itself).
//
// findings discovered while writing these (PR 9 input):
//   - DD-API-KEY/DD-APPLICATION-KEY today classify as semantic-default
//     (constant across exemplars) not auth-secret. Classifier needs an
//     explicit name-pattern rule for DD- prefix headers.
//   - dd-request-id today classifies as unknown (varies per request,
//     no name-pattern match). Classifier needs a name-pattern rule for
//     dd-request-id / x-request-id / retry-after-ms / sentry-trace
//     variants beyond the existing prefix list.
//   - Authorization: Basic <base64> today classifies as semantic-default
//     (constant + name doesn't trigger). IsAuthSecretValue only matches
//     xoxc / JWT shapes; Basic-auth header detection is a separate gap.
//   - Idempotency-Key today classifies as unknown (varies, no rule).
//     Acceptable today — the unknown class forces the user to supply it.
//     A future "semantic-perrequest" class could be more accurate.

// skipUnlessRunPinFails mirrors the helper in internal/browsersniff/
// slack_redacted_pin_test.go but lives here so the wireevidence
// package has no cross-package import for test gating. Kept as a
// thin helper to maximize signal: each skip line names the PR that
// owns the gap.
func skipUnlessRunPinFails(t *testing.T, pr, gap string) {
	t.Helper()
	if os.Getenv("RUN_PIN_FAILS") == "" {
		t.Skipf("PIN: blocked by %s (%s). "+
			"Run with RUN_PIN_FAILS=1 to see the failing assertion. "+
			"See docs/brainstorms/2026-06-04-request-evidence-pr7-roadmap.md",
			pr, gap)
	}
}

// TestClassifySlot_RealAPIVocabulary asserts classifier behavior on
// header / body / query names drawn from the matrix fixtures. Subtests
// that mark `skipUnlessRunPinFails` document a classifier extension PR 9
// still owes; the remainder pin behavior that already works today.
func TestClassifySlot_RealAPIVocabulary(t *testing.T) {
	t.Parallel()

	t.Run("IdempotencyKey_must_not_be_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// Stripe's Idempotency-Key varies per request but is the user's
		// responsibility — must never be classified as volatile-drop
		// (which would silently strip it from reconstructed requests).
		class, _ := ClassifySlot(LocationHeader, "Idempotency-Key",
			[]string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"Idempotency-Key is user-meaningful per Stripe contract; must not be volatile-drop")
	})

	t.Run("NotionVersion_semantic_default", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier extends to Notion-Version header")
		t.Parallel()
		class, constant := ClassifySlot(LocationHeader, "Notion-Version",
			[]string{"2022-06-28", "2022-06-28"})
		assert.Equal(t, ClassSemanticDefault, class,
			"Notion-Version is constant across captures and user-overridable")
		assert.True(t, constant)
	})

	t.Run("DDAPIKey_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns DD-API-KEY/DD-APPLICATION-KEY are auth-secret")
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "DD-API-KEY",
			[]string{"FAKE_DD_API_KEY_0000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"DD-API-KEY name signals auth-secret regardless of value shape")
	})

	t.Run("DDApplicationKey_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns DD-APPLICATION-KEY is auth-secret")
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "DD-APPLICATION-KEY",
			[]string{"FAKE_DD_APP_KEY_00000000000000000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"DD-APPLICATION-KEY name signals auth-secret regardless of value shape")
	})

	t.Run("AuthorizationBasic_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "IsAuthSecretValue learns Basic <base64> shape")
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "Authorization",
			[]string{"Basic c2tfdGVzdF9GQUtFMDAwMDAwMDAwMDAwMDAwMDA6"})
		assert.Equal(t, ClassAuthSecret, class,
			"Authorization: Basic <base64> is auth-secret regardless of value shape")
	})

	t.Run("DDRequestId_volatile_drop", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns dd-request-id name pattern")
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "dd-request-id",
			[]string{"req-abc-001", "req-abc-002"})
		assert.Equal(t, ClassVolatileDrop, class,
			"dd-request-id is per-request tracing; must drop regardless of value")
	})

	t.Run("CSRFToken_documented_choice", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier picks a class for X-CSRF-Token")
		t.Parallel()
		// X-CSRF-Token is the tricky one: it varies across sessions but
		// is REQUIRED to send. Marking volatile-drop would strip a
		// required header; marking semantic-default would replay a stale
		// token. PR 9 should pick "unknown" (user must supply) or a
		// future "semantic-perrequest" class. NOT volatile-drop.
		class, _ := ClassifySlot(LocationHeader, "X-CSRF-Token",
			[]string{"token-session-A", "token-session-B"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"X-CSRF-Token is required for the request to succeed; dropping it breaks the call")
	})

	t.Run("NotionStartCursor_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// Notion's pagination cursor varies per page but is semantically
		// meaningful. Today classifier returns "unknown" (no name rule,
		// values vary). Anything except volatile-drop is acceptable. This
		// test passes today and stays as a regression guard.
		class, _ := ClassifySlot(LocationQuery, "start_cursor",
			[]string{"abc", "def"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"start_cursor is Notion pagination; user-meaningful even when varying")
	})

	t.Run("NotionNextCursor_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		class, _ := ClassifySlot(LocationBodyForm, "next_cursor",
			[]string{"abc", "def"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"next_cursor is Notion pagination; user-meaningful even when varying")
	})

	// --- wave 2 (more-oss-fixtures) ----------------------------------
	// The following sub-tests pin classifier behavior surfaced by the
	// Shopify, MediaWiki, GitHub REST, Sentry DSN, and GitHub-webhook
	// fixtures. Each `skipUnlessRunPinFails` row documents a gap PR 9
	// (or a future PR — Sentry DSN userinfo parsing is upstream of the
	// classifier) still owes; the rest are regression guards that
	// already pass today.

	t.Run("IfNoneMatch_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// If-None-Match is user-meaningful cache control. Like
		// Idempotency-Key, it varies with cache state but the user
		// controls it. Must NEVER be volatile-drop.
		class, _ := ClassifySlot(LocationHeader, "If-None-Match",
			[]string{"W/\"abc123\"", "W/\"def456\""})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"If-None-Match is user-controlled cache validation; must not be volatile-drop")
	})

	t.Run("XHubSignature256_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns X-Hub-Signature-256 is auth-secret (HMAC body signature)")
		t.Parallel()
		// X-Hub-Signature-256 carries an HMAC of the body; even though
		// the verifier (not the emitter) holds the secret, the value
		// itself is secret-shaped and non-reconstructable from
		// captured data. Replaying it verbatim against new body bytes
		// is wrong; the classifier should flag it auth-secret AND
		// (future) a non-reconstructable sub-class.
		class, _ := ClassifySlot(LocationHeader, "X-Hub-Signature-256",
			[]string{
				"sha256=aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
				"sha256=9999888877776666555544443333222211110000ffffeeeeddddccccbbbbaaaa",
			})
		assert.Equal(t, ClassAuthSecret, class,
			"X-Hub-Signature-256 is an HMAC body signature; classify as auth-secret")
	})

	t.Run("XGitHubDelivery_volatile_drop", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns X-GitHub-Delivery is per-request UUID")
		t.Parallel()
		// X-GitHub-Delivery is GitHub's per-delivery UUID — every
		// webhook delivery gets a fresh one. Must drop on replay.
		class, _ := ClassifySlot(LocationHeader, "X-GitHub-Delivery",
			[]string{
				"00000000-0000-4000-8000-00000000aaa1",
				"00000000-0000-4000-8000-00000000aaa2",
			})
		assert.Equal(t, ClassVolatileDrop, class,
			"X-GitHub-Delivery is per-request UUID; must drop on replay")
	})

	t.Run("XShopifyAccessToken_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns X-Shopify-Access-Token / shpat_ prefix is auth-secret")
		t.Parallel()
		// X-Shopify-Access-Token is Shopify's per-store admin token.
		// Today the classifier returns semantic-default (constant
		// across exemplars). After PR 9, either a name rule
		// (`*-access-token`) or a value-shape rule (`shpat_` prefix)
		// should mark it auth-secret.
		class, _ := ClassifySlot(LocationHeader, "X-Shopify-Access-Token",
			[]string{"shpat_FAKE0000000000000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"X-Shopify-Access-Token name+shpat_ prefix signals auth-secret")
	})

	t.Run("MediaWikiCSRFToken_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// MediaWiki's body `token` field varies across sessions but
		// is REQUIRED to send. Today the classifier returns "unknown"
		// (varying values, no name rule). Anything except
		// volatile-drop is acceptable — the user must supply it.
		// Regression guard: passes today.
		class, _ := ClassifySlot(LocationBodyForm, "token",
			[]string{
				"abcdef0123456789abcdef0123456789ABCD+\\",
				"fedcba9876543210fedcba9876543210FEDC+\\",
			})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"MediaWiki CSRF token in body is required-but-varying; must not be volatile-drop")
	})

	t.Run("OAuthCode_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 9", "classifier learns OAuth `code` query param is auth-secret (one-time)")
		t.Parallel()
		// OAuth authorization codes are one-time-use bearer-like
		// secrets. Embedding one in a generated CLI is dangerous;
		// the classifier should mark it auth-secret (forcing redaction
		// upstream) even though the param name is the bland `code`.
		class, _ := ClassifySlot(LocationQuery, "code",
			[]string{
				"AUTHCODE_AAAAAAAAAAAAAAAAAAAAAAAA",
				"AUTHCODE_BBBBBBBBBBBBBBBBBBBBBBBB",
			})
		assert.Equal(t, ClassAuthSecret, class,
			"OAuth `code` query param is a one-time bearer secret")
	})

	t.Run("OAuthState_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// OAuth `state` is the client's CSRF guard. The CLI use case
		// would not typically replay it, but it is user-meaningful
		// (not a tracing UUID the server invented). Today: unknown
		// when varying, semantic-default when constant. Either is
		// acceptable — only volatile-drop is wrong because it would
		// silently strip a header the user might want to inspect.
		// Two-exemplar constant case (typical of a single OAuth flow
		// in the capture):
		class, _ := ClassifySlot(LocationQuery, "state",
			[]string{"csrfguardvaluexyz", "csrfguardvaluexyz"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"OAuth `state` is user-meaningful CSRF guard; not volatile")
	})

	t.Run("SentryDSNUserinfo_auth_secret", func(t *testing.T) {
		skipUnlessRunPinFails(t, "PR 12 (URL-userinfo parsing)", "convertHAREntry/inferURLParams must surface url.User as a slot")
		t.Parallel()
		// Sentry DSNs embed a public key in the URL's userinfo
		// segment (https://<32hex>@host/path). Today nothing parses
		// url.User into the evidence model, so the classifier never
		// sees it. The pin: once the userinfo IS surfaced as a slot
		// (likely under a new Location value like LocationURLUserinfo),
		// the 32-hex shape must be classified auth-secret. The location
		// constant doesn't exist yet, so this test pins shape via the
		// query location as a stand-in — the real test arrives with
		// the parser extension.
		class, _ := ClassifySlot(LocationQuery, "userinfo",
			[]string{"abcdef0123456789abcdef0123456789"})
		assert.Equal(t, ClassAuthSecret, class,
			"32-hex DSN public key in URL userinfo is auth-secret")
	})
}
