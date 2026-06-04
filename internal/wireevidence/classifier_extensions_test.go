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
		t.Parallel()
		class, constant := ClassifySlot(LocationHeader, "Notion-Version",
			[]string{"2022-06-28", "2022-06-28"})
		assert.Equal(t, ClassSemanticDefault, class,
			"Notion-Version is constant across captures and user-overridable")
		assert.True(t, constant)
	})

	t.Run("DDAPIKey_auth_secret", func(t *testing.T) {
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "DD-API-KEY",
			[]string{"FAKE_DD_API_KEY_0000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"DD-API-KEY name signals auth-secret regardless of value shape")
	})

	t.Run("DDApplicationKey_auth_secret", func(t *testing.T) {
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "DD-APPLICATION-KEY",
			[]string{"FAKE_DD_APP_KEY_00000000000000000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"DD-APPLICATION-KEY name signals auth-secret regardless of value shape")
	})

	t.Run("AuthorizationBasic_auth_secret", func(t *testing.T) {
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "Authorization",
			[]string{"Basic c2tfdGVzdF9GQUtFMDAwMDAwMDAwMDAwMDAwMDA6"})
		assert.Equal(t, ClassAuthSecret, class,
			"Authorization: Basic <base64> is auth-secret regardless of value shape")
	})

	t.Run("DDRequestId_volatile_drop", func(t *testing.T) {
		t.Parallel()
		class, _ := ClassifySlot(LocationHeader, "dd-request-id",
			[]string{"req-abc-001", "req-abc-002"})
		assert.Equal(t, ClassVolatileDrop, class,
			"dd-request-id is per-request tracing; must drop regardless of value")
	})

	t.Run("CSRFToken_documented_choice", func(t *testing.T) {
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

	// --- wave 3 (wave3-oss-fixtures) --------------------------------
	// The following sub-tests pin classifier behavior surfaced by the
	// Discourse, GitLab, Twilio, Tailscale, and HomeAssistant fixtures.
	// Findings (PR 9 input):
	//   - PRIVATE-TOKEN: GitLab's per-user/group token header. Today
	//     semantic-default; PR 9 should mark it auth-secret (name rule
	//     for `private-token` or value-shape rule for `glpat-` prefix).
	//   - Api-Key: Discourse uses the bare `Api-Key` header. Today
	//     detectAuthWithWarnings does promote it to api_key AUTH, but
	//     ClassifySlot still returns semantic-default for the value
	//     itself — the classifier and the auth detector disagree.
	//   - Api-Username: identity half of a dual-header scheme. Today
	//     semantic-default (constant string). Documented choice: NOT
	//     auth-secret (it's user-supplied identity, not a secret).
	//   - tskey-api- prefix: Tailscale API key. Today semantic-default
	//     (no value-shape rule). PR 9 needs a prefix rule.
	//   - Authorization Basic <b64(AC<sid>:<token>)>: Twilio shape. The
	//     SID prefix in the decoded username is a strong identity signal;
	//     the password is the real secret. Today semantic-default
	//     (Basic shape not recognized) — gap covered by the existing
	//     AuthorizationBasic_auth_secret pin from wave 1.

	t.Run("PrivateToken_auth_secret", func(t *testing.T) {
		t.Parallel()
		// GitLab's PRIVATE-TOKEN header carries a Personal Access Token
		// (glpat-...). Today: semantic-default (constant across
		// exemplars, no name pattern). PR 9 should mark auth-secret via
		// name rule (`private-token`) or value-shape (`glpat-` prefix).
		class, _ := ClassifySlot(LocationHeader, "PRIVATE-TOKEN",
			[]string{"glpat-FAKE000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"PRIVATE-TOKEN with glpat- prefix is auth-secret")
	})

	t.Run("GLPATPrefix_auth_secret_anywhere", func(t *testing.T) {
		t.Parallel()
		// A glpat- token might ride in a header named something other
		// than PRIVATE-TOKEN (e.g. Authorization: Bearer glpat-...).
		// Value-shape rule should fire regardless of name.
		class, _ := ClassifySlot(LocationHeader, "X-Custom-Token",
			[]string{"glpat-FAKE000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"glpat- prefix in any header value signals auth-secret")
	})

	t.Run("DiscourseApiKey_auth_secret", func(t *testing.T) {
		t.Parallel()
		// detectAuthWithWarnings already treats Api-Key as api_key auth
		// (isStrongAuthHeaderName matches `api-key`). The classifier
		// should agree and mark the VALUE auth-secret regardless of
		// constancy.
		class, _ := ClassifySlot(LocationHeader, "Api-Key",
			[]string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"})
		assert.Equal(t, ClassAuthSecret, class,
			"Api-Key header value should classify auth-secret (auth detector already treats name as api_key)")
	})

	t.Run("DiscourseApiUsername_not_auth_secret", func(t *testing.T) {
		t.Parallel()
		// Documented choice: Api-Username is the IDENTITY half of
		// Discourse's dual-header scheme. It is user-supplied, not a
		// secret — embedding it in a generated CLI's defaults is
		// acceptable (the SECRET half lives in Api-Key). Anything
		// except auth-secret AND volatile-drop is fine today
		// (semantic-default when constant, unknown when varying).
		// Pin: NOT auth-secret. Regression guard passes today.
		class, _ := ClassifySlot(LocationHeader, "Api-Username",
			[]string{"discourse-admin-bot", "discourse-admin-bot"})
		assert.NotEqual(t, ClassAuthSecret, class,
			"Api-Username is user-supplied identity; treating it as a secret would force redaction of a user-meaningful value")
		assert.NotEqual(t, ClassVolatileDrop, class,
			"Api-Username is REQUIRED to send; dropping it breaks the request")
	})

	t.Run("TailscaleKeyPrefix_auth_secret", func(t *testing.T) {
		t.Parallel()
		// Tailscale API tokens use the `tskey-api-` prefix
		// (analogous to Slack's `xoxc-`). PR 9 should add a value-shape
		// rule mirroring slackTokenPattern.
		class, _ := ClassifySlot(LocationHeader, "Authorization",
			[]string{"Bearer tskey-api-FAKE0000000000000000000000000000000000"})
		assert.Equal(t, ClassAuthSecret, class,
			"tskey-api- prefix signals auth-secret regardless of name")
	})

	t.Run("WebSocketUpgrade_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// Upgrade / Connection / Sec-WebSocket-* are protocol-mandated
		// for the WS handshake. Today none have classifier rules so
		// constant values land as semantic-default. The invariant:
		// these must NEVER be volatile-drop (the handshake breaks
		// without them). A future "WebSocket recognition" PR might
		// reclassify them as protocol-constant; either is acceptable.
		class, _ := ClassifySlot(LocationHeader, "Upgrade",
			[]string{"websocket", "websocket"})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"Upgrade: websocket is part of the WS handshake; must not be volatile-drop")
	})

	t.Run("SecWebSocketKey_not_volatile_drop", func(t *testing.T) {
		t.Parallel()
		// Sec-WebSocket-Key is a client-generated nonce per handshake.
		// It VARIES per connection but is REQUIRED — similar shape to
		// MediaWiki CSRF or Idempotency-Key (varying-but-required).
		// Pin: NOT volatile-drop (today: unknown when varying — OK).
		class, _ := ClassifySlot(LocationHeader, "Sec-WebSocket-Key",
			[]string{"dGhlIHNhbXBsZSBub25jZQ==", "another-fake-nonce-base64=="})
		assert.NotEqual(t, ClassVolatileDrop, class,
			"Sec-WebSocket-Key is required per-handshake; dropping it breaks the WS upgrade")
	})

	t.Run("SentryDSNUserinfo_auth_secret", func(t *testing.T) {
		t.Parallel()
		// Sentry DSNs embed a public key in the URL's userinfo segment
		// (https://<32hex>@host/path). The parser now surfaces it as a
		// LocationURLUserinfo slot named "userinfo"; the classifier rule
		// treats any non-empty userinfo as auth-secret unconditionally
		// because URL-userinfo has no legitimate non-credential use.
		class, _ := ClassifySlot(LocationURLUserinfo, "userinfo",
			[]string{"abcdef0123456789abcdef0123456789"})
		assert.Equal(t, ClassAuthSecret, class,
			"DSN public key in URL userinfo is auth-secret regardless of shape")
	})
}
