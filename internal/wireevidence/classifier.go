package wireevidence

import (
	"regexp"
	"sort"
	"strings"
)

// volatileHeaderPrefixes match telemetry/tracing header names that must never
// be replayed verbatim even if their value happens to repeat across exemplars.
var volatileHeaderPrefixes = []string{
	"x-b3-",
	"x-request-id",
	"x-correlation-id",
	"traceparent",
	"tracestate",
	"x-amzn-trace-id",
	"x-cloud-trace-context",
	"sentry-trace",
	"baggage",
	"x-datadog-",
	"x-newrelic-",
	// Datadog's per-request tracing IDs ride under the `dd-` name space
	// (dd-request-id, dd-trace-id, ...) which the `x-datadog-` prefix above
	// does NOT cover. The bare `dd-` prefix also catches future Datadog
	// tracing additions without further classifier churn.
	// NOTE: dd-api-key / dd-application-key share the same prefix but are
	// short-circuited by authSecretHeaderNames before this list is consulted.
	"dd-",
	// GitHub stamps every webhook delivery (and many REST calls) with a
	// fresh UUID under this header. Replaying it verbatim would collide
	// with subsequent deliveries on the receiver side.
	"x-github-delivery",
	// GitHub REST surfaces the request id on every response/echoes it on
	// retries -- per-request and must not be replayed.
	"x-github-request-id",
}

// protocolConstantHeaders are HTTP-mandated headers whose value is part of
// content negotiation rather than application semantics. The classifier
// surfaces them so codegen can replay them verbatim without prompting the
// user.
var protocolConstantHeaders = map[string]bool{
	"accept":          true,
	"accept-encoding": true,
	"accept-language": true,
	"content-type":    true,
	"content-length":  true,
	"user-agent":      true,
	"host":            true,
}

// authSecretHeaderNames are header names whose presence ALWAYS signals an
// auth-secret value, regardless of the value's shape or whether it stays
// constant across exemplars. Used to short-circuit the "constant => semantic-default"
// branch for headers whose vendor contract names them as secrets
// (Datadog DD-API-KEY, GitLab PRIVATE-TOKEN, Shopify X-Shopify-Access-Token,
// ...). Compared case-insensitive.
var authSecretHeaderNames = map[string]bool{
	"dd-api-key":             true, // Datadog API key
	"dd-application-key":     true, // Datadog application key
	"private-token":          true, // GitLab PAT header
	"x-shopify-access-token": true, // Shopify admin access token
	"x-hub-signature":        true, // GitHub/webhook HMAC (legacy sha1)
	"x-hub-signature-256":    true, // GitHub/webhook HMAC (sha256)
}

// hexAuthHeaderNames are header names whose AUTH classification depends on
// the value matching a hex-shape (avoids treating non-secret usages of the
// same header -- e.g. an Api-Key set to a UUID or human-readable label -- as
// auth-secret). These names already light up the auth detector elsewhere so
// agreeing here keeps classifier and auth detector in sync.
var hexAuthHeaderNames = map[string]bool{
	"api-key": true, // Discourse and many generic APIs
}

var (
	slackTokenPattern = regexp.MustCompile(`xox[abcdpr]-`)
	// jwtPattern uses `eyJ` (base64 of `{"`) as the cheap shape check. Full
	// JWT validation is overkill for classifier purposes. Matched anywhere
	// in the value so a `Bearer eyJ...` Authorization header still classifies.
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.`)
	// basicAuthPattern matches `Basic <base64>` Authorization values. The
	// classifier treats every Basic-credential as auth-secret because the
	// base64 payload always contains `username:password`.
	basicAuthPattern = regexp.MustCompile(`(?i)^basic\s+[A-Za-z0-9+/=_-]+\s*$`)
	// hmacSha256Pattern matches GitHub-style webhook signatures
	// (`sha256=<64-hex>`). The value itself is non-secret on the wire but
	// it is non-reconstructable from captured data -- treating it as
	// auth-secret forces redaction and prevents codegen from replaying a
	// stale signature against new body bytes.
	hmacSha256Pattern = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)
	// hexValuePattern matches values that are pure hex (>=32 chars), the
	// typical shape of API keys / tokens.
	hexValuePattern = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	// shopifyAccessTokenPrefix marks Shopify admin API access tokens.
	shopifyAccessTokenPrefix = "shpat_"
	// tailscaleAPIKeyPrefix marks Tailscale API keys. Narrowed to the API
	// variant (not bare `tskey-`) to avoid catching unrelated strings;
	// broaden if/when other tskey-* variants show up in the matrix.
	tailscaleAPIKeyPrefix = "tskey-api-"
	// gitlabPATPrefix marks GitLab Personal Access Tokens.
	gitlabPATPrefix = "glpat-"
	// oauthCodeValuePattern recognizes token-shaped values for the OAuth
	// `code` query param heuristic (see ClassifySlot).
	oauthCodeValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{20,100}$`)
)

// IsAuthSecretValue returns true for values whose shape matches one of the
// classifier's auth-secret heuristics: Slack workspace tokens
// (`xox[abcdpr]-`), JWTs (`eyJ...` payload), HTTP Basic credentials
// (`Basic <base64>`), GitHub-style HMAC signatures (`sha256=<64-hex>`),
// Shopify admin tokens (`shpat_...`), Tailscale API keys (`tskey-api-...`),
// GitLab PATs (`glpat-...`). Shared with the browsersniff detection so
// codegen and capture agree on the same rule. Prefix/contains-based
// shapes match anywhere in the value so wrappers like
// `Authorization: Bearer <secret>` still classify.
func IsAuthSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if slackTokenPattern.MatchString(trimmed) || jwtPattern.MatchString(trimmed) {
		return true
	}
	if basicAuthPattern.MatchString(trimmed) {
		return true
	}
	if hmacSha256Pattern.MatchString(trimmed) {
		return true
	}
	if strings.Contains(trimmed, shopifyAccessTokenPrefix) {
		return true
	}
	if strings.Contains(trimmed, tailscaleAPIKeyPrefix) {
		return true
	}
	if strings.Contains(trimmed, gitlabPATPrefix) {
		return true
	}
	return false
}

// IsVolatileHeaderName reports whether the header name matches a known
// telemetry/tracing pattern that must be dropped from any reconstructed
// request regardless of constancy.
func IsVolatileHeaderName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	for _, prefix := range volatileHeaderPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// IsProtocolConstantHeader reports whether the header is part of HTTP-level
// content negotiation rather than application semantics.
func IsProtocolConstantHeader(name string) bool {
	return protocolConstantHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// isAuthSecretHeaderName reports whether the header name itself is enough to
// declare the value an auth-secret (e.g. DD-API-KEY, PRIVATE-TOKEN).
func isAuthSecretHeaderName(name string) bool {
	return authSecretHeaderNames[strings.ToLower(strings.TrimSpace(name))]
}

// isOAuthCodeSlot applies a pragmatic heuristic for OAuth authorization
// codes appearing as a query param. The slot classifier sees only
// (location, name, values) -- not the endpoint path -- so we cannot apply
// the ideal rule of "param named `code` on a /callback or /oauth/ path".
// Instead we require: location=query, name (case-insensitive) equals
// `code`, and every observed value is token-shaped (length 20-100,
// URL-safe alphabet). False positives on non-OAuth `code` params with
// long opaque values are accepted as the cost of catching real OAuth
// codes -- the failure mode of treating a value as auth-secret is
// over-redaction, which is the safe direction. If the parser ever gains
// endpoint-path context the rule should tighten to require the path to
// contain `callback`, `oauth`, or `redirect`.
func isOAuthCodeSlot(location, name string, values []string) bool {
	if location != LocationQuery {
		return false
	}
	if strings.ToLower(strings.TrimSpace(name)) != "code" {
		return false
	}
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if !oauthCodeValuePattern.MatchString(strings.TrimSpace(v)) {
			return false
		}
	}
	return true
}

// ClassifySlot picks the wire-evidence class for one slot given its
// location, name, and the set of observed values across exemplars.
//
// The decision tree (priority order):
//  1. Any value matches the auth-secret shape -> auth-secret.
//  2. Location is header and name itself signals an auth-secret
//     (DD-API-KEY, PRIVATE-TOKEN, ...) -> auth-secret.
//  3. Location is header and name is a hex-keyed auth header AND every
//     value is hex-shaped -> auth-secret.
//  4. OAuth `code` query param heuristic matches -> auth-secret.
//  5. Name matches a known volatile header pattern -> volatile-drop.
//  6. Location is header and name is protocol-mandated -> protocol-constant.
//  7. Values are identical across exemplars and the name looks meaningful ->
//     semantic-default.
//  8. Otherwise -> unknown.
//
// "Meaningful" name = non-empty and not pure whitespace. The unknown class
// is the safe fallback: PR 5's template will surface unknown slots as
// required CLI flags so the user is forced to provide them rather than the
// generator inventing a default.
//
// Note on Sentry DSN userinfo: a separate gap (PR 12) tracks parsing
// `https://<32hex>@host/...` URLs into a userinfo slot. Until that parser
// change lands the classifier never sees such slots, so no rule is emitted
// here. The corresponding pin in classifier_extensions_test.go
// (SentryDSNUserinfo_auth_secret) intentionally stays gated.
func ClassifySlot(location, name string, values []string) (class string, constant bool) {
	constant = valuesAreConstant(values)

	for _, v := range values {
		if IsAuthSecretValue(v) {
			return ClassAuthSecret, constant
		}
	}

	if location == LocationHeader && isAuthSecretHeaderName(name) {
		return ClassAuthSecret, constant
	}

	// URL userinfo (e.g. Sentry DSN public key in
	// `https://<32hex>@host/...`) is always a credential by construction
	// — no legitimate non-secret use case for embedding a value in the
	// URL's user[:password]@ segment. Classify unconditionally so the
	// generator forces it to an env-var-backed slot.
	if location == LocationURLUserinfo {
		return ClassAuthSecret, constant
	}

	if location == LocationHeader {
		lowerName := strings.ToLower(strings.TrimSpace(name))
		if hexAuthHeaderNames[lowerName] && len(values) > 0 {
			allHex := true
			for _, v := range values {
				if !hexValuePattern.MatchString(strings.TrimSpace(v)) {
					allHex = false
					break
				}
			}
			if allHex {
				return ClassAuthSecret, constant
			}
		}
	}

	if isOAuthCodeSlot(location, name, values) {
		return ClassAuthSecret, constant
	}

	if location == LocationHeader && IsVolatileHeaderName(name) {
		return ClassVolatileDrop, constant
	}

	if location == LocationHeader && IsProtocolConstantHeader(name) {
		return ClassProtocolConstant, constant
	}

	if constant && strings.TrimSpace(name) != "" {
		return ClassSemanticDefault, constant
	}

	return ClassUnknown, constant
}

func valuesAreConstant(values []string) bool {
	if len(values) == 0 {
		return false
	}
	first := values[0]
	for _, v := range values[1:] {
		if v != first {
			return false
		}
	}
	return true
}

// BuildSlots walks all exemplars and emits one Slot per distinct
// (location, name) pair, classified and ordered deterministically.
func BuildSlots(exemplars []Exemplar) []Slot {
	type key struct {
		location string
		name     string
	}
	values := map[key][]string{}
	add := func(location, name, value string) {
		k := key{location: location, name: name}
		values[k] = append(values[k], value)
	}

	for _, ex := range exemplars {
		for n, v := range ex.Headers {
			add(LocationHeader, n, v)
		}
		for n, v := range ex.Query {
			add(LocationQuery, n, v)
		}
		for n, v := range ex.BodyForm {
			add(LocationBodyForm, n, v)
		}
		for n, v := range ex.BodyMulti {
			add(LocationBodyMulti, n, v)
		}
		if ex.URLUserinfo != "" {
			add(LocationURLUserinfo, "userinfo", ex.URLUserinfo)
		}
	}

	slots := make([]Slot, 0, len(values))
	for k, vs := range values {
		class, constant := ClassifySlot(k.location, k.name, vs)
		slot := Slot{
			Location:       k.location,
			Name:           k.name,
			Classification: class,
			Constant:       constant,
		}
		if constant && (class == ClassProtocolConstant || class == ClassSemanticDefault) {
			slot.Value = vs[0]
		}
		slots = append(slots, slot)
	}

	sort.Slice(slots, func(i, j int) bool {
		if slots[i].Location != slots[j].Location {
			return slots[i].Location < slots[j].Location
		}
		return slots[i].Name < slots[j].Name
	})
	return slots
}
