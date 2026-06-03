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

var (
	slackTokenPattern = regexp.MustCompile(`xox[abcdpr]-`)
	// jwtPattern uses `eyJ` (base64 of `{"`) as the cheap shape check. Full
	// JWT validation is overkill for classifier purposes. Matched anywhere
	// in the value so a `Bearer eyJ...` Authorization header still classifies.
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.`)
)

// IsAuthSecretValue returns true for values whose shape matches the
// classifier's PR 3 auth-secret heuristics: Slack workspace tokens
// (`xox[abcdpr]-`) and JWTs (`eyJ...` payload). Shared with the browsersniff
// PR 3 detection so codegen and capture agree on the same rule.
func IsAuthSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	return slackTokenPattern.MatchString(trimmed) || jwtPattern.MatchString(trimmed)
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

// ClassifySlot picks the wire-evidence class for one slot given its
// location, name, and the set of observed values across exemplars.
//
// The decision tree (priority order):
//  1. Any value matches the auth-secret shape → auth-secret.
//  2. Name matches a known volatile header pattern → volatile-drop.
//  3. Location is header and name is protocol-mandated → protocol-constant.
//  4. Values are identical across exemplars and the name looks meaningful →
//     semantic-default.
//  5. Otherwise → unknown.
//
// "Meaningful" name = non-empty and not pure whitespace. The unknown class
// is the safe fallback: PR 5's template will surface unknown slots as
// required CLI flags so the user is forced to provide them rather than the
// generator inventing a default.
func ClassifySlot(location, name string, values []string) (class string, constant bool) {
	constant = valuesAreConstant(values)

	for _, v := range values {
		if IsAuthSecretValue(v) {
			return ClassAuthSecret, constant
		}
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
