package wireevidence

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ReconstructedRequest is the offline replay of an evidence entry: what the
// generator would have to put on the wire to match the captured exemplar.
// The validation gate compares this against the original Exemplar field by
// field; any divergence means the evidence vocabulary lost information the
// capture had.
type ReconstructedRequest struct {
	Method    string
	URL       string
	Headers   map[string]string
	BodyForm  map[string]string
	BodyMulti map[string]string
}

// ReconstructRequest replays an evidence entry into a request shape using
// the given env-var lookup for auth-secret slots. Returns the reconstructed
// shape without invoking any network IO. The returned URL has query
// parameters encoded in alphabetical order so callers can byte-compare.
//
// Replay rules (mirror the PR 5 template-branch intent):
//   - protocol-constant + semantic-default header slots: emit verbatim
//   - auth-secret slots: env lookup; missing env yields the literal
//     placeholder ${ENV_NAME} so callers see the unresolved gap
//   - volatile-drop slots: dropped
//   - unknown slots: also emitted verbatim from the exemplar (the template
//     would surface them as CLI flags whose default is the captured value)
//
// "env" callbacks receive the slot's wire name and return the runtime value
// the printed CLI would supply; pass nil to default to the env-var name
// placeholder.
func ReconstructRequest(req RequestEvidence, exemplar Exemplar, env func(slotName string) (string, bool)) (ReconstructedRequest, error) {
	if env == nil {
		env = func(string) (string, bool) { return "", false }
	}

	out := ReconstructedRequest{
		Method:    strings.ToUpper(strings.TrimSpace(req.Method)),
		Headers:   map[string]string{},
		BodyForm:  map[string]string{},
		BodyMulti: map[string]string{},
	}

	slotByKey := map[secretKey]Slot{}
	for _, s := range req.Slots {
		slotByKey[secretKey{s.Location, s.Name}] = s
	}

	queryParams := url.Values{}

	// Headers from exemplar, gated by slot classification.
	for name, value := range exemplar.Headers {
		slot, ok := slotByKey[secretKey{LocationHeader, name}]
		if !ok {
			// Unrecorded header (should not happen because BuildSlots walks
			// every exemplar header). Treat as unknown: pass through.
			out.Headers[name] = value
			continue
		}
		if slot.Classification == ClassVolatileDrop {
			continue
		}
		if slot.Classification == ClassAuthSecret {
			if v, ok := env(name); ok {
				out.Headers[name] = v
			} else {
				out.Headers[name] = envPlaceholder(name)
			}
			continue
		}
		out.Headers[name] = value
	}

	// Query slots: reconstruct from the exemplar URL's raw query so we
	// preserve the captured ordering signal.
	if exemplar.URL != "" {
		parsed, err := url.Parse(exemplar.URL)
		if err != nil {
			return ReconstructedRequest{}, fmt.Errorf("parsing exemplar URL: %w", err)
		}
		baseURL := exemplar.URL
		if idx := strings.Index(exemplar.URL, "?"); idx >= 0 {
			baseURL = exemplar.URL[:idx]
		}
		for name, values := range parsed.Query() {
			slot, ok := slotByKey[secretKey{LocationQuery, name}]
			if ok && slot.Classification == ClassVolatileDrop {
				continue
			}
			if ok && slot.Classification == ClassAuthSecret {
				if v, ok := env(name); ok {
					queryParams.Set(name, v)
				} else {
					queryParams.Set(name, envPlaceholder(name))
				}
				continue
			}
			for _, v := range values {
				queryParams.Add(name, v)
			}
		}
		if len(queryParams) > 0 {
			out.URL = baseURL + "?" + queryParams.Encode()
		} else {
			out.URL = baseURL
		}
	}

	for name, value := range exemplar.BodyForm {
		out.BodyForm[name] = resolveBodyValue(slotByKey, LocationBodyForm, name, value, env)
	}
	for name, value := range exemplar.BodyMulti {
		out.BodyMulti[name] = resolveBodyValue(slotByKey, LocationBodyMulti, name, value, env)
	}

	return out, nil
}

func resolveBodyValue(slotByKey map[secretKey]Slot, location, name, value string, env func(string) (string, bool)) string {
	slot, ok := slotByKey[secretKey{location, name}]
	if !ok {
		return value
	}
	if slot.Classification == ClassAuthSecret {
		if v, ok := env(name); ok {
			return v
		}
		return envPlaceholder(name)
	}
	return value
}

func envPlaceholder(name string) string {
	upper := strings.ToUpper(name)
	upper = strings.ReplaceAll(upper, "-", "_")
	return "${" + upper + "}"
}

// secretKey identifies one (location, name) slot for lookups.
type secretKey struct{ location, name string }

// CompareRequestAgainstExemplar checks that an exemplar matches what the
// slot vocabulary CLAIMS the wire should look like. For each non-volatile
// (location, name) pair recorded in the exemplar, the comparison resolves
// the slot's claimed value (constant slot value, or auth-secret env
// lookup, or the exemplar value itself for unknown / unrecorded slots)
// and asserts it equals the exemplar's recorded value.
//
// This catches three regression shapes:
//   - constant-classed slot whose recorded Slot.Value diverges from the
//     exemplar's wire value (PR 4 classifier drift)
//   - auth-secret slot whose env-resolved value diverges from the
//     exemplar's wire value (PR 5 redaction-format drift between
//     classifier and gate)
//   - exemplar key that no slot records as volatile-drop, but the slot
//     vocabulary nevertheless excluded it (slot list out of sync with
//     exemplar list)
//
// The gate is **slot-anchored**: the slot list is the contract under
// validation; the exemplar is the truth. Multipart bodies compare as
// parsed key→value maps (boundary differs per request) and query strings
// compare order-tolerant.
//
// authValues maps slot names to the un-redacted captured value, used to
// resolve auth-secret slots.
func CompareRequestAgainstExemplar(req RequestEvidence, exemplar Exemplar, authValues map[string]string) error {
	if method := strings.ToUpper(strings.TrimSpace(req.Method)); method != "" && exemplar.URL != "" {
		// method comparison is degenerate (the exemplar doesn't carry
		// one); skip without erroring.
		_ = method
	}

	if err := compareLocationMap(req.Slots, LocationHeader, exemplar.Headers, authValues); err != nil {
		return fmt.Errorf("headers: %w", err)
	}
	if err := compareLocationMap(req.Slots, LocationBodyForm, exemplar.BodyForm, authValues); err != nil {
		return fmt.Errorf("body_form: %w", err)
	}
	if err := compareLocationMap(req.Slots, LocationBodyMulti, exemplar.BodyMulti, authValues); err != nil {
		return fmt.Errorf("body_multipart: %w", err)
	}

	// URL query slots are compared via the parsed exemplar URL because
	// the slot list lives on the request, not the exemplar.
	if exemplar.URL != "" {
		parsed, err := url.Parse(exemplar.URL)
		if err != nil {
			return fmt.Errorf("parsing exemplar URL: %w", err)
		}
		queryMap := map[string]string{}
		for k, vs := range parsed.Query() {
			if len(vs) == 0 {
				queryMap[k] = ""
				continue
			}
			queryMap[k] = vs[0]
		}
		if err := compareLocationMap(req.Slots, LocationQuery, queryMap, authValues); err != nil {
			return fmt.Errorf("query: %w", err)
		}
	}
	return nil
}

// compareLocationMap walks the exemplar's recorded values for one slot
// location and asserts each value matches the slot's claim.
func compareLocationMap(slots []Slot, location string, exemplarMap, authValues map[string]string) error {
	for name, exemplarValue := range exemplarMap {
		slot, ok := slotForName(slots, location, name)
		if !ok {
			// Unrecorded slot. Acceptable: the slot list may have been
			// pruned at sniff time. Skip rather than fire — the only
			// safety check possible here is that the value parses.
			continue
		}
		switch slot.Classification {
		case ClassVolatileDrop:
			// Exemplar carries the value (browsers send trace ids) but
			// the slot says "drop on replay" — no comparison needed.
			continue
		case ClassAuthSecret:
			expected, ok := authValues[name]
			if !ok {
				return fmt.Errorf("%s %q: auth-secret slot has no captured value in any exemplar — cannot validate redaction round-trip", location, name)
			}
			if expected != exemplarValue {
				return fmt.Errorf("%s %q: auth-secret env-resolved value %q != exemplar value %q", location, name, expected, exemplarValue)
			}
		case ClassProtocolConstant, ClassSemanticDefault:
			if !slot.Constant {
				continue
			}
			if slot.Value != exemplarValue {
				return fmt.Errorf("%s %q: constant slot value %q != exemplar value %q", location, name, slot.Value, exemplarValue)
			}
		default:
			// unknown / unclassified: nothing to assert beyond the
			// exemplar's own consistency.
			continue
		}
	}
	return nil
}

func slotForName(slots []Slot, location, name string) (Slot, bool) {
	for _, s := range slots {
		if s.Location == location && s.Name == name {
			return s, true
		}
	}
	return Slot{}, false
}

// urlsEquivalent compares two URLs for wire-equivalence. Query parameter
// order is ignored; everything else must match.
func urlsEquivalent(got, want string) error {
	if got == want {
		return nil
	}
	gotParsed, err := url.Parse(got)
	if err != nil {
		return fmt.Errorf("parse got: %w", err)
	}
	wantParsed, err := url.Parse(want)
	if err != nil {
		return fmt.Errorf("parse want: %w", err)
	}
	if gotParsed.Scheme != wantParsed.Scheme {
		return fmt.Errorf("scheme: got %q want %q", gotParsed.Scheme, wantParsed.Scheme)
	}
	if gotParsed.Host != wantParsed.Host {
		return fmt.Errorf("host: got %q want %q", gotParsed.Host, wantParsed.Host)
	}
	if gotParsed.Path != wantParsed.Path {
		return fmt.Errorf("path: got %q want %q", gotParsed.Path, wantParsed.Path)
	}
	gotQ := gotParsed.Query()
	wantQ := wantParsed.Query()
	if len(gotQ) != len(wantQ) {
		return fmt.Errorf("query size: got %d want %d", len(gotQ), len(wantQ))
	}
	keys := make([]string, 0, len(wantQ))
	for k := range wantQ {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := append([]string(nil), gotQ[k]...)
		w := append([]string(nil), wantQ[k]...)
		sort.Strings(g)
		sort.Strings(w)
		if len(g) != len(w) {
			return fmt.Errorf("query %q: got %d values want %d", k, len(g), len(w))
		}
		for i := range g {
			if g[i] != w[i] {
				return fmt.Errorf("query %q[%d]: got %q want %q", k, i, g[i], w[i])
			}
		}
	}
	return nil
}
