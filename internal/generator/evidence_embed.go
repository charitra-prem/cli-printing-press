// Evidence sidecar consumption for browser-sniffed CLIs.
//
// loadSanitizedEvidence reads the *-request-evidence.json sidecar emitted by
// PR 4, classifies-sanitizes every auth-secret value (replacing both Exemplar
// values and any populated Slot.Value with a `${ENV_NAME}` placeholder), and
// returns the JSON bytes ready to embed into the generated printed CLI.
//
// Redaction format: `${ENV_NAME}` literal placeholders. The placeholder is
// computed from the slot's wire name via authSecretBodyEnvName-style
// upper-snake-of-name. Bleeding env-var names into the binary is fine — the
// printed CLI's doctor surfaces them anyway. Decision rationale in PR 5
// section of docs/brainstorms/2026-06-02-request-evidence-requirements.md.
//
// emitRequestEvidenceGo writes the sanitized JSON as a []byte literal into
// internal/client/request_evidence.gen.go. We inline the bytes rather than
// copying the sidecar into the generated tree because the generator's own
// test suite assembles projects in temp dirs without an out-of-tree sidecar
// path; an inlined []byte survives that without extra wiring.
package generator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mvanhorn/cli-printing-press/v4/internal/naming"
	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

// loadEvidenceFromPath reads and parses an evidence sidecar. Returns nil with
// no error when the file does not exist; sidecars are optional. Caller is
// responsible for the spec_source gate.
func loadEvidenceFromPath(path string) (*wireevidence.Document, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading request evidence: %w", err)
	}
	var doc wireevidence.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing request evidence: %w", err)
	}
	return &doc, nil
}

// authSecretEnvName converts a slot's wire name into the env var the printed
// CLI reads at request time. Matches the PR 3 convention
// (authSecretBodyEnvName) so a body field already routed through PR 3 keeps
// its existing env name when the sidecar also classifies it as auth-secret.
func authSecretEnvName(slotName string) string {
	trimmed := strings.TrimSpace(slotName)
	if trimmed == "" {
		return "AUTH_SECRET"
	}
	return strings.ToUpper(strings.ReplaceAll(naming.Snake(trimmed), "-", "_"))
}

// sanitizeEvidence walks every RequestEvidence and replaces auth-secret values
// in both Exemplars and Slot.Value with `${ENV_NAME}` placeholders. Returns a
// copy; the original document is not mutated so the caller can still write
// the un-redacted sidecar to disk for debugging / the PR 6 validation gate.
func sanitizeEvidence(doc *wireevidence.Document) *wireevidence.Document {
	if doc == nil {
		return nil
	}
	out := wireevidence.Document{
		Version:  doc.Version,
		Requests: make([]wireevidence.RequestEvidence, len(doc.Requests)),
	}
	for i, req := range doc.Requests {
		out.Requests[i] = sanitizeRequest(req)
	}
	return &out
}

// secretKey identifies one (location, name) slot. Package-level so the
// helper functions can share its type without rebuilding it on every call.
type secretKey struct{ location, name string }

func sanitizeRequest(req wireevidence.RequestEvidence) wireevidence.RequestEvidence {
	// Build the set of (location, name) pairs classified as auth-secret.
	secretKeys := map[secretKey]string{}
	for _, slot := range req.Slots {
		if slot.Classification == wireevidence.ClassAuthSecret {
			secretKeys[secretKey{slot.Location, slot.Name}] = authSecretEnvName(slot.Name)
		}
	}

	out := wireevidence.RequestEvidence{
		Method:         req.Method,
		BaseURL:        req.BaseURL,
		NormalizedPath: req.NormalizedPath,
		Exemplars:      make([]wireevidence.Exemplar, len(req.Exemplars)),
		Slots:          make([]wireevidence.Slot, len(req.Slots)),
	}

	for i, ex := range req.Exemplars {
		out.Exemplars[i] = sanitizeExemplar(ex, secretKeys)
	}
	for i, slot := range req.Slots {
		s := slot
		if slot.Classification == wireevidence.ClassAuthSecret {
			s.Value = placeholderFor(authSecretEnvName(slot.Name))
		}
		out.Slots[i] = s
	}
	return out
}

func sanitizeExemplar(ex wireevidence.Exemplar, secretKeys map[secretKey]string) wireevidence.Exemplar {
	out := wireevidence.Exemplar{URL: ex.URL}
	out.Headers = sanitizeMap(ex.Headers, wireevidence.LocationHeader, secretKeys)
	out.Query = sanitizeMap(ex.Query, wireevidence.LocationQuery, secretKeys)
	out.BodyForm = sanitizeMap(ex.BodyForm, wireevidence.LocationBodyForm, secretKeys)
	out.BodyMulti = sanitizeMap(ex.BodyMulti, wireevidence.LocationBodyMulti, secretKeys)
	return out
}

func sanitizeMap(in map[string]string, location string, secretKeys map[secretKey]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if env, ok := secretKeys[secretKey{location, k}]; ok {
			out[k] = placeholderFor(env)
			continue
		}
		out[k] = v
	}
	return out
}

func placeholderFor(env string) string {
	return "${" + env + "}"
}

// marshalSanitizedEvidence returns the JSON-serialized form of the sanitized
// document, ready to embed.
func marshalSanitizedEvidence(doc *wireevidence.Document) ([]byte, error) {
	if doc == nil {
		return nil, nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling sanitized evidence: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

// emitRequestEvidenceGo writes the sanitized JSON as a Go []byte literal at
// internal/client/request_evidence.gen.go inside outputDir.
func emitRequestEvidenceGo(outputDir string, sanitized []byte) error {
	if len(sanitized) == 0 {
		return nil
	}
	target := filepath.Join(outputDir, "internal", "client", "request_evidence.gen.go")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("creating client dir: %w", err)
	}
	var b strings.Builder
	b.WriteString("// Code generated by cli-printing-press from the request-evidence sidecar; DO NOT EDIT.\n")
	b.WriteString("//\n")
	b.WriteString("// Auth-secret values were redacted with ${ENV_NAME} placeholders before\n")
	b.WriteString("// embed. The un-redacted sidecar remains on disk next to the spec for\n")
	b.WriteString("// debugging and the request-evidence validation gate.\n\n")
	b.WriteString("package client\n\n")
	b.WriteString("var requestEvidenceJSON = []byte(`")
	// Backticks in the JSON would close the raw string. JSON doesn't allow
	// raw backticks in string values anyway (they're emitted as-is since
	// JSON's only escapes are backslash-prefixed), but defensively replace
	// any backtick to keep the literal compilable.
	escaped := strings.ReplaceAll(string(sanitized), "`", "` + \"`\" + `")
	b.WriteString(escaped)
	b.WriteString("`)\n")
	return os.WriteFile(target, []byte(b.String()), 0o644)
}

// overlayEvidenceBaseURLs rewrites every endpoint's BaseURL with the
// matching evidence entry's base_url. Matching is by canonical method + path.
// Endpoints with no matching evidence entry are left alone (PR 2's
// preserve-hosts fallback still applies).
//
// Deprecated: use overlayEvidenceRequestShape, which calls this overlay
// alongside Params / Body / HeaderOverrides / RequestContentType repair.
// Kept as a separate entry point because some test fixtures still target
// it directly.
func overlayEvidenceBaseURLs(g *Generator, doc *wireevidence.Document) {
	if g == nil || g.Spec == nil || doc == nil {
		return
	}
	type key struct{ method, path string }
	byKey := map[key]string{}
	for _, req := range doc.Requests {
		k := key{strings.ToUpper(strings.TrimSpace(req.Method)), req.NormalizedPath}
		if req.BaseURL == "" || k.path == "" {
			continue
		}
		byKey[k] = req.BaseURL
	}
	if len(byKey) == 0 {
		return
	}
	for rname, resource := range g.Spec.Resources {
		modified := false
		for ename, endpoint := range resource.Endpoints {
			k := key{strings.ToUpper(strings.TrimSpace(endpoint.Method)), endpoint.Path}
			if base, ok := byKey[k]; ok && endpoint.BaseURL != base {
				endpoint.BaseURL = base
				resource.Endpoints[ename] = endpoint
				modified = true
			}
		}
		if modified {
			g.Spec.Resources[rname] = resource
		}
	}
}

// overlayEvidenceRequestShape promotes the sidecar from "base-URL repair only"
// (PR 5) to "full request-shape repair" (PR 11). For each spec endpoint that
// matches an evidence RequestEvidence by canonical method + path, the
// overlay:
//
//   - Rewrites BaseURL from the sidecar (same as overlayEvidenceBaseURLs).
//   - Ensures every non-volatile evidence slot is represented somewhere in
//     the spec's surface: query → Endpoint.Params, body_form / body_multipart
//     → Endpoint.Body, semantic-default header → Endpoint.HeaderOverrides.
//   - Removes any spec param / body field that the sidecar classifies as
//     volatile-drop (defense-in-depth — PR 9 already drops these upstream).
//   - Stamps the wireevidence Classification onto matching Param entries so
//     downstream surface walkers can route auth-secret slots to env vars.
//   - Backfills RequestContentType when the spec has body fields but no
//     declared content type and the sidecar carries one body location.
//
// Endpoints with no matching evidence entry are left untouched, matching
// the prior overlay's tolerance for partial sidecars.
//
// The overlay is repair: today's spec (post-PR-7 + post-PR-9) is already
// correct for fresh sniffs. The overlay catches silent drift between the
// spec.yaml on disk and the sidecar (e.g., the user hand-edited spec.yaml,
// or an older generator wrote a stale shape) before the PR 12 validation
// gate fires.
func overlayEvidenceRequestShape(g *Generator, doc *wireevidence.Document) {
	if g == nil || g.Spec == nil || doc == nil {
		return
	}
	overlayEvidenceBaseURLs(g, doc)

	type key struct{ method, path string }
	reqByKey := map[key]wireevidence.RequestEvidence{}
	for _, req := range doc.Requests {
		k := key{strings.ToUpper(strings.TrimSpace(req.Method)), req.NormalizedPath}
		if k.path == "" {
			continue
		}
		reqByKey[k] = req
	}
	if len(reqByKey) == 0 {
		return
	}

	for rname, resource := range g.Spec.Resources {
		modified := false
		for ename, endpoint := range resource.Endpoints {
			k := key{strings.ToUpper(strings.TrimSpace(endpoint.Method)), endpoint.Path}
			req, ok := reqByKey[k]
			if !ok {
				continue
			}
			if applyShapeFromEvidence(&endpoint, req) {
				resource.Endpoints[ename] = endpoint
				modified = true
			}
		}
		if modified {
			g.Spec.Resources[rname] = resource
		}
	}
}

// applyShapeFromEvidence is the per-endpoint overlay body. Returns true when
// any field on the endpoint was mutated, so the caller writes the modified
// copy back into the spec map.
func applyShapeFromEvidence(endpoint *spec.Endpoint, req wireevidence.RequestEvidence) bool {
	if endpoint == nil {
		return false
	}
	modified := false

	// Index existing Params and Body by name for O(1) lookup. The spec
	// stores them as slices; we mutate in place where possible.
	paramIdx := map[string]int{}
	for i, p := range endpoint.Params {
		paramIdx[p.Name] = i
	}
	bodyIdx := map[string]int{}
	for i, p := range endpoint.Body {
		bodyIdx[p.Name] = i
	}
	headerIdx := map[string]int{}
	for i, h := range endpoint.HeaderOverrides {
		headerIdx[strings.ToLower(h.Name)] = i
	}

	for _, slot := range req.Slots {
		switch slot.Classification {
		case wireevidence.ClassVolatileDrop:
			// Defense-in-depth: PR 9 dropped these upstream. If anything
			// slipped through (hand-edited spec, older generator), drop
			// here too.
			switch slot.Location {
			case wireevidence.LocationQuery:
				if i, ok := paramIdx[slot.Name]; ok && !endpoint.Params[i].Positional {
					endpoint.Params = removeParamAt(endpoint.Params, i)
					paramIdx = rebuildParamIdx(endpoint.Params)
					modified = true
				}
			case wireevidence.LocationBodyForm, wireevidence.LocationBodyMulti:
				if i, ok := bodyIdx[slot.Name]; ok {
					endpoint.Body = removeParamAt(endpoint.Body, i)
					bodyIdx = rebuildParamIdx(endpoint.Body)
					modified = true
				}
			case wireevidence.LocationHeader:
				if i, ok := headerIdx[strings.ToLower(slot.Name)]; ok {
					endpoint.HeaderOverrides = append(endpoint.HeaderOverrides[:i], endpoint.HeaderOverrides[i+1:]...)
					headerIdx = rebuildHeaderIdx(endpoint.HeaderOverrides)
					modified = true
				}
			}
			continue

		case wireevidence.ClassProtocolConstant:
			// HTTP-stdlib handles content-negotiation headers already
			// (User-Agent, Accept, ...). Don't pollute HeaderOverrides
			// with them — the runtime stamps them.
			continue
		}

		// Non-volatile, non-protocol-constant slots must be represented.
		switch slot.Location {
		case wireevidence.LocationQuery:
			if _, ok := paramIdx[slot.Name]; !ok {
				endpoint.Params = append(endpoint.Params, spec.Param{
					Name: slot.Name,
					Type: "string",
					ContentLocation: "query",
					Classification: slot.Classification,
				})
				paramIdx[slot.Name] = len(endpoint.Params) - 1
				modified = true
			} else if endpoint.Params[paramIdx[slot.Name]].Classification == "" && slot.Classification != "" {
				endpoint.Params[paramIdx[slot.Name]].Classification = slot.Classification
				modified = true
			}
		case wireevidence.LocationBodyForm:
			if _, ok := bodyIdx[slot.Name]; !ok {
				endpoint.Body = append(endpoint.Body, spec.Param{
					Name: slot.Name,
					Type: "string",
					ContentLocation: "body_form",
					Classification: slot.Classification,
				})
				bodyIdx[slot.Name] = len(endpoint.Body) - 1
				modified = true
			} else if endpoint.Body[bodyIdx[slot.Name]].Classification == "" && slot.Classification != "" {
				endpoint.Body[bodyIdx[slot.Name]].Classification = slot.Classification
				modified = true
			}
		case wireevidence.LocationBodyMulti:
			if _, ok := bodyIdx[slot.Name]; !ok {
				endpoint.Body = append(endpoint.Body, spec.Param{
					Name: slot.Name,
					Type: "string",
					ContentLocation: "body_multipart",
					Classification: slot.Classification,
				})
				bodyIdx[slot.Name] = len(endpoint.Body) - 1
				modified = true
			} else if endpoint.Body[bodyIdx[slot.Name]].Classification == "" && slot.Classification != "" {
				endpoint.Body[bodyIdx[slot.Name]].Classification = slot.Classification
				modified = true
			}
		case wireevidence.LocationHeader:
			// Only surface semantic-default headers as overrides; auth-secret
			// headers (Authorization, DD-API-KEY, ...) are handled by the
			// AuthConfig machinery, not per-endpoint overrides.
			if slot.Classification != wireevidence.ClassSemanticDefault {
				continue
			}
			if _, ok := headerIdx[strings.ToLower(slot.Name)]; !ok {
				endpoint.HeaderOverrides = append(endpoint.HeaderOverrides, spec.RequiredHeader{
					Name:  slot.Name,
					Value: slot.Value,
				})
				headerIdx[strings.ToLower(slot.Name)] = len(endpoint.HeaderOverrides) - 1
				modified = true
			}
		}
	}

	// Backfill RequestContentType from a single body location if absent.
	if strings.TrimSpace(endpoint.RequestContentType) == "" && len(endpoint.Body) > 0 {
		mp, form := 0, 0
		for _, b := range endpoint.Body {
			switch b.ContentLocation {
			case "body_multipart":
				mp++
			case "body_form":
				form++
			}
		}
		switch {
		case mp > 0 && form == 0:
			endpoint.RequestContentType = "multipart/form-data"
			modified = true
		case form > 0 && mp == 0:
			endpoint.RequestContentType = "application/x-www-form-urlencoded"
			modified = true
		}
	}

	return modified
}

func removeParamAt(s []spec.Param, i int) []spec.Param {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

func rebuildParamIdx(params []spec.Param) map[string]int {
	out := map[string]int{}
	for i, p := range params {
		out[p.Name] = i
	}
	return out
}

func rebuildHeaderIdx(headers []spec.RequiredHeader) map[string]int {
	out := map[string]int{}
	for i, h := range headers {
		out[strings.ToLower(h.Name)] = i
	}
	return out
}

// applyRequestEvidence loads the sidecar referenced by RequestEvidencePath,
// overlays per-endpoint BaseURLs, sanitizes the document, and writes the
// embedded Go source file. Silent no-op when the spec source isn't sniffed
// or when no sidecar is configured / present.
func (g *Generator) applyRequestEvidence() error {
	if g == nil || g.Spec == nil {
		return nil
	}
	if !specSourceIsSniffed(g.Spec.SpecSource) {
		return nil
	}
	doc, err := loadEvidenceFromPath(g.RequestEvidencePath)
	if err != nil {
		return err
	}
	if doc == nil || len(doc.Requests) == 0 {
		return nil
	}
	overlayEvidenceRequestShape(g, doc)
	sanitized := sanitizeEvidence(doc)
	data, err := marshalSanitizedEvidence(sanitized)
	if err != nil {
		return err
	}
	return emitRequestEvidenceGo(g.OutputDir, data)
}

// specSourceIsSniffed returns true for any sniffed alias. The CLI normalizes
// "browser-sniffed" to "sniffed" at parse time, but the generator may also be
// invoked directly via library tooling that retains the longer form.
func specSourceIsSniffed(specSource string) bool {
	switch strings.ToLower(strings.TrimSpace(specSource)) {
	case "sniffed", "browser-sniffed":
		return true
	}
	return false
}
