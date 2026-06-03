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
	overlayEvidenceBaseURLs(g, doc)
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
