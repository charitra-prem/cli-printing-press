// Request-evidence wire-fidelity gate (PR 6 of the request-evidence plan).
//
// For browser-sniffed CLIs that ship with a *-request-evidence.json sidecar,
// the gate confirms that every captured exemplar round-trips through the
// wireevidence vocabulary without losing wire information. Regressions in
// PRs 1–5 (body parsing, slot classification, redaction round-trip) surface
// as exemplar drift the gate refuses to ship.
//
// Offline only: no network IO. The un-redacted on-disk sidecar is the
// source of truth for both the slot model AND the auth-secret values used
// to fill placeholders before comparison.
package generator

import (
	"fmt"

	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

// validateRequestEvidence runs the wire-fidelity gate. Returns nil when the
// CLI has no sidecar (non-sniffed sources, or sniffed sources with no
// evidence on disk) so the gate is safe to wire unconditionally into the
// existing Validate() pipeline.
func (g *Generator) validateRequestEvidence() error {
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

	for _, req := range doc.Requests {
		authValues := capturedAuthValuesFromExemplars(req)
		for i, exemplar := range req.Exemplars {
			if err := wireevidence.CompareRequestAgainstExemplar(req, exemplar, authValues); err != nil {
				return fmt.Errorf("evidence entry %s %s%s exemplar %d: %w",
					req.Method, req.BaseURL, req.NormalizedPath, i, err)
			}
		}
	}
	return nil
}

// capturedAuthValuesFromExemplars collects every auth-secret slot's value
// from the first exemplar that recorded one. The un-redacted sidecar on
// disk is the source of truth: the slot's Value field is empty for
// auth-secret slots (by classifier convention), so we walk the exemplar
// maps directly.
func capturedAuthValuesFromExemplars(req wireevidence.RequestEvidence) map[string]string {
	out := map[string]string{}
	authNames := map[string]struct{}{}
	for _, s := range req.Slots {
		if s.Classification == wireevidence.ClassAuthSecret {
			authNames[locationNameKey(s.Location, s.Name)] = struct{}{}
		}
	}
	if len(authNames) == 0 {
		return nil
	}
	for _, ex := range req.Exemplars {
		harvest := func(location string, in map[string]string) {
			for name, value := range in {
				if _, ok := authNames[locationNameKey(location, name)]; !ok {
					continue
				}
				if _, already := out[name]; already {
					continue
				}
				if value == "" {
					continue
				}
				out[name] = value
			}
		}
		harvest(wireevidence.LocationHeader, ex.Headers)
		harvest(wireevidence.LocationQuery, ex.Query)
		harvest(wireevidence.LocationBodyForm, ex.BodyForm)
		harvest(wireevidence.LocationBodyMulti, ex.BodyMulti)
	}
	return out
}

func locationNameKey(location, name string) string {
	return location + "|" + name
}
