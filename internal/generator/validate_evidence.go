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
	"strings"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
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

	// PR 12 — surface-coverage assertion. After PR 9 (suppression) and PR 11
	// (overlay) the spec.yaml on disk should already mirror the sidecar's
	// non-volatile slots and exclude its volatile-drop slots. The gate
	// guards against regressions where a future spec edit silently drops a
	// captured slot (missing --channel) or reintroduces a volatile one
	// (--x-b3-traceid leaks back into the CLI).
	if err := assertEvidenceSurfaceCoverage(g.Spec, doc); err != nil {
		return err
	}
	return nil
}

// assertEvidenceSurfaceCoverage walks every non-volatile evidence slot and
// confirms it is represented somewhere in the rendered APISpec surface
// (Endpoint.Params, Endpoint.Body, Endpoint.HeaderOverrides, Auth.EnvVars,
// or Auth.AdditionalHeaders). Conversely, every volatile-drop slot must be
// ABSENT from the same surface. Returns the first violation found.
//
// Matching strategy:
//   - Find each evidence RequestEvidence's matching spec.Endpoint by
//     canonical method + normalized_path. Sidecar entries with no matching
//     endpoint are tolerated (the spec may have pruned the endpoint after
//     capture; the slot is still recorded for audit but isn't checked).
//   - Protocol-constant slots are skipped: the http stdlib stamps them at
//     runtime regardless of spec contents.
//   - Auth-secret slots are satisfied either by an env-var entry on the
//     spec's Auth (typical) or by a Param with classification=auth-secret
//     (body-field-as-secret case from PR 3).
func assertEvidenceSurfaceCoverage(apiSpec *spec.APISpec, doc *wireevidence.Document) error {
	if apiSpec == nil || doc == nil {
		return nil
	}

	type key struct{ method, path string }
	endpointByKey := map[key]spec.Endpoint{}
	for _, resource := range apiSpec.Resources {
		for _, ep := range resource.Endpoints {
			endpointByKey[key{strings.ToUpper(strings.TrimSpace(ep.Method)), ep.Path}] = ep
		}
	}

	authEnvVarNames := map[string]struct{}{}
	for _, v := range apiSpec.Auth.EnvVars {
		authEnvVarNames[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}
	for _, ah := range apiSpec.Auth.AdditionalHeaders {
		authEnvVarNames[strings.ToUpper(strings.TrimSpace(ah.Header))] = struct{}{}
	}
	authHeaderNames := map[string]struct{}{}
	if h := strings.TrimSpace(apiSpec.Auth.Header); h != "" {
		authHeaderNames[strings.ToLower(h)] = struct{}{}
	}
	for _, ah := range apiSpec.Auth.AdditionalHeaders {
		if h := strings.TrimSpace(ah.Header); h != "" {
			authHeaderNames[strings.ToLower(h)] = struct{}{}
		}
	}

	for _, req := range doc.Requests {
		ep, ok := endpointByKey[key{strings.ToUpper(strings.TrimSpace(req.Method)), req.NormalizedPath}]
		if !ok {
			// No matching endpoint; nothing to assert on. Allowed because
			// some sidecar entries pre-date a spec prune.
			continue
		}
		for _, slot := range req.Slots {
			if err := assertSlotSurfaceCoverage(req, ep, slot, authEnvVarNames, authHeaderNames); err != nil {
				return err
			}
		}
	}
	return nil
}

func assertSlotSurfaceCoverage(req wireevidence.RequestEvidence, ep spec.Endpoint, slot wireevidence.Slot, authEnvs, authHeaders map[string]struct{}) error {
	switch slot.Classification {
	case wireevidence.ClassProtocolConstant:
		// http stdlib stamps these; no surface entry required.
		return nil
	case wireevidence.ClassVolatileDrop:
		if slotIsPresentOnSurface(slot, ep, authEnvs, authHeaders) {
			return fmt.Errorf("endpoint %s %s: volatile slot %s:%s leaked into CLI surface",
				req.Method, req.NormalizedPath, slot.Location, slot.Name)
		}
		return nil
	}
	if !slotIsPresentOnSurface(slot, ep, authEnvs, authHeaders) {
		return fmt.Errorf("endpoint %s %s: evidence slot %s:%s (class=%s) not represented in CLI surface",
			req.Method, req.NormalizedPath, slot.Location, slot.Name, slot.Classification)
	}
	return nil
}

func slotIsPresentOnSurface(slot wireevidence.Slot, ep spec.Endpoint, authEnvs, authHeaders map[string]struct{}) bool {
	switch slot.Location {
	case wireevidence.LocationQuery:
		for _, p := range ep.Params {
			if p.Name == slot.Name {
				return true
			}
		}
	case wireevidence.LocationBodyForm, wireevidence.LocationBodyMulti:
		for _, p := range ep.Body {
			if p.Name == slot.Name {
				return true
			}
		}
	case wireevidence.LocationHeader:
		for _, h := range ep.HeaderOverrides {
			if strings.EqualFold(h.Name, slot.Name) {
				return true
			}
		}
		// Auth headers (Authorization, DD-API-KEY, Cookie, ...) live on
		// the spec's AuthConfig rather than HeaderOverrides.
		if _, ok := authHeaders[strings.ToLower(slot.Name)]; ok {
			return true
		}
		// auth-secret slots that ride on a header may be tracked via an
		// env-var-derived name on AuthConfig.EnvVars.
		if slot.Classification == wireevidence.ClassAuthSecret {
			candidate := strings.ToUpper(strings.ReplaceAll(slot.Name, "-", "_"))
			if _, ok := authEnvs[candidate]; ok {
				return true
			}
			// Any auth env var being declared is enough for the canonical
			// Authorization header case (env is named TOKEN / API_KEY, not
			// AUTHORIZATION).
			if strings.EqualFold(slot.Name, "Authorization") && len(authEnvs) > 0 {
				return true
			}
		}
	case wireevidence.LocationURLUserinfo:
		// URL userinfo is always auth-secret; satisfied by any auth env var.
		if len(authEnvs) > 0 {
			return true
		}
	}
	// Auth-secret body/query slots can also be represented as a Param with
	// classification=auth-secret (PR 3 routes them to env vars rather than
	// public --flag values).
	if slot.Classification == wireevidence.ClassAuthSecret {
		for _, p := range ep.Body {
			if p.Name == slot.Name && p.Classification == spec.ParamClassAuthSecret {
				return true
			}
		}
		for _, p := range ep.Params {
			if p.Name == slot.Name && p.Classification == spec.ParamClassAuthSecret {
				return true
			}
		}
	}
	return false
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
