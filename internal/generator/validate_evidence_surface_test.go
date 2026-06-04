// Tests for PR 12 — surface coverage in validateRequestEvidence. The
// existing validate_evidence_test.go pins the PR 6 wire-comparison gate;
// these tests pin the additional assertion that every non-volatile
// evidence slot is represented in the rendered APISpec and every
// volatile-drop slot is absent.
package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

func newSurfaceSpec(ep spec.Endpoint, auth spec.AuthConfig) *spec.APISpec {
	return &spec.APISpec{
		Name:       "x",
		SpecSource: "sniffed",
		Auth:       auth,
		Resources: map[string]spec.Resource{
			"r": {Endpoints: map[string]spec.Endpoint{"e": ep}},
		},
	}
}

// TestValidateRequestEvidence_FailsWhenSemanticSlotMissingFromSurface
// constructs a sidecar with a semantic-default body slot and a spec
// without that slot. The gate must fire so the printed CLI doesn't ship
// without `--channel` even though the wire requires it.
func TestValidateRequestEvidence_FailsWhenSemanticSlotMissingFromSurface(t *testing.T) {
	t.Parallel()
	ep := spec.Endpoint{Method: "POST", Path: "/api/x"} // empty Body
	apiSpec := newSurfaceSpec(ep, spec.AuthConfig{Type: spec.TierAuthTypeBearerToken, Header: "Authorization", EnvVars: []string{"TOKEN"}})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			NormalizedPath: "/api/x",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationBodyMulti, Name: "channel", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "C123"},
			},
			Exemplars: []wireevidence.Exemplar{{URL: "https://h/api/x", BodyMulti: map[string]string{"channel": "C123"}}},
		}},
	}

	err := assertEvidenceSurfaceCoverage(apiSpec, doc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "channel")
	assert.Contains(t, err.Error(), "not represented")
}

// TestValidateRequestEvidence_FailsWhenVolatileSlotLeakedToSurface
// constructs a sidecar with a volatile-drop slot and a spec that
// accidentally still carries it as a Param. The gate must fire so
// telemetry slots can't slip back into the CLI through a hand-edited
// spec.yaml.
func TestValidateRequestEvidence_FailsWhenVolatileSlotLeakedToSurface(t *testing.T) {
	t.Parallel()
	ep := spec.Endpoint{
		Method: "POST",
		Path:   "/api/x",
		Params: []spec.Param{{Name: "_x_b3_traceid", Type: "string", ContentLocation: "query"}},
	}
	apiSpec := newSurfaceSpec(ep, spec.AuthConfig{Type: spec.TierAuthTypeBearerToken, Header: "Authorization", EnvVars: []string{"TOKEN"}})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			NormalizedPath: "/api/x",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationQuery, Name: "_x_b3_traceid", Classification: wireevidence.ClassVolatileDrop},
			},
		}},
	}

	err := assertEvidenceSurfaceCoverage(apiSpec, doc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "_x_b3_traceid")
	assert.Contains(t, err.Error(), "leaked")
}

// TestValidateRequestEvidence_PassesWhenEveryNonVolatileSlotRepresented
// pins the happy path: spec carries each non-volatile slot as a Param /
// Body / HeaderOverride / auth env var, and the volatile slot is absent.
// The gate returns nil.
func TestValidateRequestEvidence_PassesWhenEveryNonVolatileSlotRepresented(t *testing.T) {
	t.Parallel()
	ep := spec.Endpoint{
		Method: "POST",
		Path:   "/api/x",
		Body: []spec.Param{
			{Name: "channel", Type: "string", ContentLocation: "body_multipart"},
			{Name: "token", Type: "string", ContentLocation: "body_multipart", Classification: spec.ParamClassAuthSecret},
		},
		HeaderOverrides: []spec.RequiredHeader{
			{Name: "X-Slack-Version", Value: "v1"},
		},
	}
	apiSpec := newSurfaceSpec(ep, spec.AuthConfig{
		Type:    spec.TierAuthTypeBearerToken,
		Header:  "Authorization",
		EnvVars: []string{"TOKEN"},
	})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			NormalizedPath: "/api/x",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationBodyMulti, Name: "channel", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "C1"},
				{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret},
				{Location: wireevidence.LocationHeader, Name: "X-Slack-Version", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "v1"},
				{Location: wireevidence.LocationHeader, Name: "Accept", Classification: wireevidence.ClassProtocolConstant, Constant: true, Value: "application/json"},
				{Location: wireevidence.LocationHeader, Name: "Authorization", Classification: wireevidence.ClassAuthSecret},
				{Location: wireevidence.LocationQuery, Name: "_x_b3_traceid", Classification: wireevidence.ClassVolatileDrop},
			},
		}},
	}

	require.NoError(t, assertEvidenceSurfaceCoverage(apiSpec, doc))
}

// TestValidateRequestEvidence_AuthSecretBodyAsParamSatisfiesGate covers the
// PR 3 case where a body field (e.g. Slack's `token`) is classified
// auth-secret on the spec param itself. The gate must accept this as
// coverage for the matching evidence slot, since codegen routes it to env
// vars rather than a public --flag.
func TestValidateRequestEvidence_AuthSecretBodyAsParamSatisfiesGate(t *testing.T) {
	t.Parallel()
	ep := spec.Endpoint{
		Method: "POST",
		Path:   "/api/x",
		Body: []spec.Param{
			{Name: "token", Type: "string", ContentLocation: "body_multipart", Classification: spec.ParamClassAuthSecret},
		},
	}
	apiSpec := newSurfaceSpec(ep, spec.AuthConfig{})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			NormalizedPath: "/api/x",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret},
			},
		}},
	}
	require.NoError(t, assertEvidenceSurfaceCoverage(apiSpec, doc))
}
