// Tests for overlayEvidenceRequestShape (PR 11). The overlay promotes the
// request-evidence sidecar from "BaseURL repair only" (PR 5) to "full
// request-shape repair" so the spec.yaml stays the generator IR while the
// sidecar is the wire authority. These unit tests pin three properties:
//
//  1. A spec missing a body field is repaired from the sidecar so the body
//     walker sees the slot before it emits CLI flags / MCP descriptors.
//  2. A spec carrying a volatile-classed param is stripped to match the
//     sidecar's volatile-drop decision (defense-in-depth: PR 9 already drops
//     these upstream, but a hand-edited spec.yaml can reintroduce them).
//  3. A spec already in sync round-trips unchanged: every non-volatile
//     evidence slot maps to a Params / Body / HeaderOverrides entry; every
//     volatile-drop slot is absent.
package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

func newSniffedGenWithEndpoint(t *testing.T, ep spec.Endpoint) *Generator {
	t.Helper()
	api := &spec.APISpec{
		Name:       "x",
		SpecSource: "sniffed",
		Resources: map[string]spec.Resource{
			"r": {Endpoints: map[string]spec.Endpoint{"e": ep}},
		},
	}
	return &Generator{Spec: api}
}

func endpointFromGen(t *testing.T, g *Generator) spec.Endpoint {
	t.Helper()
	r, ok := g.Spec.Resources["r"]
	require.True(t, ok)
	require.Len(t, r.Endpoints, 1)
	return r.Endpoints["e"]
}

// TestOverlayRequestShape_PopulatesMissingBodyParam confirms a sidecar slot
// at body_multipart materializes into Endpoint.Body when the spec doesn't
// already carry it. Catches the failure mode where the parser dropped the
// field (older browsersniff binary) but the sidecar still records it.
func TestOverlayRequestShape_PopulatesMissingBodyParam(t *testing.T) {
	t.Parallel()
	g := newSniffedGenWithEndpoint(t, spec.Endpoint{
		Method: "POST",
		Path:   "/api/conversations.history",
		Body:   nil,
	})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			BaseURL:        "https://api.example.com",
			NormalizedPath: "/api/conversations.history",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationBodyMulti, Name: "channel", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "C123"},
			},
		}},
	}
	overlayEvidenceRequestShape(g, doc)

	ep := endpointFromGen(t, g)
	require.Len(t, ep.Body, 1)
	assert.Equal(t, "channel", ep.Body[0].Name)
	assert.Equal(t, spec.ParamLocationBodyMultipart, ep.Body[0].ContentLocation)
	assert.Equal(t, "multipart/form-data", ep.RequestContentType)
}

// TestOverlayRequestShape_RemovesVolatileQueryParam pins the defense-in-
// depth removal path: the sidecar classifies a slot volatile-drop and the
// spec still carries it as a Param. After overlay, the spec must be free of
// that param so it never reaches CLI flag emission.
func TestOverlayRequestShape_RemovesVolatileQueryParam(t *testing.T) {
	t.Parallel()
	g := newSniffedGenWithEndpoint(t, spec.Endpoint{
		Method: "POST",
		Path:   "/api/conversations.history",
		Params: []spec.Param{
			{Name: "channel", Type: "string", ContentLocation: "query"},
			{Name: "_x_b3_traceid", Type: "string", ContentLocation: "query"},
		},
	})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			BaseURL:        "https://api.example.com",
			NormalizedPath: "/api/conversations.history",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationQuery, Name: "channel", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "C123"},
				{Location: wireevidence.LocationQuery, Name: "_x_b3_traceid", Classification: wireevidence.ClassVolatileDrop},
			},
		}},
	}
	overlayEvidenceRequestShape(g, doc)

	ep := endpointFromGen(t, g)
	names := []string{}
	for _, p := range ep.Params {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"channel"}, names, "volatile param must be stripped")
}

// TestOverlayRequestShape_NoOpWhenInSync round-trips a spec whose Params /
// Body / HeaderOverrides already mirror the sidecar. The overlay must not
// mutate it (no double-inserts, no spurious classification stamps when one
// is already present).
func TestOverlayRequestShape_NoOpWhenInSync(t *testing.T) {
	t.Parallel()
	g := newSniffedGenWithEndpoint(t, spec.Endpoint{
		Method:             "POST",
		Path:               "/api/conversations.history",
		BaseURL:            "https://api.example.com",
		RequestContentType: "multipart/form-data",
		Body: []spec.Param{
			{Name: "channel", Type: "string", ContentLocation: "body_multipart", Classification: spec.ParamClassSemanticDefault},
			{Name: "token", Type: "string", ContentLocation: "body_multipart", Classification: spec.ParamClassAuthSecret},
		},
		HeaderOverrides: []spec.RequiredHeader{
			{Name: "X-Slack-Version", Value: "v1"},
		},
	})
	doc := &wireevidence.Document{
		Version: wireevidence.FormatVersion,
		Requests: []wireevidence.RequestEvidence{{
			Method:         "POST",
			BaseURL:        "https://api.example.com",
			NormalizedPath: "/api/conversations.history",
			Slots: []wireevidence.Slot{
				{Location: wireevidence.LocationBodyMulti, Name: "channel", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "C123"},
				{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret},
				{Location: wireevidence.LocationHeader, Name: "X-Slack-Version", Classification: wireevidence.ClassSemanticDefault, Constant: true, Value: "v1"},
				{Location: wireevidence.LocationHeader, Name: "Accept", Classification: wireevidence.ClassProtocolConstant, Constant: true, Value: "application/json"},
				{Location: wireevidence.LocationQuery, Name: "_x_b3_traceid", Classification: wireevidence.ClassVolatileDrop},
			},
		}},
	}
	overlayEvidenceRequestShape(g, doc)

	ep := endpointFromGen(t, g)
	require.Len(t, ep.Body, 2, "body must keep both non-volatile slots without duplication")
	require.Len(t, ep.HeaderOverrides, 1, "header overrides untouched")
	assert.Empty(t, ep.Params, "no volatile slot should sneak in as a param")
	// Protocol-constant header must NOT be added to HeaderOverrides (the
	// runtime stamps Accept itself).
	for _, h := range ep.HeaderOverrides {
		assert.NotEqualValues(t, "Accept", h.Name)
	}
}

// TestOverlayRequestShape_StampsClassificationOnExistingParam catches the
// case where the spec has the param but no classification metadata (older
// generator). The overlay should backfill the classification so downstream
// auth-secret routing fires correctly.
func TestOverlayRequestShape_StampsClassificationOnExistingParam(t *testing.T) {
	t.Parallel()
	g := newSniffedGenWithEndpoint(t, spec.Endpoint{
		Method: "POST",
		Path:   "/api/x",
		Body: []spec.Param{
			{Name: "token", Type: "string", ContentLocation: "body_multipart"},
		},
	})
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
	overlayEvidenceRequestShape(g, doc)

	ep := endpointFromGen(t, g)
	require.Len(t, ep.Body, 1)
	assert.Equal(t, spec.ParamClassAuthSecret, ep.Body[0].Classification)
}
