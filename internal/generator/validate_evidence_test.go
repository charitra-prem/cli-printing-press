package generator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

func writeSidecar(t *testing.T, dir string, requests []wireevidence.RequestEvidence) string {
	t.Helper()
	sidecar := filepath.Join(dir, "spec-request-evidence.json")
	data, err := json.Marshal(&wireevidence.Document{Version: wireevidence.FormatVersion, Requests: requests})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sidecar, data, 0o600))
	return sidecar
}

// TestValidateRequestEvidence_PassesForFaithfulSidecar pins the happy path:
// a sidecar whose exemplars round-trip cleanly through the wireevidence
// vocabulary does not fail the gate. Mirrors the shape of a real sniff
// output (form-body endpoint with auth-secret + semantic-default slots).
func TestValidateRequestEvidence_PassesForFaithfulSidecar(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exemplar := wireevidence.Exemplar{
		URL: "https://api.example.com/v1/items?limit=20",
		Headers: map[string]string{
			"Accept":        "application/json",
			"Authorization": "Bearer eyJabc.def.ghi",
		},
		BodyForm: map[string]string{
			"locale": "en-US",
			"token":  "xoxc-secret-1-2-3",
		},
	}
	req := wireevidence.RequestEvidence{
		Method:         "POST",
		BaseURL:        "https://api.example.com",
		NormalizedPath: "/v1/items",
		Exemplars:      []wireevidence.Exemplar{exemplar},
		Slots:          wireevidence.BuildSlots([]wireevidence.Exemplar{exemplar}),
	}
	sidecar := writeSidecar(t, dir, []wireevidence.RequestEvidence{req})

	g := &Generator{
		Spec:                &spec.APISpec{Name: "x", SpecSource: "sniffed"},
		RequestEvidencePath: sidecar,
	}
	require.NoError(t, g.validateRequestEvidence())
}

// TestValidateRequestEvidence_NonSniffedNoOp confirms the gate is a true
// no-op for non-sniffed sources so it adds zero latency to the
// overwhelming majority of generate runs.
func TestValidateRequestEvidence_NonSniffedNoOp(t *testing.T) {
	t.Parallel()
	g := &Generator{Spec: &spec.APISpec{Name: "x", SpecSource: "official"}}
	require.NoError(t, g.validateRequestEvidence())
}

// TestValidateRequestEvidence_NoSidecarNoOp ensures that a sniffed spec
// without an evidence sidecar still passes (sidecar adoption is opt-in;
// older sniffed CLIs regenerated without re-sniffing must not hard-fail).
func TestValidateRequestEvidence_NoSidecarNoOp(t *testing.T) {
	t.Parallel()
	g := &Generator{
		Spec:                &spec.APISpec{Name: "x", SpecSource: "sniffed"},
		RequestEvidencePath: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}
	require.NoError(t, g.validateRequestEvidence())
}

// TestValidateRequestEvidence_CatchesAuthSecretValueDrift simulates a real
// regression: the captured exemplar's Authorization value diverges from
// what the auth-value harvester finds. This shape catches PR 5 redaction
// bugs that mutate the value before it lands in the embedded sidecar.
func TestValidateRequestEvidence_CatchesAuthSecretValueDrift(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Two exemplars: the first has the real auth value (which the
	// harvester records as the canonical), the second carries a stale /
	// rotated value. The compare against the second exemplar fires
	// because the harvester resolves to exemplar-1's value but
	// exemplar-2's recorded value differs.
	exemplar1 := wireevidence.Exemplar{
		URL: "https://api.example.com/v1/items",
		Headers: map[string]string{
			"Authorization": "Bearer eyJrealsession.payload.sig",
		},
	}
	exemplar2 := wireevidence.Exemplar{
		URL: "https://api.example.com/v1/items",
		Headers: map[string]string{
			"Authorization": "Bearer eyJrotatedsession.payload.sig",
		},
	}
	req := wireevidence.RequestEvidence{
		Method:    "GET",
		Exemplars: []wireevidence.Exemplar{exemplar1, exemplar2},
		Slots:     wireevidence.BuildSlots([]wireevidence.Exemplar{exemplar1, exemplar2}),
	}
	sidecar := writeSidecar(t, dir, []wireevidence.RequestEvidence{req})

	g := &Generator{
		Spec:                &spec.APISpec{Name: "x", SpecSource: "sniffed"},
		RequestEvidencePath: sidecar,
	}
	err := g.validateRequestEvidence()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "headers")
	assert.Contains(t, err.Error(), "Authorization")
}

// TestValidateRequestEvidence_CatchesConstantValueDrift simulates the PR 4
// classifier mislabeling a constant-classed slot — recording one value in
// the Slot.Value field while the exemplar carries another. The gate must
// fire so the generator refuses to embed a sidecar whose classification
// contradicts the wire.
func TestValidateRequestEvidence_CatchesConstantValueDrift(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	req := wireevidence.RequestEvidence{
		Method: "GET",
		Exemplars: []wireevidence.Exemplar{
			{
				URL:     "https://api.example.com/v1/items",
				Headers: map[string]string{"Accept": "application/json"},
			},
		},
		Slots: []wireevidence.Slot{
			{Location: wireevidence.LocationHeader, Name: "Accept", Classification: wireevidence.ClassProtocolConstant, Constant: true, Value: "text/html"},
		},
	}
	sidecar := writeSidecar(t, dir, []wireevidence.RequestEvidence{req})

	g := &Generator{
		Spec:                &spec.APISpec{Name: "x", SpecSource: "sniffed"},
		RequestEvidencePath: sidecar,
	}
	err := g.validateRequestEvidence()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "headers")
	assert.Contains(t, err.Error(), "Accept")
}

// TestValidateRequestEvidence_MalformedSidecarSurfacesError ensures the
// gate fails loudly when the on-disk sidecar can't be parsed, rather
// than silently swallowing a corrupted artifact.
func TestValidateRequestEvidence_MalformedSidecarSurfacesError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sidecar := filepath.Join(dir, "spec-request-evidence.json")
	require.NoError(t, os.WriteFile(sidecar, []byte("{not json"), 0o600))
	g := &Generator{
		Spec:                &spec.APISpec{Name: "x", SpecSource: "sniffed"},
		RequestEvidencePath: sidecar,
	}
	err := g.validateRequestEvidence()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing request evidence")
}

// TestCapturedAuthValuesFromExemplars_HarvestsAcrossExemplars confirms the
// harvester reads the first non-empty value seen in any exemplar so a
// sidecar with one captured request still resolves its auth slots.
func TestCapturedAuthValuesFromExemplars_HarvestsAcrossExemplars(t *testing.T) {
	t.Parallel()
	req := wireevidence.RequestEvidence{
		Slots: []wireevidence.Slot{
			{Location: wireevidence.LocationBodyMulti, Name: "token", Classification: wireevidence.ClassAuthSecret, Constant: true},
		},
		Exemplars: []wireevidence.Exemplar{
			{BodyMulti: map[string]string{}},
			{BodyMulti: map[string]string{"token": "xoxc-found"}},
		},
	}
	got := capturedAuthValuesFromExemplars(req)
	assert.Equal(t, map[string]string{"token": "xoxc-found"}, got)
}
