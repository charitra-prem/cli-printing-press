package browsersniff

import (
	"path/filepath"
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Adversarial fixture tests cover ill-shaped captures that real browsers
// emit by mistake (boundary mismatches, content-type omissions, single
// exemplars with conflicting name-vs-value signals). Each must:
//   - parse without panic
//   - emit a spec without inventing body fields the wire didn't carry
//   - leave the classifier on its documented behavior
//
// These fixtures live under testdata/sniff/adversarial/ to keep them
// distinct from the matrix fixtures (which represent real-world APIs).

const adversarialDir = "../../testdata/sniff/adversarial"

func loadAdversarialSpec(t *testing.T, fixture string) (*EnrichedCapture, evidenceResult) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(adversarialDir, fixture))
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	capture, err := LoadCapture(abs)
	require.NoError(t, err)

	apiSpec, err := AnalyzeCaptureWithOptions(capture, AnalyzeOptions{PreserveHosts: true})
	require.NoError(t, err)
	require.NotNil(t, apiSpec)

	evidence := BuildRequestEvidenceFromCapture(capture, AnalyzeOptions{PreserveHosts: true})
	return capture, evidenceResult{apiSpec: apiSpec, evidence: evidence}
}

type evidenceResult struct {
	apiSpec  *spec.APISpec
	evidence []wireevidence.RequestEvidence
}

// TestAdversarial_MalformedMultipart_NoBodyFields pins that a multipart
// body with a boundary mismatch (header declares ----GoodBoundary, body
// uses ----WrongBoundary) parses without panic and yields zero body
// slots. The classifier never invents fields from corrupted input.
func TestAdversarial_MalformedMultipart_NoBodyFields(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "malformed-multipart.har")

	require.Len(t, result.evidence, 1)
	for _, ex := range result.evidence[0].Exemplars {
		assert.Empty(t, ex.BodyMulti, "malformed multipart must yield zero body fields")
		assert.Empty(t, ex.BodyForm, "malformed multipart must not fall back to form parsing")
	}
	for _, slot := range result.evidence[0].Slots {
		assert.NotEqual(t, wireevidence.LocationBodyMulti, slot.Location,
			"no body_multipart slots should reach evidence for malformed body")
		assert.NotEqual(t, wireevidence.LocationBodyForm, slot.Location,
			"no body_form slots should reach evidence for malformed body")
	}
}

// TestAdversarial_BodyWithoutContentType pins that a POST with a body
// but no Content-Type header yields zero body slots — the parser does
// not guess body shape from text content. Adding a guessing fallback in
// the future requires explicit design, not silent inference.
func TestAdversarial_BodyWithoutContentType(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "body-without-content-type.har")

	require.Len(t, result.evidence, 1)
	for _, ex := range result.evidence[0].Exemplars {
		assert.Empty(t, ex.BodyMulti)
		assert.Empty(t, ex.BodyForm)
	}
	for _, slot := range result.evidence[0].Slots {
		assert.NotEqual(t, wireevidence.LocationBodyMulti, slot.Location)
		assert.NotEqual(t, wireevidence.LocationBodyForm, slot.Location)
	}
}

// TestAdversarial_SingleExemplarNameConflict pins PR 4's documented
// behavior: when one exemplar carries a header whose name matches the
// volatile pattern (x-b3-traceid) AND the value is identical to itself
// (vacuously constant across the single exemplar), name-pattern wins
// and the slot classifies as volatile-drop. This guards against a
// regression where a future "constant value → semantic-default" shortcut
// is added without consulting the name-pattern rule first.
func TestAdversarial_SingleExemplarNameConflict_NameWins(t *testing.T) {
	t.Parallel()
	_, result := loadAdversarialSpec(t, "single-exemplar-name-conflict.har")

	require.Len(t, result.evidence, 1)
	var trace wireevidence.Slot
	for _, slot := range result.evidence[0].Slots {
		if slot.Location == wireevidence.LocationHeader && slot.Name == "x-b3-traceid" {
			trace = slot
			break
		}
	}
	require.NotEmpty(t, trace.Name, "x-b3-traceid slot must appear in the evidence sidecar")
	assert.Equal(t, wireevidence.ClassVolatileDrop, trace.Classification,
		"x-b3-traceid name-pattern must win over single-exemplar constancy")
	assert.Empty(t, trace.Value, "volatile-drop slots must not record a value, even when constant")
}
