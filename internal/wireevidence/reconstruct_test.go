package wireevidence

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReconstructRequest_HappyPath verifies that an exemplar with mixed slot
// classes round-trips through the wire-evidence vocabulary.
func TestReconstructRequest_HappyPath(t *testing.T) {
	t.Parallel()

	exemplar := Exemplar{
		URL: "https://api.example.com/v1/items?limit=20&token=xoxc-secret",
		Headers: map[string]string{
			"Accept":        "application/json",
			"Authorization": "Bearer eyJabc.def.ghi",
			"X-B3-TraceId":  "00f067aa0ba902b7",
		},
		BodyForm: map[string]string{
			"locale": "en-US",
			"token":  "xoxc-secret",
		},
	}
	req := RequestEvidence{
		Method:         "POST",
		BaseURL:        "https://api.example.com",
		NormalizedPath: "/v1/items",
		Exemplars:      []Exemplar{exemplar},
		Slots:          BuildSlots([]Exemplar{exemplar}),
	}

	authValues := map[string]string{
		"Authorization": "Bearer eyJabc.def.ghi",
		"token":         "xoxc-secret",
	}

	require.NoError(t, CompareRequestAgainstExemplar(req, exemplar, authValues),
		"reconstruction with original auth values must match the exemplar")
}

// TestReconstructRequest_VolatileDropped pins that x-b3-traceid is excluded
// from the reconstructed headers regardless of whether the env supplies a
// value, so replaying a captured request never leaks a stale trace id onto
// the wire of a new request.
func TestReconstructRequest_VolatileDropped(t *testing.T) {
	t.Parallel()

	exemplar := Exemplar{
		URL: "https://api.example.com/v1/items",
		Headers: map[string]string{
			"X-B3-TraceId": "00f067aa0ba902b7",
			"Accept":       "application/json",
		},
	}
	req := RequestEvidence{
		Method:    "GET",
		Exemplars: []Exemplar{exemplar},
		Slots:     BuildSlots([]Exemplar{exemplar}),
	}
	got, err := ReconstructRequest(req, exemplar, nil)
	require.NoError(t, err)
	_, present := got.Headers["X-B3-TraceId"]
	assert.False(t, present, "volatile-drop slot must be excluded from the reconstructed headers")
	assert.Equal(t, "application/json", got.Headers["Accept"], "non-volatile headers pass through")
}

// TestReconstructRequest_AuthSecretMissingEnvLeavesPlaceholder ensures the
// caller sees an explicit ${ENV} marker when the auth-secret env wasn't
// resolved, so the validation gate's failure message is actionable.
func TestReconstructRequest_AuthSecretMissingEnvLeavesPlaceholder(t *testing.T) {
	t.Parallel()

	exemplar := Exemplar{
		URL: "https://api.example.com/v1/items",
		Headers: map[string]string{
			"Authorization": "Bearer eyJabc.def.ghi",
		},
	}
	req := RequestEvidence{
		Method:    "GET",
		Exemplars: []Exemplar{exemplar},
		Slots:     BuildSlots([]Exemplar{exemplar}),
	}
	got, err := ReconstructRequest(req, exemplar, nil)
	require.NoError(t, err)
	assert.Equal(t, "${AUTHORIZATION}", got.Headers["Authorization"])
}

// TestCompareRequestAgainstExemplar_DetectsAuthSecretDrift catches a real
// regression shape: two exemplars carry distinct auth-secret values for the
// same slot (e.g. session rotated between captures). The harvester locks in
// the first one; the comparison against the second exemplar fires.
func TestCompareRequestAgainstExemplar_DetectsAuthSecretDrift(t *testing.T) {
	t.Parallel()

	exemplar1 := Exemplar{
		URL:     "https://api.example.com/v1/items",
		Headers: map[string]string{"Authorization": "Bearer eyJfirst.payload.sig"},
	}
	exemplar2 := Exemplar{
		URL:     "https://api.example.com/v1/items",
		Headers: map[string]string{"Authorization": "Bearer eyJsecond.payload.sig"},
	}
	req := RequestEvidence{
		Method:    "GET",
		Exemplars: []Exemplar{exemplar1, exemplar2},
		Slots:     BuildSlots([]Exemplar{exemplar1, exemplar2}),
	}
	authValues := map[string]string{"Authorization": exemplar1.Headers["Authorization"]}
	require.NoError(t, CompareRequestAgainstExemplar(req, exemplar1, authValues))
	err := CompareRequestAgainstExemplar(req, exemplar2, authValues)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Authorization")
}

// TestCompareRequestAgainstExemplar_DetectsMisclassifiedVolatile catches the
// inverse regression: the slot vocabulary mislabels a non-volatile header
// as volatile-drop. The reconstruction strips it; the expected map also
// strips it via the same logic — so both omit, both equal, gate passes.
// This documents the gate's known blind spot: classification swaps that
// produce internally-consistent reconstructions are invisible here, and
// have to be caught by name-pattern unit tests in classifier_test.go
// instead.
func TestCompareRequestAgainstExemplar_BlindSpotMisclassifiedVolatile(t *testing.T) {
	t.Parallel()

	exemplar := Exemplar{
		URL:     "https://api.example.com/v1/items",
		Headers: map[string]string{"X-App-Locale": "en-US"},
	}
	req := RequestEvidence{
		Method:    "GET",
		Exemplars: []Exemplar{exemplar},
		Slots: []Slot{
			{Location: LocationHeader, Name: "X-App-Locale", Classification: ClassVolatileDrop, Constant: true},
		},
	}
	// Misclassification is symmetric; gate cannot catch this from the
	// evidence alone. Keep this test pinned so a future agent can't
	// claim the gate covers what it doesn't.
	assert.NoError(t, CompareRequestAgainstExemplar(req, exemplar, nil))
}

// TestURLsEquivalent_OrderIndependent verifies that query parameter order
// does not influence the comparison — captured URLs frequently have
// non-deterministic query order across browser sessions.
func TestURLsEquivalent_OrderIndependent(t *testing.T) {
	t.Parallel()
	assert.NoError(t, urlsEquivalent(
		"https://x/path?a=1&b=2",
		"https://x/path?b=2&a=1",
	))
	assert.Error(t, urlsEquivalent(
		"https://x/path?a=1",
		"https://x/path?a=2",
	))
}
