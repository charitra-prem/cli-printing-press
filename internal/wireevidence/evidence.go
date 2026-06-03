// Package wireevidence captures the verbatim wire shape of one or more
// observed HTTP requests against an endpoint, separately from the inferred
// spec. The browser-sniff path emits a `*-request-evidence.json` sidecar that
// later codegen phases (PR 5+) can consume to reconstruct requests with
// byte-fidelity to the capture, rather than re-inferring from the spec.
//
// The package is intentionally capture-agnostic — it does not import
// browsersniff or any other parser — so the generator can depend on it
// without pulling in HAR types.
package wireevidence

// FormatVersion identifies the on-disk evidence schema. Bumped whenever the
// JSON shape changes in a backwards-incompatible way.
const FormatVersion = "1"

// ContentLocation values name where a slot lives in the wire request.
const (
	LocationHeader    = "header"
	LocationQuery     = "query"
	LocationBodyForm  = "body_form"
	LocationBodyMulti = "body_multipart"
)

// Classification values are the shared five-class vocabulary that maps a
// slot's observed values to a generator action. The same constants appear on
// spec.Param.Classification so the template layer can switch on them.
const (
	ClassProtocolConstant = "protocol-constant"
	ClassSemanticDefault  = "semantic-default"
	ClassAuthSecret       = "auth-secret"
	ClassVolatileDrop     = "volatile-drop"
	ClassUnknown          = "unknown"
)

// Document is the top-level sidecar payload.
type Document struct {
	Version  string             `json:"version"`
	Requests []RequestEvidence  `json:"requests"`
}

// RequestEvidence is one endpoint's observed request shape across all its
// captured exemplars.
type RequestEvidence struct {
	Method         string     `json:"method"`
	BaseURL        string     `json:"base_url"`
	NormalizedPath string     `json:"normalized_path"`
	Exemplars      []Exemplar `json:"exemplars"`
	// Slots is the per-(location,name) classification across exemplars.
	// Ordered for deterministic JSON.
	Slots []Slot `json:"slots"`
}

// Exemplar is one captured request.
type Exemplar struct {
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Query      map[string]string `json:"query,omitempty"`
	BodyForm   map[string]string `json:"body_form,omitempty"`
	BodyMulti  map[string]string `json:"body_multipart,omitempty"`
}

// Slot is the classifier's decision for one (location, name) pair.
type Slot struct {
	Location       string `json:"location"`
	Name           string `json:"name"`
	Classification string `json:"classification"`
	// Constant is true when every exemplar carried the same value for this
	// slot. The classifier consumes this signal alongside name-pattern signals
	// (so e.g. an x-b3-traceid that happens to be identical across two
	// exemplars still classifies as volatile-drop by name).
	Constant bool `json:"constant"`
	// Value is the shared value when Constant is true and the classifier is
	// confident replaying it is safe (protocol-constant, semantic-default).
	// auth-secret slots have their value redacted before sidecar emission.
	// Empty for varying or volatile-drop slots.
	Value string `json:"value,omitempty"`
}
