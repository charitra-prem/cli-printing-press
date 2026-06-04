package browsersniff

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mvanhorn/cli-printing-press/v4/internal/wireevidence"
)

// BuildRequestEvidenceFromCapture runs the same dedup/classification pass
// the spec generator uses, then produces the wireevidence model. Returns
// nil when the capture has no API entries. Mirrors the AnalyzeOptions /
// PreserveHosts behavior so the evidence matches the spec's host split.
func BuildRequestEvidenceFromCapture(capture *EnrichedCapture, options AnalyzeOptions) []wireevidence.RequestEvidence {
	if capture == nil {
		return nil
	}
	apiEntries, _ := specVisibleEntries(capture, options)
	groups := deduplicateSpecEndpoints(apiEntries, options)
	return BuildRequestEvidence(groups)
}

// BuildRequestEvidence converts the analyzer's EndpointGroup slice into the
// capture-agnostic wireevidence model. Each group becomes one
// RequestEvidence entry; every entry in the group becomes one Exemplar.
//
// The conversion is verbatim — header / query / body-form / body-multipart
// values land in the Exemplar unmodified. The classifier in
// internal/wireevidence is the single source of truth for which slots get
// dropped / redacted / replayed, so this adapter stays mechanical.
func BuildRequestEvidence(groups []EndpointGroup) []wireevidence.RequestEvidence {
	out := make([]wireevidence.RequestEvidence, 0, len(groups))
	for _, group := range groups {
		baseURL := mostCommonBaseURL(group.Entries)
		exemplars := make([]wireevidence.Exemplar, 0, len(group.Entries))
		for _, entry := range group.Entries {
			exemplars = append(exemplars, exemplarFromEntry(entry))
		}
		evidence := wireevidence.RequestEvidence{
			Method:         strings.ToUpper(strings.TrimSpace(group.Method)),
			BaseURL:        baseURL,
			NormalizedPath: group.NormalizedPath,
			Exemplars:      exemplars,
		}
		evidence.Slots = wireevidence.BuildSlots(exemplars)
		out = append(out, evidence)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].BaseURL != out[j].BaseURL {
			return out[i].BaseURL < out[j].BaseURL
		}
		return out[i].NormalizedPath < out[j].NormalizedPath
	})
	return out
}

func exemplarFromEntry(entry EnrichedEntry) wireevidence.Exemplar {
	ex := wireevidence.Exemplar{URL: entry.URL}

	if len(entry.RequestHeaders) > 0 {
		ex.Headers = make(map[string]string, len(entry.RequestHeaders))
		for k, v := range entry.RequestHeaders {
			ex.Headers[k] = v
		}
	}

	if parsed, err := url.Parse(entry.URL); err == nil {
		q := parsed.Query()
		if len(q) > 0 {
			ex.Query = make(map[string]string, len(q))
			for k, vs := range q {
				if len(vs) == 0 {
					ex.Query[k] = ""
					continue
				}
				ex.Query[k] = vs[0]
			}
		}
		// DSN-style URLs (Sentry et al.) embed a credential in the
		// userinfo segment. Surface it as its own slot so classifier
		// rules can target the location specifically without risking
		// false positives on generic 32-hex query params.
		if parsed.User != nil {
			if userinfo := parsed.User.String(); userinfo != "" {
				ex.URLUserinfo = userinfo
			}
		}
	}

	body := strings.TrimSpace(entry.RequestBody)
	if body == "" {
		return ex
	}
	contentType := getHeaderValue(entry.RequestHeaders, "Content-Type")
	switch {
	case strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded"):
		fields := ParseFormBody(entry.RequestBody)
		if len(fields) > 0 {
			ex.BodyForm = fields
		}
	case strings.Contains(strings.ToLower(contentType), "multipart/form-data"):
		fields := ParseMultipartBody(entry.RequestBody, contentType)
		if len(fields) > 0 {
			ex.BodyMulti = fields
		}
	}
	return ex
}

// WriteRequestEvidence serializes the evidence document to the given output
// path. Mirrors WriteTrafficAnalysis's mode (0o600, MkdirAll, trailing
// newline) so artifacts cluster identically on disk.
func WriteRequestEvidence(requests []wireevidence.RequestEvidence, outputPath string) error {
	if strings.TrimSpace(outputPath) == "" {
		return fmt.Errorf("output path is required")
	}
	doc := wireevidence.Document{Version: wireevidence.FormatVersion, Requests: requests}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling request evidence: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening request evidence json: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("writing request evidence json: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing request evidence json: %w", err)
	}
	return nil
}

// DefaultRequestEvidencePath returns the canonical sidecar location for an
// evidence file emitted alongside the given spec. Mirrors
// DefaultTrafficAnalysisPath's naming so all sniff artifacts cluster
// (`<stem>-spec.yaml`, `<stem>-traffic-analysis.json`,
// `<stem>-request-evidence.json`).
func DefaultRequestEvidencePath(specPath string) string {
	dir := filepath.Dir(specPath)
	base := filepath.Base(specPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" || stem == "." {
		stem = "request"
	}
	return filepath.Join(dir, stem+"-request-evidence.json")
}
