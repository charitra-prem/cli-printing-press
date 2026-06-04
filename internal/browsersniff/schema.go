package browsersniff

import (
	"encoding/json"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
)

const maxSchemaDepth = 3

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

type inferredField struct {
	count  int
	param  spec.Param
	nested map[string]*inferredField
}

func InferResponseSchema(bodies []string) []spec.Param {
	parsedSamples := make([]map[string]any, 0, len(bodies))
	for _, body := range bodies {
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}

		var value any
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			continue
		}

		root := topLevelObject(value)
		if root == nil {
			continue
		}

		parsedSamples = append(parsedSamples, root)
	}

	if len(parsedSamples) == 0 {
		return nil
	}

	fields := make(map[string]*inferredField)
	for _, sample := range parsedSamples {
		mergeObject(fields, sample, 1)
	}

	return buildParams(fields, len(parsedSamples))
}

func InferRequestSchema(body string, contentType string) []spec.Param {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}

	// Keep the original-case contentType for downstream parsers that read
	// case-sensitive parameters (notably the multipart boundary). Switch on a
	// lowercase copy.
	lowerCT := strings.ToLower(contentType)
	switch {
	case strings.Contains(lowerCT, "json"):
		var value any
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			return nil
		}

		root := topLevelObject(value)
		if root == nil {
			return nil
		}

		fields := make(map[string]*inferredField)
		mergeObject(fields, root, 1)
		return buildParams(fields, 1)
	case strings.Contains(lowerCT, "form-urlencoded"):
		values := ParseFormBody(body)
		if len(values) == 0 {
			return nil
		}

		params := make([]spec.Param, 0, len(values))
		for key, value := range values {
			params = append(params, bodyFieldParam(key, value, spec.ParamLocationBodyForm))
		}

		sort.Slice(params, func(i, j int) bool {
			return params[i].Name < params[j].Name
		})
		return params
	case strings.Contains(lowerCT, "multipart/form-data"):
		values := ParseMultipartBody(body, contentType)
		if len(values) == 0 {
			return nil
		}
		params := make([]spec.Param, 0, len(values))
		for key, value := range values {
			params = append(params, bodyFieldParam(key, value, spec.ParamLocationBodyMultipart))
		}
		sort.Slice(params, func(i, j int) bool {
			return params[i].Name < params[j].Name
		})
		return params
	default:
		return nil
	}
}

// ParseMultipartBody decodes a multipart/form-data request body into a
// field→value map keyed on the part's form-data name. The boundary is read
// from the Content-Type header (mime.ParseMediaType). File parts are skipped:
// the press surfaces multipart structure for downstream codegen, not file
// payloads. Returns an empty map on any parse failure so callers degrade to
// "no extracted fields" rather than erroring the whole sniff.
func ParseMultipartBody(body string, contentType string) map[string]string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return map[string]string{}
	}
	boundary := params["boundary"]
	if boundary == "" {
		return map[string]string{}
	}
	reader := multipart.NewReader(strings.NewReader(body), boundary)
	out := map[string]string{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		name := part.FormName()
		if name == "" {
			_ = part.Close()
			continue
		}
		// Skip file parts — only scalar form fields become wire-shape params.
		if part.FileName() != "" {
			_ = part.Close()
			continue
		}
		value, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			continue
		}
		out[name] = string(value)
	}
	return out
}

// bodyFieldParam wraps a single form/multipart body field as a spec.Param,
// stamping its ContentLocation so downstream codegen routes it to the right
// body encoder and applying the PR 3 classifier rule for token-shaped values
// (xox*-prefixed Slack tokens and eyJ-prefixed JWTs) so secrets become
// env-var-backed instead of leaking into shell history as a --flag value.
//
// Body-field-name normalization decision (open question 2 in the
// request-evidence plan): the public CLI flag name is derived by the
// generator's existing FlagName helper (kebab-case), so hyphenated and
// snake-case wire names both round-trip to the same CLI surface. The wire
// Name is preserved verbatim here; only the public surface gets normalized.
func bodyFieldParam(name string, value string, location string) spec.Param {
	p := spec.Param{
		Name:            name,
		Type:            inferScalarStringType(value),
		Required:        true,
		Description:     "",
		ContentLocation: location,
	}
	if isAuthSecretValue(value) {
		p.Classification = spec.ParamClassAuthSecret
	}
	return p
}

var (
	// slackTokenPattern matches xoxa/xoxb/xoxc/xoxd/xoxp/xoxr workspace tokens.
	slackTokenPattern = regexp.MustCompile(`^xox[abcdpr]-`)
	// jwtPattern matches the standard JWT header prefix (`eyJ` is the base64
	// of `{"`). Used as a cheap shape check; full JWT validation is overkill
	// for classifier purposes.
	jwtPattern = regexp.MustCompile(`^eyJ`)
)

func isAuthSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	return slackTokenPattern.MatchString(trimmed) || jwtPattern.MatchString(trimmed)
}

func ParseFormBody(body string) map[string]string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return map[string]string{}
	}

	parsed := make(map[string]string, len(values))
	for key, vals := range values {
		if len(vals) == 0 {
			parsed[key] = ""
			continue
		}
		parsed[key] = vals[0]
	}

	return parsed
}

func topLevelObject(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case []any:
		if len(typed) == 0 {
			return nil
		}

		object, ok := typed[0].(map[string]any)
		if !ok {
			return nil
		}
		return object
	default:
		return nil
	}
}

func mergeObject(fields map[string]*inferredField, object map[string]any, depth int) {
	for name, value := range object {
		if value == nil {
			continue
		}

		field, ok := fields[name]
		if !ok {
			field = &inferredField{}
			fields[name] = field
		}

		field.count++
		field.param = inferParam(name, value, depth)

		if (field.param.Type == "object" || field.param.Type == "array") && len(field.param.Fields) > 0 {
			if field.nested == nil {
				field.nested = make(map[string]*inferredField)
			}

			if child, ok := nestedObjectSample(value); ok {
				mergeObject(field.nested, child, depth+1)
			}
		}
	}
}

func nestedObjectSample(value any) (map[string]any, bool) {
	if child, ok := value.(map[string]any); ok {
		return child, true
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return nil, false
	}
	child, ok := items[0].(map[string]any)
	return child, ok
}

func inferParam(name string, value any, depth int) spec.Param {
	param := spec.Param{
		Name:        name,
		Description: "",
	}

	switch typed := value.(type) {
	case float64:
		if math.Trunc(typed) == typed {
			param.Type = "integer"
		} else {
			param.Type = "number"
		}
	case string:
		param.Type = "string"
		param.Format = inferStringFormat(typed)
	case bool:
		param.Type = "boolean"
	case []any:
		param.Type = "array"
		if len(typed) > 0 {
			if firstObject, ok := typed[0].(map[string]any); ok && depth < maxSchemaDepth {
				param.Fields = inferObjectFields(firstObject, depth+1)
			}
		}
	case map[string]any:
		param.Type = "object"
		if depth < maxSchemaDepth {
			param.Fields = inferObjectFields(typed, depth+1)
		}
	default:
		param.Type = "string"
	}

	return param
}

func inferObjectFields(object map[string]any, depth int) []spec.Param {
	if depth > maxSchemaDepth {
		return nil
	}

	params := make([]spec.Param, 0, len(object))
	for name, value := range object {
		if value == nil {
			continue
		}

		child := inferParam(name, value, depth)
		child.Required = true
		params = append(params, child)
	}

	sort.Slice(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})
	return params
}

func buildParams(fields map[string]*inferredField, sampleCount int) []spec.Param {
	params := make([]spec.Param, 0, len(fields))
	for name, field := range fields {
		param := field.param
		param.Name = name
		param.Required = field.count == sampleCount
		if (field.param.Type == "object" || field.param.Type == "array") && field.nested != nil {
			param.Fields = buildParams(field.nested, field.count)
		}
		params = append(params, param)
	}

	sort.Slice(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})
	return params
}

func inferStringFormat(value string) string {
	switch {
	case isRFC3339(value):
		return "date-time"
	case uuidPattern.MatchString(value):
		return "uuid"
	case emailPattern.MatchString(value):
		return "email"
	case isURL(value):
		return "url"
	default:
		return ""
	}
}

func isRFC3339(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func isURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	return parsed.Scheme != "" && parsed.Host != ""
}

func inferScalarStringType(value string) string {
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return "integer"
	}

	if value == "true" || value == "false" {
		return "boolean"
	}

	return "string"
}
