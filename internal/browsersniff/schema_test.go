package browsersniff

import (
	"testing"

	"github.com/mvanhorn/cli-printing-press/v4/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInferResponseSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		bodies []string
		want   []spec.Param
	}{
		{
			name:   "infers simple object fields",
			bodies: []string{`{"id":1,"name":"test","created_at":"2026-01-01T00:00:00Z"}`},
			want: []spec.Param{
				{Name: "created_at", Type: "string", Required: true, Description: "", Format: "date-time"},
				{Name: "id", Type: "integer", Required: true, Description: ""},
				{Name: "name", Type: "string", Required: true, Description: ""},
			},
		},
		{
			name:   "merges multiple samples and marks optional fields",
			bodies: []string{`{"a":1,"b":"x"}`, `{"a":2,"c":true}`},
			want: []spec.Param{
				{Name: "a", Type: "integer", Required: true, Description: ""},
				{Name: "b", Type: "string", Required: false, Description: ""},
				{Name: "c", Type: "boolean", Required: false, Description: ""},
			},
		},
		{
			name:   "infers from array response using first element",
			bodies: []string{`[{"id":1},{"id":2}]`},
			want: []spec.Param{
				{Name: "id", Type: "integer", Required: true, Description: ""},
			},
		},
		{
			name:   "returns empty for empty body",
			bodies: []string{""},
			want:   nil,
		},
		{
			name:   "returns empty for non json body",
			bodies: []string{"not json"},
			want:   nil,
		},
		{
			name:   "limits nested object recursion at depth three",
			bodies: []string{`{"outer":{"middle":{"inner":{"deep":{"value":1}}}}}`},
			want: []spec.Param{
				{
					Name:        "outer",
					Type:        "object",
					Required:    true,
					Description: "",
					Fields: []spec.Param{
						{
							Name:        "middle",
							Type:        "object",
							Required:    true,
							Description: "",
							Fields: []spec.Param{
								{
									Name:        "inner",
									Type:        "object",
									Required:    true,
									Description: "",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, InferResponseSchema(tt.bodies))
		})
	}
}

func TestInferRequestSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		contentType string
		want        []spec.Param
	}{
		{
			name:        "infers form body values",
			body:        "q=hello&page=1&limit=20",
			contentType: "application/x-www-form-urlencoded",
			want: []spec.Param{
				{Name: "limit", Type: "integer", Required: true, Description: "", ContentLocation: spec.ParamLocationBodyForm},
				{Name: "page", Type: "integer", Required: true, Description: "", ContentLocation: spec.ParamLocationBodyForm},
				{Name: "q", Type: "string", Required: true, Description: "", ContentLocation: spec.ParamLocationBodyForm},
			},
		},
		{
			name:        "infers json request body",
			body:        `{"active":true,"count":1,"name":"test"}`,
			contentType: "application/json",
			want: []spec.Param{
				{Name: "active", Type: "boolean", Required: true, Description: ""},
				{Name: "count", Type: "integer", Required: true, Description: ""},
				{Name: "name", Type: "string", Required: true, Description: ""},
			},
		},
		{
			name:        "returns empty for unsupported content type",
			body:        "a=b",
			contentType: "text/plain",
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, InferRequestSchema(tt.body, tt.contentType))
		})
	}
}

func TestParseFormBody(t *testing.T) {
	t.Parallel()

	assert.Equal(t, map[string]string{
		"page":  "1",
		"q":     "hello world",
		"token": "abc+123",
	}, ParseFormBody("q=hello+world&page=1&token=abc%2B123"))
}

func TestInferRequestSchemaTagsContentLocation(t *testing.T) {
	t.Parallel()

	t.Run("form-urlencoded fields carry body_form location", func(t *testing.T) {
		t.Parallel()
		got := InferRequestSchema("name=widget&qty=3", "application/x-www-form-urlencoded")
		require.Len(t, got, 2)
		for _, p := range got {
			assert.Equal(t, spec.ParamLocationBodyForm, p.ContentLocation, "param %s", p.Name)
			assert.Empty(t, p.Classification, "param %s should not be auth-secret", p.Name)
		}
	})

	t.Run("multipart fields carry body_multipart location and skip file parts", func(t *testing.T) {
		t.Parallel()
		boundary := "----boundary42"
		body := "--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"name\"\r\n\r\n" +
			"widget\r\n" +
			"--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\r\n" +
			"Content-Type: text/plain\r\n\r\n" +
			"file-bytes\r\n" +
			"--" + boundary + "--\r\n"
		got := InferRequestSchema(body, "multipart/form-data; boundary="+boundary)
		require.Len(t, got, 1)
		assert.Equal(t, "name", got[0].Name)
		assert.Equal(t, spec.ParamLocationBodyMultipart, got[0].ContentLocation)
	})

	t.Run("Slack xoxc token in body field is classified auth-secret", func(t *testing.T) {
		t.Parallel()
		got := InferRequestSchema("token=xoxc-1234-abcd&channel=C123", "application/x-www-form-urlencoded")
		require.Len(t, got, 2)
		var tokenParam, channelParam spec.Param
		for _, p := range got {
			switch p.Name {
			case "token":
				tokenParam = p
			case "channel":
				channelParam = p
			}
		}
		assert.Equal(t, spec.ParamClassAuthSecret, tokenParam.Classification, "xoxc-prefixed token should be auth-secret")
		assert.Equal(t, spec.ParamLocationBodyForm, tokenParam.ContentLocation)
		assert.Empty(t, channelParam.Classification, "non-token field should stay unclassified")
	})

	t.Run("JWT-shaped body field is classified auth-secret", func(t *testing.T) {
		t.Parallel()
		got := InferRequestSchema("session=eyJhbGciOiJIUzI1NiJ9.payload.sig", "application/x-www-form-urlencoded")
		require.Len(t, got, 1)
		assert.Equal(t, spec.ParamClassAuthSecret, got[0].Classification)
	})

	t.Run("JSON request bodies leave content_location empty", func(t *testing.T) {
		t.Parallel()
		got := InferRequestSchema(`{"name":"widget"}`, "application/json")
		require.Len(t, got, 1)
		assert.Empty(t, got[0].ContentLocation, "JSON params keep the legacy default")
	})
}

func TestParseMultipartBody(t *testing.T) {
	t.Parallel()

	boundary := "----b"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"a\"\r\n\r\n" +
		"alpha\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"b\"\r\n\r\n" +
		"beta\r\n" +
		"--" + boundary + "--\r\n"
	got := ParseMultipartBody(body, "multipart/form-data; boundary="+boundary)
	assert.Equal(t, map[string]string{"a": "alpha", "b": "beta"}, got)

	assert.Equal(t, map[string]string{}, ParseMultipartBody("garbage", "multipart/form-data"))
}
