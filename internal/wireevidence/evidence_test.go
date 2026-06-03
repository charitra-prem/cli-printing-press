package wireevidence

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifySlot_FiveClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		location  string
		slotName  string
		values    []string
		wantClass string
		constant  bool
	}{
		{
			name:      "protocol-constant: accept header same across exemplars",
			location:  LocationHeader,
			slotName:  "Accept",
			values:    []string{"application/json", "application/json"},
			wantClass: ClassProtocolConstant,
			constant:  true,
		},
		{
			name:      "protocol-constant: content-type still classified by name when only one exemplar",
			location:  LocationHeader,
			slotName:  "Content-Type",
			values:    []string{"application/json"},
			wantClass: ClassProtocolConstant,
			constant:  true,
		},
		{
			name:      "semantic-default: app field identical across exemplars",
			location:  LocationQuery,
			slotName:  "locale",
			values:    []string{"en-US", "en-US"},
			wantClass: ClassSemanticDefault,
			constant:  true,
		},
		{
			name:      "auth-secret: xoxc slack token in body field",
			location:  LocationBodyMulti,
			slotName:  "token",
			values:    []string{"xoxc-1234-abcd"},
			wantClass: ClassAuthSecret,
			constant:  true,
		},
		{
			name:      "auth-secret: JWT bearer in header wins over protocol-constant name match",
			location:  LocationHeader,
			slotName:  "Authorization",
			values:    []string{"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"},
			wantClass: ClassAuthSecret,
			constant:  true,
		},
		{
			name:      "volatile-drop: x-b3-traceid classifies by name even when value is identical across exemplars",
			location:  LocationHeader,
			slotName:  "X-B3-TraceId",
			values:    []string{"00f067aa0ba902b7", "00f067aa0ba902b7"},
			wantClass: ClassVolatileDrop,
			constant:  true,
		},
		{
			name:      "volatile-drop: traceparent",
			location:  LocationHeader,
			slotName:  "traceparent",
			values:    []string{"00-1-2-01"},
			wantClass: ClassVolatileDrop,
			constant:  true,
		},
		{
			name:      "unknown: varying values with no name signal",
			location:  LocationQuery,
			slotName:  "page_token",
			values:    []string{"abc", "def"},
			wantClass: ClassUnknown,
			constant:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			class, constant := ClassifySlot(tt.location, tt.slotName, tt.values)
			assert.Equal(t, tt.wantClass, class)
			assert.Equal(t, tt.constant, constant)
		})
	}
}

func TestBuildSlots_ProducesDeterministicOrder(t *testing.T) {
	t.Parallel()

	exemplars := []Exemplar{
		{
			Headers: map[string]string{
				"Accept":         "application/json",
				"X-B3-TraceId":   "trace-1",
				"Authorization":  "Bearer eyJabc.def.ghi",
			},
			Query: map[string]string{
				"limit":  "20",
				"cursor": "page-a",
			},
			BodyForm: map[string]string{
				"locale": "en-US",
			},
		},
		{
			Headers: map[string]string{
				"Accept":         "application/json",
				"X-B3-TraceId":   "trace-2",
				"Authorization":  "Bearer eyJabc.def.ghi",
			},
			Query: map[string]string{
				"limit":  "20",
				"cursor": "page-b",
			},
			BodyForm: map[string]string{
				"locale": "en-US",
			},
		},
	}

	slots := BuildSlots(exemplars)
	require.NotEmpty(t, slots)

	// Header < query < body_form lexicographically: matches our deterministic order.
	prevKey := ""
	for _, s := range slots {
		key := s.Location + ":" + s.Name
		if prevKey != "" {
			assert.True(t, key > prevKey, "slots must be sorted: %s should come after %s", key, prevKey)
		}
		prevKey = key
	}

	// Spot-check classifications.
	byKey := map[string]Slot{}
	for _, s := range slots {
		byKey[s.Location+":"+s.Name] = s
	}

	accept := byKey[LocationHeader+":Accept"]
	assert.Equal(t, ClassProtocolConstant, accept.Classification)
	assert.True(t, accept.Constant)
	assert.Equal(t, "application/json", accept.Value)

	trace := byKey[LocationHeader+":X-B3-TraceId"]
	assert.Equal(t, ClassVolatileDrop, trace.Classification, "tracing IDs must be volatile-drop even when identical across exemplars")
	assert.Empty(t, trace.Value, "volatile-drop slots must not record a value")

	auth := byKey[LocationHeader+":Authorization"]
	assert.Equal(t, ClassAuthSecret, auth.Classification)
	assert.Empty(t, auth.Value, "auth-secret slots must not record a value")

	cursor := byKey[LocationQuery+":cursor"]
	assert.Equal(t, ClassUnknown, cursor.Classification)
	assert.False(t, cursor.Constant)

	limit := byKey[LocationQuery+":limit"]
	assert.Equal(t, ClassSemanticDefault, limit.Classification)
	assert.Equal(t, "20", limit.Value)

	locale := byKey[LocationBodyForm+":locale"]
	assert.Equal(t, ClassSemanticDefault, locale.Classification)
	assert.Equal(t, "en-US", locale.Value)
}

func TestIsAuthSecretValue(t *testing.T) {
	t.Parallel()
	assert.True(t, IsAuthSecretValue("xoxc-1-2-3"))
	assert.True(t, IsAuthSecretValue("xoxb-A-B"))
	assert.True(t, IsAuthSecretValue("eyJhbGciOiJIUzI1NiJ9.payload.sig"))
	assert.False(t, IsAuthSecretValue("hello"))
	assert.False(t, IsAuthSecretValue(""))
}

func TestIsVolatileHeaderName(t *testing.T) {
	t.Parallel()
	assert.True(t, IsVolatileHeaderName("X-B3-TraceId"))
	assert.True(t, IsVolatileHeaderName("x-b3-spanid"))
	assert.True(t, IsVolatileHeaderName("traceparent"))
	assert.True(t, IsVolatileHeaderName("X-Datadog-Trace-Id"))
	assert.False(t, IsVolatileHeaderName("Accept"))
	assert.False(t, IsVolatileHeaderName(""))
}
