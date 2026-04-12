package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/metrics", "/metrics"},
		{"/healthz", "/healthz"},
		{"/", "other"},
		{"/admin", "other"},
		{"/some/random/path", "other"},
		{"/metrics/extra", "other"},
		{"", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizePath(tt.input))
		})
	}
}

func TestInstrumentHandler_StatusCapture(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	handler := InstrumentHandler(inner)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestInstrumentHandler_DefaultStatus(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No explicit WriteHeader — should default to 200
		_, _ = w.Write([]byte("OK"))
	})
	handler := InstrumentHandler(inner)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "OK", rr.Body.String())
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, status: http.StatusOK}

	rw.WriteHeader(http.StatusBadGateway)
	assert.Equal(t, http.StatusBadGateway, rw.status)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
}
