package wechat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxRequestBytesAndValidateUnavailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"access_token":"tok","expires_in":7200}`))
	}))
	defer ts.Close()

	s := NewService(ts.URL, 2000, 1024*1024)
	s.SetMaxRequestBytes(50)
	if _, err := s.doJSONRequest(http.MethodPost, ts.URL+"/x", map[string]any{"content": strings.Repeat("a", 100)}); err == nil ||
		!strings.Contains(err.Error(), "WECHAT_MAX_REQUEST_BYTES") {
		t.Fatalf("expected request size limit error, got %v", err)
	}

	// 网络不可达：Unavailable=true（对应 502 WECHAT_UNAVAILABLE）
	bad := NewService("http://127.0.0.1:1", 500, 1024)
	if res := bad.ValidateCredentials("ww", "sec", "1"); res.Valid || !res.Unavailable {
		t.Fatalf("expected unavailable, got %+v", res)
	}
}
