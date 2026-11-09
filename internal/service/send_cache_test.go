package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/crypto"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/wechat"
)

// 覆盖：接收人不可被调用方覆盖、去重缓存（cached）、force 绕过、safe 透传。
func TestSendDedupForceSafeAndRecipientLock(t *testing.T) {
	var mu sync.Mutex
	sendCount := 0
	var lastPayload map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "access_token": "tok", "expires_in": 7200})
		case "/cgi-bin/agent/get":
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "name": "app"})
		case "/cgi-bin/message/send":
			var p map[string]any
			_ = json.NewDecoder(r.Body).Decode(&p)
			mu.Lock()
			sendCount++
			lastPayload = p
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "msgid": "m1"})
		}
	}))
	defer ts.Close()

	cfg := config.FromEnv()
	cfg.WechatAPIBase = ts.URL
	cfg.SendDedupTTLMs = 30000
	db := database.New(filepath.Join(t.TempDir(), "notifier.db"))
	cryptoSvc, _ := crypto.NewService("0123456789abcdef0123456789abcdef")
	n := NewNotifier(cfg, db, cryptoSvc, wechat.NewService(ts.URL, 5000, 1024*1024))
	if err := n.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer db.Close()
	created, err := n.CreateConfiguration(map[string]any{"corpId": "ww1", "corpSecret": "s", "agentId": "1000002", "name": "x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	code := created["code"].(string)

	// 1. 调用方传入的 toUser 被忽略
	res, err := n.SendNotification(code, "hello", "attacker", "text", map[string]any{})
	if err != nil {
		t.Fatalf("send1: %v", err)
	}
	if lastPayload["touser"] == "attacker" {
		t.Fatalf("caller must not override recipient, payload=%v", lastPayload)
	}
	if lastPayload["safe"] != float64(0) {
		t.Fatalf("default safe must be 0, got %v", lastPayload["safe"])
	}
	if res["response"] == nil {
		t.Fatalf("missing response")
	}

	// 2. 相同请求命中缓存，不再实际发送，response.cached=true
	res2, err := n.SendNotification(code, "hello", "", "text", map[string]any{})
	if err != nil || sendCount != 1 {
		t.Fatalf("expected cached result, count=%d err=%v", sendCount, err)
	}
	if rm, _ := res2["response"].(map[string]any); rm["cached"] != true {
		t.Fatalf("expected response.cached=true, got %v", res2["response"])
	}

	// 3. force=true 绕过缓存
	if _, err := n.SendNotification(code, "hello", "", "text", map[string]any{"force": true}); err != nil || sendCount != 2 {
		t.Fatalf("force should bypass cache, count=%d err=%v", sendCount, err)
	}

	// 4. safe=1 透传企业微信（且属于不同缓存键）
	if _, err := n.SendNotification(code, "hello", "", "text", map[string]any{"safe": float64(1)}); err != nil || sendCount != 3 {
		t.Fatalf("safe send failed, count=%d err=%v", sendCount, err)
	}
	if lastPayload["safe"] != float64(1) {
		t.Fatalf("expected safe=1 in payload, got %v", lastPayload["safe"])
	}

	// 5. 配置变更清缓存后重新发送
	n.ClearRuntimeCaches()
	if _, err := n.SendNotification(code, "hello", "", "text", map[string]any{}); err != nil || sendCount != 4 {
		t.Fatalf("expected resend after cache clear, count=%d err=%v", sendCount, err)
	}
}

func TestWrapWeChatSendErrorAndSafeParse(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{&wechat.WechatError{Message: "x", WechatErrCode: 45009}, 429, "WECHAT_BACKOFF"},
		{&wechat.WechatError{Message: "x", WechatErrCode: 40001}, 400, "WECHAT_CREDENTIAL_INVALID"},
		{errors.New("dial tcp: timeout"), 502, "WECHAT_UNAVAILABLE"},
		{NewError("biz", 403, "APP_DISABLED"), 403, "APP_DISABLED"},
	}
	for _, c := range cases {
		var ae *AppError
		if !errors.As(wrapWeChatSendError(c.err), &ae) || ae.StatusCode != c.status || ae.Code != c.code {
			t.Fatalf("wrap(%v) = %+v, want %d %s", c.err, ae, c.status, c.code)
		}
	}
	if safeFromAny(nil) != 0 || safeFromAny(float64(1)) != 1 || safeFromAny("2") != 2 || safeFromAny(json.Number("1")) != 1 || safeFromAny(true) != 1 {
		t.Fatalf("safeFromAny parse mismatch")
	}
}
