package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/crypto"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/wechat"
)

func TestNotifierLifecycleSwitchesAndBugFixes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode":      0,
				"errmsg":       "ok",
				"access_token": "tok-test",
				"expires_in":   7200,
			})
		case "/cgi-bin/agent/get":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"name":    "测试告警应用",
			})
		case "/cgi-bin/message/send":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"msgid":   "msg-001",
			})
		}
	}))
	defer ts.Close()

	cfg := config.FromEnv()
	cfg.WechatAPIBase = ts.URL

	db := database.New(filepath.Join(t.TempDir(), "notifier.db"))
	cryptoSvc, err := crypto.NewService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("crypto.NewService failed: %v", err)
	}
	wxSvc := wechat.NewService(ts.URL, 5000, 1024*1024)
	n := NewNotifier(cfg, db, cryptoSvc, wxSvc)
	if err := n.Init(); err != nil {
		t.Fatalf("n.Init failed: %v", err)
	}
	defer db.Close()

	// 1. Create configuration & verify BUG-07 canonical code return on mixed-case queries
	created, err := n.CreateConfiguration(map[string]any{
		"corpId":     "ww12345678",
		"corpSecret": "secret123456",
		"agentId":    "1000002",
		"name":       "核心告警",
	})
	if err != nil {
		t.Fatalf("CreateConfiguration failed: %v", err)
	}
	canonicalCode := created["code"].(string)
	upperCode := strings.ToUpper(canonicalCode)

	ver := 1
	toggled, err := n.SetCodeSendEnabled(upperCode, false, &ver)
	if err != nil {
		t.Fatalf("SetCodeSendEnabled failed: %v", err)
	}
	if toggled["code"].(string) != canonicalCode {
		t.Fatalf("BUG-07 regression: expected canonical lower-case code %q, got %q", canonicalCode, toggled["code"])
	}

	// 2. Verify 3-layer switch: DIRECT_SEND_DISABLED blocks direct app code send, but allows rule send
	_, sendErr := n.SendNotification(canonicalCode, "direct msg", "", "text", nil)
	var appErr *AppError
	if !errors.As(sendErr, &appErr) || appErr.Code != "DIRECT_SEND_DISABLED" || appErr.StatusCode != 403 {
		t.Fatalf("expected 403 DIRECT_SEND_DISABLED, got %v", sendErr)
	}

	ver = 2
	ruleRes, err := n.CreateNotificationRule(canonicalCode, "运维组规则", "ops1|ops2", &ver, "ops-rule-01", nil)
	if err != nil {
		t.Fatalf("CreateNotificationRule failed: %v", err)
	}
	ruleMap := ruleRes["rule"].(map[string]any)
	ruleID := ruleMap["id"].(int)

	// Rule send should succeed even when code_send_enabled=false
	sent, err := n.SendNotification("OPS-RULE-01", "rule msg", "", "text", nil)
	if err != nil || sent["targetType"] != "rule" {
		t.Fatalf("expected rule send to succeed, got %v %v", sent, err)
	}

	// Disable rule -> 403 RULE_DISABLED
	ver = 3
	_, err = n.SetNotificationRuleEnabled(ruleID, false, &ver)
	if err != nil {
		t.Fatalf("SetNotificationRuleEnabled failed: %v", err)
	}
	_, sendErr = n.SendNotification("ops-rule-01", "rule msg 2", "", "text", nil)
	if !errors.As(sendErr, &appErr) || appErr.Code != "RULE_DISABLED" {
		t.Fatalf("expected 403 RULE_DISABLED, got %v", sendErr)
	}

	// Disable app -> 403 APP_DISABLED takes precedence over RULE_DISABLED
	ver = 4
	_, err = n.SetAppEnabled(canonicalCode, false, &ver)
	if err != nil {
		t.Fatalf("SetAppEnabled failed: %v", err)
	}
	_, sendErr = n.SendNotification("ops-rule-01", "rule msg 3", "", "text", nil)
	if !errors.As(sendErr, &appErr) || appErr.Code != "APP_DISABLED" {
		t.Fatalf("expected 403 APP_DISABLED priority over RULE_DISABLED, got %v", sendErr)
	}
}
