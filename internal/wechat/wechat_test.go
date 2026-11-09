package wechat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestWeChatServiceTokenRetryAndSend(t *testing.T) {
	var tokenCalls int32
	var sendCalls int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			n := atomic.AddInt32(&tokenCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode":      0,
				"errmsg":       "ok",
				"access_token": "tok-" + string(rune('0'+n)),
				"expires_in":   7200,
			})
		case "/cgi-bin/message/send":
			s := atomic.AddInt32(&sendCalls, 1)
			if s == 1 {
				// Simulate expired token 40014 on first attempt
				_ = json.NewEncoder(w).Encode(map[string]any{
					"errcode": 40014,
					"errmsg":  "invalid access_token",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"msgid":   "msg-999",
			})
		case "/cgi-bin/agent/get":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"name":    "测试应用",
				"allow_userinfos": map[string]any{
					"user": []any{
						map[string]any{"userid": "u1", "name": "张三"},
					},
				},
			})
		}
	}))
	defer ts.Close()

	svc := NewService(ts.URL, 5000, 1024*1024)
	res, err := svc.SendTextMessage("ww1", "sec1", "1000002", "hello", "u1")
	if err != nil {
		t.Fatalf("SendTextMessage failed: %v", err)
	}
	if !res.Success || res.MsgID != "msg-999" {
		t.Fatalf("unexpected send result: %+v", res)
	}
	if atomic.LoadInt32(&tokenCalls) != 2 || atomic.LoadInt32(&sendCalls) != 2 {
		t.Fatalf("expected 2 token calls and 2 send calls for 40014 retry, got token=%d send=%d", tokenCalls, sendCalls)
	}

	val := svc.ValidateCredentials("ww1", "sec1", "1000002")
	if !val.Valid || val.AgentName != "测试应用" {
		t.Fatalf("unexpected ValidateCredentials: %+v", val)
	}

	vis := svc.GetVisibleUsers("ww1", "sec1", "1000002")
	if !vis.Success || len(vis.Users) != 1 || vis.Users[0].UserID != "u1" {
		t.Fatalf("unexpected GetVisibleUsers: %+v", vis)
	}
}
