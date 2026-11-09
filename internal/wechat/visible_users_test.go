package wechat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 与 Node 版 getAgentVisibleUsers 一致：部门/标签读取失败返回错误；无可见范围时回退根部门。
func TestGetVisibleUsersFailurePropagation(t *testing.T) {
	var agentResp map[string]any
	var listResp map[string]any
	rootFetched := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "access_token": "tok", "expires_in": 7200})
		case "/cgi-bin/agent/get":
			_ = json.NewEncoder(w).Encode(agentResp)
		case "/cgi-bin/user/simplelist":
			if r.URL.Query().Get("department_id") == "1" {
				rootFetched = true
			}
			_ = json.NewEncoder(w).Encode(listResp)
		}
	}))
	defer ts.Close()
	s := NewService(ts.URL, 2000, 1024*1024)

	agentResp = map[string]any{"errcode": 0, "allow_partys": map[string]any{"partyid": []any{2}}}
	listResp = map[string]any{"errcode": 60011, "errmsg": "no privilege"}
	res := s.GetVisibleUsers("ww", "sec", "1")
	if res.Success || res.Unavailable {
		t.Fatalf("department fetch failure must propagate as wechat error, got %+v", res)
	}

	agentResp = map[string]any{"errcode": 0}
	listResp = map[string]any{"errcode": 0, "userlist": []any{map[string]any{"userid": "u1", "name": "U1"}}}
	res = s.GetVisibleUsers("ww", "sec", "1")
	if !res.Success || !rootFetched || len(res.Users) != 1 {
		t.Fatalf("no scope must fall back to root department, got %+v root=%v", res, rootFetched)
	}

	bad := NewService("http://127.0.0.1:1", 500, 1024)
	if r := bad.GetVisibleUsers("ww", "sec", "1"); r.Success || !r.Unavailable {
		t.Fatalf("network failure must be Unavailable, got %+v", r)
	}
}
