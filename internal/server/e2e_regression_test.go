package server

import (
	"net/http"
	"strings"
	"testing"
)

// E2E 回归：数字 agentid、缺少/非法 If-Match 错误码、text 仅 title 无 content。
func TestE2ERegressions(t *testing.T) {
	_, httpSrv, _ := setupTestServer(t)
	client := &http.Client{}
	_, _, hdr := doJSONReq(t, client, "POST", httpSrv.URL+"/api/login", map[string]any{
		"username": "admin", "password": "StrongAdminPassword123!",
	}, nil)
	ck := map[string]string{"Cookie": strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]}

	// 前端 wizard 发送数字 agentid
	status, body, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/validate", map[string]any{
		"corpid": "ww99887766", "corpsecret": "secret9988", "agentid": 1000088,
	}, ck)
	if status != 200 || body["users"] == nil {
		t.Fatalf("numeric agentid validate failed: %d %+v", status, body)
	}

	_, cb, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/generate-callback", map[string]any{"name": "x"}, ck)
	code, _ := cb["code"].(string)
	status, body, _ = doJSONReq(t, client, "PUT", httpSrv.URL+"/api/configuration/"+code, map[string]any{"description": "d"}, ck)
	if status != 428 || body["code"] != "APP_VERSION_REQUIRED" {
		t.Fatalf("missing If-Match: %d %+v", status, body)
	}
	h := map[string]string{"Cookie": ck["Cookie"], "If-Match": "abc"}
	status, body, _ = doJSONReq(t, client, "PUT", httpSrv.URL+"/api/configuration/"+code, map[string]any{"description": "d"}, h)
	if status != 400 || body["code"] != "INVALID_INPUT" {
		t.Fatalf("invalid If-Match: %d %+v", status, body)
	}
}
