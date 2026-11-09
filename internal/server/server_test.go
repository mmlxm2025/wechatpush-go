package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"

	"qywx-notifier-plus/internal/auth"
	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/crypto"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/notifyauth"
	"qywx-notifier-plus/internal/service"
	"qywx-notifier-plus/internal/wechat"
	"qywx-notifier-plus/internal/wxcrypt"
)

func setupTestServer(t *testing.T) (*Server, *httptest.Server, *httptest.Server) {
	t.Helper()

	mockWeChat := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode":      0,
				"errmsg":       "ok",
				"access_token": "mock-token-123",
				"expires_in":   7200,
			})
		case "/cgi-bin/agent/get":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"name":    "集成测试应用",
				"allow_userinfos": map[string]any{
					"user": []any{
						map[string]any{"userid": "zhangsan", "name": "张三"},
					},
				},
			})
		case "/cgi-bin/message/send":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errcode": 0,
				"errmsg":  "ok",
				"msgid":   "msgid-integration-001",
			})
		}
	}))

	cfg := config.FromEnv()
	cfg.EncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.AdminUsername = "admin"
	cfg.AdminPassword = "StrongAdminPassword123!"
	cfg.WechatAPIBase = mockWeChat.URL
	cfg.AllowCustomWechatAPIBase = true
	cfg.TestInstanceID = "integration-test-instance-id-2026"
	cfg.DBPath = filepath.Join(t.TempDir(), "integration.db")

	db := database.New(cfg.DBPath)
	cryptoSvc, err := crypto.NewService(cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("crypto.NewService failed: %v", err)
	}
	wxSvc := wechat.NewService(cfg.WechatAPIBase, 5000, 1024*1024)
	notifier := service.NewNotifier(cfg, db, cryptoSvc, wxSvc)
	if err := notifier.Init(); err != nil {
		t.Fatalf("notifier.Init failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		mockWeChat.Close()
	})

	authSvc := auth.NewService(cfg.AdminUsername, cfg.AdminPassword)
	srv := NewServer(cfg, notifier, authSvc)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		httpSrv.Close()
	})

	return srv, httpSrv, mockWeChat
}

func doJSONReq(t *testing.T, client *http.Client, method, reqURL string, body any, headers map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body failed: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, reqURL, reader)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var data map[string]any
	_ = json.Unmarshal(raw, &data)
	return resp.StatusCode, data, resp.Header
}

func TestServerFullMatrixAndBugFixes(t *testing.T) {
	srv, httpSrv, _ := setupTestServer(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Unauthenticated GET / redirects to /login with security headers
	resp, err := client.Get(httpSrv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("expected 302 to /login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %+v", resp.Header)
	}

	// 2. Embedded static asset GET /public/edit.js works and contains BUG-09 fix
	respStatic, err := client.Get(httpSrv.URL + "/public/edit.js")
	if err != nil {
		t.Fatalf("GET /public/edit.js failed: %v", err)
	}
	staticBytes, _ := io.ReadAll(respStatic.Body)
	respStatic.Body.Close()
	if respStatic.StatusCode != 200 || !strings.Contains(string(staticBytes), "original.notify_key_enabled = (action !== 'revoke')") {
		t.Fatalf("BUG-09 fix not found in served /public/edit.js, status=%d", respStatic.StatusCode)
	}

	// 3. Health endpoints
	status, readyBody, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/health/ready", nil, nil)
	if status != 200 || readyBody["status"] != "ok" {
		t.Fatalf("expected /health/ready 200, got %d %+v", status, readyBody)
	}
	srv.SetShuttingDown(true)
	status, readyBody, _ = doJSONReq(t, client, "GET", httpSrv.URL+"/health/ready", nil, nil)
	if status != 503 || readyBody["status"] != "shutting_down" {
		t.Fatalf("expected /health/ready 503 shutting_down, got %d %+v", status, readyBody)
	}
	srv.SetShuttingDown(false)

	// 4. Login & Session
	status, loginData, loginHdr := doJSONReq(t, client, "POST", httpSrv.URL+"/api/login", map[string]any{
		"username": "admin",
		"password": "StrongAdminPassword123!",
	}, nil)
	if status != 200 || loginData["success"] != true {
		t.Fatalf("login failed: %d %+v", status, loginData)
	}
	authHeaders := map[string]string{"Cookie": strings.SplitN(loginHdr.Get("Set-Cookie"), ";", 2)[0]}
	if !strings.Contains(loginHdr.Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("expected HttpOnly Set-Cookie on login, got %q", loginHdr.Get("Set-Cookie"))
	}

	// 5. Create draft callback & verify URL via GET /api/callback/:code
	status, cbData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/generate-callback", map[string]any{
		"name": "向导草稿应用",
	}, authHeaders)
	if status != 200 {
		t.Fatalf("generate-callback failed: %d %+v", status, cbData)
	}
	draftCode := cbData["code"].(string)
	cbToken := cbData["token"].(string)
	cbAESKey := cbData["encodingAESKey"].(string)

	crypt, err := wxcrypt.NewWXBizMsgCrypt(cbToken, cbAESKey, "ww12345678")
	if err != nil {
		t.Fatalf("NewWXBizMsgCrypt failed: %v", err)
	}
	echoCipher, _ := crypt.Encrypt("echo-verified-ok")
	tsNow := strconv.FormatInt(time.Now().Unix(), 10)
	sig := wxcrypt.Sign(cbToken, tsNow, "nonce123", echoCipher)

	cbVerifyURL := fmt.Sprintf("%s/api/callback/%s?msg_signature=%s&timestamp=%s&nonce=nonce123&echostr=%s",
		httpSrv.URL, draftCode, url.QueryEscape(sig), url.QueryEscape(tsNow), url.QueryEscape(echoCipher))
	cbResp, err := client.Get(cbVerifyURL)
	if err != nil {
		t.Fatalf("GET callback verify failed: %v", err)
	}
	cbEchoBytes, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()
	if cbResp.StatusCode != 200 || string(cbEchoBytes) != "echo-verified-ok" {
		t.Fatalf("unexpected callback verify response: %d %q", cbResp.StatusCode, string(cbEchoBytes))
	}

	// 6. Complete draft configuration
	status, compData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/complete-config", map[string]any{
		"code":       draftCode,
		"corpId":     "ww12345678",
		"corpSecret": "secret123456",
		"agentId":    "1000002",
		"name":       "正式应用A",
	}, authHeaders)
	if status != 200 || compData["success"] != true {
		t.Fatalf("complete-config failed: %d %+v", status, compData)
	}

	// 7. Optimistic lock checks on PUT /api/configuration/:code (428 missing, 400 invalid, 409 conflict, 200 ok)
	status, errBody, _ := doJSONReq(t, client, "PUT", httpSrv.URL+"/api/configuration/"+draftCode, map[string]any{
		"name": "新名称",
	}, authHeaders)
	if status != 428 || errBody["code"] != "APP_VERSION_REQUIRED" {
		t.Fatalf("expected 428 APP_VERSION_REQUIRED, got %d %+v", status, errBody)
	}

	status, errBody, _ = doJSONReq(t, client, "PUT", httpSrv.URL+"/api/configuration/"+draftCode, map[string]any{
		"name":    "新名称",
		"version": "abc",
	}, authHeaders)
	if status != 400 || errBody["code"] != "INVALID_INPUT" {
		t.Fatalf("expected 400 INVALID_INPUT, got %d %+v", status, errBody)
	}

	status, errBody, _ = doJSONReq(t, client, "PUT", httpSrv.URL+"/api/configuration/"+draftCode, map[string]any{
		"name": "新名称",
	}, map[string]string{
		"Cookie":   authHeaders["Cookie"],
		"If-Match": `"99"`,
	})
	if status != 409 || errBody["code"] != "APP_VERSION_CONFLICT" {
		t.Fatalf("expected 409 APP_VERSION_CONFLICT, got %d %+v", status, errBody)
	}

	// 8. Rotate NotifyKey & create custom rule
	status, nkData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/configuration/"+draftCode+"/notify-key", map[string]any{}, map[string]string{
		"Cookie":   authHeaders["Cookie"],
		"If-Match": `"2"`,
	})
	if status != 200 || nkData["notify_key"] == nil {
		t.Fatalf("rotate notify-key failed: %d %+v", status, nkData)
	}
	notifyKey := nkData["notify_key"].(string)

	status, ruleData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/configuration/"+draftCode+"/rules", map[string]any{
		"name":     "核心报警规则",
		"to_user":  "zhangsan",
		"api_code": "alert-ops-01",
	}, map[string]string{
		"Cookie":   authHeaders["Cookie"],
		"If-Match": `"3"`,
	})
	if status != 200 {
		t.Fatalf("create rule failed: %d %+v", status, ruleData)
	}

	// 9. BUG-04 verification: POST /api/notify/:code with text/plain returns 400 with code: "INVALID_INPUT"
	plainReq, _ := http.NewRequest("POST", httpSrv.URL+"/api/notify/alert-ops-01", strings.NewReader("hello"))
	plainReq.Header.Set("Content-Type", "text/plain")
	plainResp, err := client.Do(plainReq)
	if err != nil {
		t.Fatalf("plain notify req failed: %v", err)
	}
	var plainErrData map[string]any
	_ = json.NewDecoder(plainResp.Body).Decode(&plainErrData)
	plainResp.Body.Close()
	if plainResp.StatusCode != 400 || plainErrData["code"] != "INVALID_INPUT" {
		t.Fatalf("BUG-04 regression: expected 400 code=INVALID_INPUT, got %d %+v", plainResp.StatusCode, plainErrData)
	}

	// 10. Notify with GB18030/GBK body + HMAC signature
	gbkUTF8 := `{"message":"GBK中文告警测试","msg_type":"text"}`
	gbkBytes, _ := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(gbkUTF8))
	keyHash := notifyauth.HashNotifyKey(notifyKey)
	nonce := "nonce-gbk-12345"
	sigHMAC := notifyauth.ComputeNotifySignature(keyHash, tsNow, nonce, gbkBytes)

	gbkReq, _ := http.NewRequest("POST", httpSrv.URL+"/api/notify/alert-ops-01", bytes.NewReader(gbkBytes))
	gbkReq.Header.Set("Content-Type", "application/json")
	gbkReq.Header.Set("X-Notify-Timestamp", tsNow)
	gbkReq.Header.Set("X-Notify-Nonce", nonce)
	gbkReq.Header.Set("X-Notify-Signature", sigHMAC)
	gbkResp, err := client.Do(gbkReq)
	if err != nil {
		t.Fatalf("gbk notify req failed: %v", err)
	}
	var gbkRespData map[string]any
	_ = json.NewDecoder(gbkResp.Body).Decode(&gbkRespData)
	gbkResp.Body.Close()
	if gbkResp.StatusCode != 200 || gbkRespData["message"] != "发送成功" {
		t.Fatalf("expected GBK + HMAC notify to succeed, got %d %+v", gbkResp.StatusCode, gbkRespData)
	}

	// 11. BUG-03 verification: If a rule api_code and a configuration code collide in a legacy DB,
	// POST /api/notify/:code must return 500 NOTIFY_CODE_NAMESPACE_CORRUPTED BEFORE auth/switch checks
	_, _ = srv.notifier.DB().RawExec("DROP TRIGGER IF EXISTS trg_config_code_vs_rules_insert")
	_, _ = srv.notifier.DB().RawExec(`
		INSERT INTO configurations (code, corp_id, corp_secret, agent_id, to_user, token, aes_key, is_completed, enabled, code_send_enabled, version)
		VALUES ('ALERT-OPS-01', '', '', '1000099', '@all', 'tok', 'aes', 1, 1, 1, 1)
	`)
	srv.notifier.ClearRuntimeCaches()

	// Notice we do NOT send X-Notify-Key: before BUG-03 fix, resolveNotifyAuth would return 401 NOTIFY_UNAUTHORIZED
	// instead of detecting the namespace collision 500 NOTIFY_CODE_NAMESPACE_CORRUPTED!
	status, corruptData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/notify/alert-ops-01", map[string]any{
		"message": "should fail with 500 namespace corrupted",
	}, nil)
	if status != 500 || corruptData["code"] != "NOTIFY_CODE_NAMESPACE_CORRUPTED" {
		t.Fatalf("BUG-03 regression: expected 500 NOTIFY_CODE_NAMESPACE_CORRUPTED, got %d %+v", status, corruptData)
	}
}

func TestBrowserFrontendContract(t *testing.T) {
	_, httpSrv, _ := setupTestServer(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. Browser POST /api/login -> Set-Cookie: session=...
	status, loginData, loginHdr := doJSONReq(t, client, "POST", httpSrv.URL+"/api/login", map[string]any{
		"username": "admin",
		"password": "StrongAdminPassword123!",
	}, nil)
	if status != 200 || loginData["success"] != true {
		t.Fatalf("browser login failed: %d %+v", status, loginData)
	}
	setCookie := loginHdr.Get("Set-Cookie")
	if !strings.HasPrefix(setCookie, "session=") {
		t.Fatalf("expected Set-Cookie starting with 'session=', got %q", setCookie)
	}
	cookieHeader := strings.Split(setCookie, ";")[0]
	cookieAuth := map[string]string{"Cookie": cookieHeader}

	// 2. Browser GET /api/auth-status with session cookie MUST return loggedIn: true, configured: true
	status, authStatus, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/api/auth-status", nil, cookieAuth)
	if status != 200 || authStatus["loggedIn"] != true || authStatus["configured"] != true || authStatus["username"] != "admin" {
		t.Fatalf("unexpected /api/auth-status response: %d %+v", status, authStatus)
	}

	// 3. Browser GET / with session cookie MUST return 200 OK (not 302 redirect)
	indexReq, _ := http.NewRequest("GET", httpSrv.URL+"/", nil)
	indexReq.Header.Set("Cookie", cookieHeader)
	indexResp, err := client.Do(indexReq)
	if err != nil {
		t.Fatalf("GET / with cookie failed: %v", err)
	}
	indexResp.Body.Close()
	if indexResp.StatusCode != 200 {
		t.Fatalf("expected GET / 200 OK with session cookie, got %d", indexResp.StatusCode)
	}

	// 4. Browser Wizard Step 1: POST /api/generate-callback with corpid, callback_token, encoding_aes_key
	status, wizStep1, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/generate-callback", map[string]any{
		"corpid":           "ww99887766",
		"callback_token":   "mywizardtoken123",
		"encoding_aes_key": "0123456789abcdef0123456789abcdef0123456789a",
	}, cookieAuth)
	if status != 201 || wizStep1["code"] == nil || wizStep1["callbackUrl"] == nil {
		t.Fatalf("wizard step 1 failed: %d %+v", status, wizStep1)
	}
	wizCode := wizStep1["code"].(string)

	// 5. Browser Wizard Step 3: POST /api/validate with snake_case corpid, corpsecret, agentid
	status, valData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/validate", map[string]any{
		"corpid":     "ww99887766",
		"corpsecret": "secret9988",
		"agentid":    "1000088",
	}, cookieAuth)
	if status != 200 || valData["agentid"] != float64(1000088) || valData["users"] == nil {
		t.Fatalf("wizard step 3 validate failed: %d %+v", status, valData)
	}

	// 6. Browser Wizard Step 4: POST /api/complete-config with snake_case fields + touser array
	status, compData, _ := doJSONReq(t, client, "POST", httpSrv.URL+"/api/complete-config", map[string]any{
		"code":       wizCode,
		"corpid":     "ww99887766",
		"corpsecret": "secret9988",
		"agentid":    "1000088",
		"touser":     []string{"zhangsan"},
		"name":       "浏览器向导应用",
	}, cookieAuth)
	if status != 200 || compData["apiUrl"] == nil || compData["callbackUrl"] == nil {
		t.Fatalf("wizard step 4 complete-config failed: %d %+v", status, compData)
	}

	// 7. Browser Edit page: GET /api/configuration/:code returns top-level completed, corpid, version, touser
	status, cfgDetail, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/api/configuration/"+wizCode, nil, cookieAuth)
	if status != 200 || cfgDetail["completed"] != true || cfgDetail["corpid"] != "ww99887766" || cfgDetail["version"] == nil {
		t.Fatalf("edit page GET /api/configuration/:code failed: %d %+v", status, cfgDetail)
	}

	// 8. Browser Rules page: GET /api/configuration/:code/rules returns config and rules
	status, rulesPageData, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/api/configuration/"+wizCode+"/rules", nil, cookieAuth)
	if status != 200 || rulesPageData["config"] == nil || rulesPageData["rules"] == nil {
		t.Fatalf("rules page GET /api/configuration/:code/rules failed: %d %+v", status, rulesPageData)
	}

	// 9. Browser Rules availability precheck: invalid format -> 400 RULE_API_CODE_INVALID; valid -> 200 available: true
	status, availInvalid, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/api/rule-api-codes/availability?api_code=a!", nil, cookieAuth)
	if status != 400 || availInvalid["code"] != "RULE_API_CODE_INVALID" {
		t.Fatalf("expected 400 RULE_API_CODE_INVALID, got %d %+v", status, availInvalid)
	}
	status, availValid, _ := doJSONReq(t, client, "GET", httpSrv.URL+"/api/rule-api-codes/availability?api_code=my-custom-rule", nil, cookieAuth)
	if status != 200 || availValid["available"] != true {
		t.Fatalf("expected 200 available:true, got %d %+v", status, availValid)
	}
}
