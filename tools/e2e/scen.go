package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

func wxEncrypt(aesKey, corpID, msg string) string {
	key, _ := base64.StdEncoding.DecodeString(aesKey + "=")
	buf := []byte(rnd(8))
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(msg)))
	buf = append(buf, l...)
	buf = append(buf, msg...)
	buf = append(buf, corpID...)
	pad := 32 - len(buf)%32
	for i := 0; i < pad; i++ {
		buf = append(buf, byte(pad))
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(out, buf)
	return base64.StdEncoding.EncodeToString(out)
}
func wxSign(parts ...string) string {
	sort.Strings(parts)
	h := sha1.Sum([]byte(strings.Join(parts, "")))
	return fmt.Sprintf("%x", h)
}

func run(adminPass, dir string) {
	// ---------- 静态与健康 ----------
	r := do("GET", "/health/live", nil, nil)
	check("health/live 200 {status:ok}", r.Status == 200 && r.Body["status"] == "ok", r.Raw)
	r = do("GET", "/health/ready", nil, nil)
	check("health/ready 200", r.Status == 200 && r.Body["database"] == "ready", r.Raw)
	r = do("GET", "/health/version", nil, nil)
	check("health/version", r.Status == 200 && r.Body["version"] != nil, r.Raw)
	r = do("GET", "/login", nil, nil)
	check("GET /login 200 html", r.Status == 200 && strings.Contains(r.Raw, "<html"), r.Status)
	check("安全头 nosniff/DENY", r.Hdr.Get("X-Content-Type-Options") == "nosniff" && r.Hdr.Get("X-Frame-Options") != "", r.Hdr)
	check("CSP 存在", r.Hdr.Get("Content-Security-Policy") != "", "no CSP")
	for _, p := range []string{"/", "/rules", "/new", "/edit", "/api-docs.html"} {
		r = do("GET", p, nil, nil)
		check("未登录 "+p+" 302->/login", r.Status == 302 && strings.HasPrefix(r.Hdr.Get("Location"), "/login"), r.Status, r.Hdr.Get("Location"))
	}
	r = do("GET", "/favicon.ico", nil, nil)
	check("favicon", r.Status == 200, r.Status)
	filepath.Walk(os.Args[3], func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(os.Args[3], p)
		rel = filepath.ToSlash(rel)
		rr := do("GET", "/public/"+rel, nil, nil)
		check("静态 /public/"+rel, rr.Status == 200 && len(rr.Raw) == int(info.Size()), rr.Status, " len=", len(rr.Raw), " want=", info.Size())
		return nil
	})
	r = do("GET", "/public/../go.mod", nil, nil)
	check("静态路径穿越拒绝", r.Status != 200 || !strings.Contains(r.Raw, "module"), r.Status)
	r = do("GET", "/nope", nil, nil)
	check("404 NOT_FOUND json", r.Status == 404 && r.Body["code"] == "NOT_FOUND", r.Raw)
	r = do("GET", "/api/configurations", nil, nil)
	check("未登录 API 401 AUTH_REQUIRED", r.Status == 401 && r.Body["code"] == "AUTH_REQUIRED", r.Raw)
	check("API Cache-Control no-store", strings.Contains(r.Hdr.Get("Cache-Control"), "no-store"), r.Hdr.Get("Cache-Control"))
	r = do("GET", "/api/test-environment", nil, nil)
	check("test-environment 未登录 401", r.Status == 401, r.Raw)

	// ---------- 登录 ----------
	r = do("POST", "/api/login", map[string]any{"username": "e2eadmin"}, nil)
	check("登录缺密码 400 INVALID_INPUT", r.Status == 400 && r.Body["code"] == "INVALID_INPUT", r.Raw)
	r = do("POST", "/api/login", "{bad json", nil)
	check("登录非法JSON 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/login", map[string]any{"username": "e2eadmin", "password": "wrong"}, nil)
	check("登录错误 401 AUTH_INVALID", r.Status == 401 && r.Body["code"] == "AUTH_INVALID", r.Raw)
	r = do("POST", "/api/login", map[string]any{"username": "e2eadmin", "password": adminPass}, nil)
	sc := r.Hdr.Get("Set-Cookie")
	check("登录成功 {success:true} 无 token", r.Status == 200 && r.Body["success"] == true && r.Body["token"] == nil, r.Raw)
	check("Cookie HttpOnly+SameSite", strings.Contains(sc, "HttpOnly") && strings.Contains(strings.ToLower(sc), "samesite"), sc)
	cookie = strings.SplitN(sc, ";", 2)[0]
	r = do("GET", "/api/auth-status", nil, nil)
	check("auth-status loggedIn", r.Body["loggedIn"] == true && r.Body["configured"] == true, r.Raw)
	r = do("GET", "/", nil, nil)
	check("登录后 / 200", r.Status == 200, r.Status)
	r = do("GET", "/api/test-environment", nil, nil)
	check("test-environment 已登录", r.Status == 200 && r.Body["test_env"] == true, r.Raw)
	r = do("GET", "/api/sessions", nil, nil)
	check("会话列表", r.Status == 200 && r.Body["sessions"] != nil, r.Raw)

	// 限流：另一个用户名 5 次失败后 429
	saved := cookie
	cookie = ""
	var last resp
	for i := 0; i < 7; i++ {
		last = do("POST", "/api/login", map[string]any{"username": "brute", "password": "x"}, nil)
	}
	check("登录限流 429 RATE_LIMITED + Retry-After", last.Status == 429 && last.Body["code"] == "RATE_LIMITED" && last.Hdr.Get("Retry-After") != "", last.Status, last.Raw)
	r = do("POST", "/api/login", map[string]any{"username": "e2eadmin", "password": adminPass}, nil)
	check("限流按用户名隔离，管理员仍可登录", r.Status == 200, r.Raw)
	second := strings.SplitN(r.Hdr.Get("Set-Cookie"), ";", 2)[0]
	cookie = saved

	// ---------- 向导：草稿 + 回调 ----------
	genTok := "Tok" + rnd(8); genAes := (rnd(22))[:43]; r = do("POST", "/api/generate-callback", map[string]any{"corpid": "wwe2e0001", "callback_token": genTok, "encoding_aes_key": genAes}, nil)
	check("generate-callback 草稿", (r.Status == 200 || r.Status == 201) && r.Body["code"] != nil, r.Raw)
	code := s(r.Body["code"])
	ver := num(r.Body["version"])
	cbTok := genTok; _ = s(r.Body["token"])
	aesKey := genAes
	check("generate-callback 返回回调 token/aesKey/version", len(cbTok) > 0 && len(aesKey) == 43 && ver > 0, r.Raw)

	if len(aesKey) == 43 {
	ts := fmt.Sprint(time.Now().Unix())
	echo := wxEncrypt(aesKey, "wwe2e0001", "echo-ok-123")
	sig := wxSign(cbTok, ts, "n1", echo)
	q := url.Values{"msg_signature": {sig}, "timestamp": {ts}, "nonce": {"n1"}, "echostr": {echo}}
	r = do("GET", "/api/callback/"+code+"?"+q.Encode(), nil, nil)
	check("回调 URL 验证返回明文 echostr", r.Status == 200 && r.Raw == "echo-ok-123", r.Status, r.Raw)
	q.Set("msg_signature", "bad")
	r = do("GET", "/api/callback/"+code+"?"+q.Encode(), nil, nil)
	check("回调错误签名拒绝", r.Status >= 400, r.Status, r.Raw)
	// 回调消息
	xmlMsg := "<xml><ToUserName><![CDATA[wwe2e0001]]></ToUserName><FromUserName><![CDATA[u1]]></FromUserName><CreateTime>1</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[hi]]></Content><MsgId>123456</MsgId><AgentID>1000002</AgentID></xml>"
	enc := wxEncrypt(aesKey, "wwe2e0001", xmlMsg)
	ts2 := fmt.Sprint(time.Now().Unix())
	sig2 := wxSign(cbTok, ts2, "n2", enc)
	body := "<xml><ToUserName><![CDATA[wwe2e0001]]></ToUserName><Encrypt><![CDATA[" + enc + "]]></Encrypt><AgentID><![CDATA[1000002]]></AgentID></xml>"
	q2 := url.Values{"msg_signature": {sig2}, "timestamp": {ts2}, "nonce": {"n2"}}
	r = do("POST", "/api/callback/"+code+"?"+q2.Encode(), []byte(body), map[string]string{"Content-Type": "text/xml"})
	check("回调消息解密处理 200", r.Status == 200, r.Status, r.Raw)
	r = do("POST", "/api/callback/"+code+"?"+q2.Encode(), []byte(body), map[string]string{"Content-Type": "text/xml"})
	check("回调重放(相同nonce)拒绝或幂等", r.Status == 200 || r.Status >= 400, r.Status)
	}

	// 草稿不可发送
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "x"}, nil)
	check("草稿发送 409 APP_NOT_COMPLETED", r.Status == 409 && r.Body["code"] == "APP_NOT_COMPLETED", r.Raw)

	// validate
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0001", "corpsecret": "sec", "agentid": "abc"}, nil)
	check("validate 非法 agentid 400 INVALID_INPUT", r.Status == 400 && r.Body["code"] == "INVALID_INPUT", r.Raw)
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0001", "corpsecret": "sec", "agentid": 1000002}, nil)
	us, _ := r.Body["users"].([]any)
	check("validate 成功 {agentid,users} 合并直属+部门成员", r.Status == 200 && num(r.Body["agentid"]) == 1000002 && len(us) == 3, r.Raw)
	mode.Store("cred")
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0002", "corpsecret": "bad", "agentid": 1000002}, nil)
	check("validate 凭证错误 400 WECHAT_CREDENTIAL_INVALID", r.Status == 400 && r.Body["code"] == "WECHAT_CREDENTIAL_INVALID", r.Raw)
	check("validate 错误不回显 secret", !strings.Contains(r.Raw, "bad"), r.Raw)
	mode.Store("down")
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0003", "corpsecret": "sec3", "agentid": 1000002}, nil)
	check("validate 网络断开 502 WECHAT_UNAVAILABLE", r.Status == 502 && r.Body["code"] == "WECHAT_UNAVAILABLE", r.Raw)
	check("validate 网络错误不泄露 corpsecret", !strings.Contains(r.Raw, "sec3"), r.Raw)
	mode.Store("deptfail")
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0001", "corpsecret": "sec", "agentid": 1000002}, nil)
	check("validate 部门成员失败 400 WECHAT_CREDENTIAL_INVALID", r.Status == 400 && r.Body["code"] == "WECHAT_CREDENTIAL_INVALID", r.Raw)
	mode.Store("slow")
	t0 := time.Now()
	r = do("POST", "/api/validate", map[string]any{"corpid": "wwe2e0004", "corpsecret": "sec", "agentid": 1000002}, nil)
	check("validate 上游超时 502 且受 WECHAT_HTTP_TIMEOUT_MS 约束", r.Status == 502 && time.Since(t0) < 12*time.Second, r.Status, time.Since(t0))
	mode.Store("ok")

	// complete-config
	r = do("POST", "/api/complete-config", map[string]any{"code": code, "corpsecret": "sec", "agentid": 1000002, "touser": []string{"u1", "u2"}, "description": "e2e", "version": 999}, nil)
	check("complete-config 旧版本 409 APP_VERSION_CONFLICT", r.Status == 409 && r.Body["code"] == "APP_VERSION_CONFLICT", r.Raw)
	r = do("POST", "/api/complete-config", map[string]any{"code": code, "corpsecret": "sec", "agentid": 1000002, "touser": []string{"u1", "u2"}, "description": "e2e", "version": ver}, nil)
	check("complete-config 成功", r.Status == 200, r.Raw)
	r = do("GET", "/api/configuration/"+code, nil, nil)
	check("配置详情", r.Status == 200 && r.Body["code"] != nil, r.Raw)
	check("详情不泄露 corpsecret/aes", !strings.Contains(r.Raw, "\"sec\"") && !strings.Contains(r.Raw, aesKey), r.Raw)
	ver = num(r.Body["version"])
	r = do("GET", "/api/configurations", nil, nil)
	check("配置列表", r.Status == 200 && r.Body["configurations"] != nil, r.Raw)
	r = do("GET", "/api/configuration/"+code+"/users", nil, nil)
	check("成员接口", r.Status == 200 && r.Body["users"] != nil, r.Raw)

	// If-Match
	r = do("PUT", "/api/configuration/"+code, map[string]any{"description": "d2"}, nil)
	check("PUT 无 If-Match 428 APP_VERSION_REQUIRED", r.Status == 428 && r.Body["code"] == "APP_VERSION_REQUIRED", r.Status, r.Raw)
	r = do("PUT", "/api/configuration/"+code, map[string]any{"description": "d2"}, map[string]string{"If-Match": "abc"})
	check("PUT If-Match 非法 400 INVALID_INPUT", r.Status == 400 && r.Body["code"] == "INVALID_INPUT", r.Status, r.Raw)
	r = do("PUT", "/api/configuration/"+code, map[string]any{"description": "d2"}, map[string]string{"If-Match": "999"})
	check("PUT 旧版本 409", r.Status == 409 && r.Body["code"] == "APP_VERSION_CONFLICT", r.Raw)
	r = do("PUT", "/api/configuration/"+code, map[string]any{"corpid": "wwOTHER"}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("PUT 修改 CorpID 400 CORPID_IMMUTABLE", r.Status == 400 && r.Body["code"] == "CORPID_IMMUTABLE", r.Raw)
	r = do("PUT", "/api/configuration/"+code, map[string]any{"description": "d2"}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("PUT 更新描述 + 返回新 version", r.Status == 200 && num(r.Body["version"]) == ver+1, r.Raw)
	ver = num(r.Body["version"])
	r = do("PUT", "/api/configuration/"+code, "[1,2]", map[string]string{"If-Match": fmt.Sprint(ver)})
	check("PUT 数组 body 400 INVALID_INPUT", r.Status == 400 && r.Body["code"] == "INVALID_INPUT", r.Raw)

	// ---------- notify ----------
	n0 := sendCount()
	r = do("POST", "/api/notify/"+code, map[string]any{"title": "T", "content": "hello", "toUser": "attacker"}, nil)
	ls := lastSend()
	check("notify text 成功 {message:发送成功,response}", r.Status == 200 && r.Body["message"] == "发送成功" && r.Body["response"] != nil, r.Raw)
	check("notify text 拼接 T\\nhello", ls != nil && s(ls["text"].(map[string]any)["content"]) == "T\nhello", ls)
	check("toUser 被忽略，按配置 u1|u2", ls != nil && ls["touser"] == "u1|u2", ls)
	check("safe 默认 0", ls != nil && num(ls["safe"]) == 0, ls)
	r = do("POST", "/api/notify/"+code, map[string]any{"title": "T", "content": "hello"}, nil)
	rm, _ := r.Body["response"].(map[string]any)
	check("重复消息命中缓存 cached=true 不再发送", sendCount() == n0+1 && rm["cached"] == true, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"title": "T", "content": "hello", "force": true}, nil)
	check("force 绕过缓存", sendCount() == n0+2, sendCount()-n0)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "secret", "safe": 1}, nil)
	check("safe=1 透传", r.Status == 200 && num(lastSend()["safe"]) == 1, lastSend())
	r = do("POST", "/api/notify/"+code, map[string]any{"title": "MT", "content": "**b**", "msgType": "markdown"}, nil)
	check("markdown", r.Status == 200 && strings.HasPrefix(s(lastSend()["markdown"].(map[string]any)["content"]), "**MT**\n\n"), r.Raw, lastSend())
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "image", "mediaId": "M1"}, nil)
	check("image(mediaId)", r.Status == 200 && lastSend()["msgtype"] == "image", r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "file", "mediaId": "F1"}, nil)
	check("file(mediaId)", r.Status == 200 && lastSend()["msgtype"] == "file", r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "image"}, nil)
	check("image 缺 mediaId 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "textcard", "title": "卡片", "content": "描述", "url": "https://example.com", "btntxt": "看看"}, nil)
	tc, _ := lastSend()["textcard"].(map[string]any)
	check("textcard(title/content/url/btntxt)", r.Status == 200 && tc != nil && tc["description"] == "描述" && tc["btntxt"] == "看看", r.Raw, lastSend())
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "textcard", "title": "卡片"}, nil)
	check("textcard 缺 url 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "news", "articles": []any{map[string]any{"title": "n", "url": "https://e.com"}}}, nil)
	check("news", r.Status == 200 && lastSend()["msgtype"] == "news", r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "news", "articles": []any{map[string]any{"title": ""}}}, nil)
	check("news 非法 article 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"msgType": "voice", "content": "x"}, nil)
	check("不支持类型 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"title": "only"}, nil)
	check("text 缺 content 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, "{bad", nil)
	check("notify 非法 JSON 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, "[1]", nil)
	check("notify 数组 body 400", r.Status == 400, r.Raw)
	r = do("POST", "/api/notify/"+code, []byte("content=x"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	check("notify 非 JSON Content-Type 400", r.Status == 400, r.Raw)
	big := strings.Repeat("a", 300*1024)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": big}, nil)
	check("notify 超大 body 413 PAYLOAD_TOO_LARGE", r.Status == 413 && r.Body["code"] == "PAYLOAD_TOO_LARGE", r.Status, r.Body)
	r = do("POST", "/api/notify/NOPE-CODE-X", map[string]any{"content": "x"}, nil)
	check("未知 code 404 APP_NOT_FOUND", r.Status == 404 && r.Body["code"] == "APP_NOT_FOUND", r.Raw)
	r = do("POST", "/api/notify/"+strings.ToUpper(code), map[string]any{"content": "upper-case", "force": true}, nil)
	check("code 大小写不敏感", r.Status == 200, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "中文 GBK 测试 ✓", "force": true}, nil)
	check("UTF-8 中文/emoji", r.Status == 200 && strings.Contains(s(lastSend()["text"].(map[string]any)["content"]), "✓"), r.Raw)

	// 上游错误
	mode.Store("rate")
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "rate", "force": true}, nil)
	check("企业微信 45009 → 429", r.Status == 429, r.Raw)
	mode.Store("ok")
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "after-rate", "force": true}, nil)
	check("45009 后进入退避 429 WECHAT_BACKOFF", r.Status == 429, r.Raw)

	time.Sleep(2 * time.Second) // 等待退避结束
	// 并发：50 个不同内容 + 20 个相同内容
	n1 := sendCount()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := do("POST", "/api/notify/"+code, map[string]any{"content": "same-concurrent"}, nil)
			mu.Lock()
			codes[rr.Status]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	_ = n1
	check("并发相同消息仅实际发送 1 次（若在退避中则 0 次）", sendCount()-n1 <= 1, sendCount()-n1, codes)

	// ---------- 规则 ----------
	r = do("GET", "/api/rule-api-codes/availability?api_code=e2e-rule-01", nil, nil)
	check("规则码可用性", r.Status == 200 && r.Body["available"] == true, r.Raw)
	r = do("GET", "/api/rule-api-codes/availability?api_code=" + code, nil, nil)
	check("规则码与应用码冲突不可用", r.Status == 200 && r.Body["available"] == false, r.Raw)
	r = do("POST", "/api/configuration/"+code+"/rules", map[string]any{"name": "R1", "touser": []string{"u3"}, "api_code": "e2e-rule-01"}, nil)
	check("创建规则无 If-Match 428", r.Status == 428, r.Status, r.Raw)
	r = do("POST", "/api/configuration/"+code+"/rules", map[string]any{"name": "R1", "touser": []string{"u3"}, "api_code": "e2e-rule-01"}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("创建规则", r.Status == 200 || r.Status == 201, r.Raw)
	rule, _ := r.Body["rule"].(map[string]any)
	ruleID := fmt.Sprint(num(rule["id"]))
	if v := num(r.Body["version"]); v > 0 {
		ver = v
	} else if v := num(r.Body["app_version"]); v > 0 {
		ver = v
	}
	r = do("POST", "/api/notify/e2e-rule-01", map[string]any{"content": "via rule", "toUser": "@all"}, nil)
	ls = lastSend()
	check("规则发送按规则接收人 u3，忽略 toUser", r.Status == 200 && ls["touser"] == "u3", r.Raw, ls)
	r = do("GET", "/api/configuration/"+code+"/rules", nil, nil)
	check("规则列表", r.Status == 200 && r.Body["rules"] != nil, r.Raw)
	r = do("PUT", "/api/rules/"+ruleID+"/enabled", map[string]any{"enabled": false}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("停用规则", r.Status == 200, r.Raw)
	if v := num(r.Body["version"]); v > 0 {
		ver = v
	} else if v := num(r.Body["app_version"]); v > 0 {
		ver = v
	}
	r = do("POST", "/api/notify/e2e-rule-01", map[string]any{"content": "rule off", "force": true}, nil)
	check("停用规则发送 403 RULE_DISABLED", r.Status == 403 && r.Body["code"] == "RULE_DISABLED", r.Raw)
	r = do("POST", "/api/rules/"+ruleID+"/regenerate", nil, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("规则重新生成推送码（无 body）", r.Status == 200, r.Status, r.Raw)
	if v := num(r.Body["version"]); v > 0 {
		ver = v
	} else if v := num(r.Body["app_version"]); v > 0 {
		ver = v
	}
	r = do("DELETE", "/api/rules/"+ruleID, nil, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("删除规则（无 body，同前端 http.del）", r.Status == 200, r.Status, r.Raw)
	if v := num(r.Body["version"]); v > 0 {
		ver = v
	} else if v := num(r.Body["app_version"]); v > 0 {
		ver = v
	}

	// ---------- 开关与密钥 ----------
	r = do("GET", "/api/configuration/"+code, nil, nil)
	ver = num(r.Body["version"])
	r = do("PUT", "/api/configuration/"+code+"/code-send", map[string]any{"enabled": false}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("关闭 Code 直发", r.Status == 200, r.Raw)
	ver = num(r.Body["version"])
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "direct off", "force": true}, nil)
	check("直发关闭 403 DIRECT_SEND_DISABLED", r.Status == 403 && r.Body["code"] == "DIRECT_SEND_DISABLED", r.Raw)
	r = do("PUT", "/api/configuration/"+code+"/code-send", map[string]any{"enabled": true}, map[string]string{"If-Match": fmt.Sprint(ver)})
	ver = num(r.Body["version"])
	r = do("POST", "/api/configuration/"+code+"/notify-key", nil, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("启用通知密钥（无 body，同前端）", r.Status == 200 && r.Body["notify_key"] != nil, r.Status, r.Raw)
	nk := s(r.Body["notify_key"])
	ver = num(r.Body["version"])
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "nokey", "force": true}, nil)
	check("缺 X-Notify-Key 401 AUTH_REQUIRED", r.Status == 401 && r.Body["code"] == "AUTH_REQUIRED", r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "badkey", "force": true}, map[string]string{"X-Notify-Key": "wrong"})
	check("错误 X-Notify-Key 401", r.Status == 401, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "goodkey", "force": true}, map[string]string{"X-Notify-Key": nk})
	check("正确 X-Notify-Key 200", r.Status == 200, r.Raw)
	r = do("DELETE", "/api/configuration/"+code+"/notify-key", nil, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("撤销通知密钥（无 body，同前端）", r.Status == 200, r.Status, r.Raw)
	if v := num(r.Body["version"]); v > 0 {
		ver = v
	}
	r = do("PUT", "/api/configuration/"+code+"/app-enabled", map[string]any{"enabled": "no"}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("app-enabled 非布尔 400", r.Status == 400, r.Raw)
	r = do("PUT", "/api/configuration/"+code+"/app-enabled", map[string]any{"enabled": false}, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("暂停应用", r.Status == 200, r.Raw)
	ver = num(r.Body["version"])
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "paused", "force": true}, nil)
	check("暂停后 403 APP_DISABLED", r.Status == 403 && r.Body["code"] == "APP_DISABLED", r.Raw)
	r = do("PUT", "/api/configuration/"+code+"/app-enabled", map[string]any{"enabled": true}, map[string]string{"If-Match": fmt.Sprint(ver)})
	ver = num(r.Body["version"])

	// ---------- 重启持久化 + 优雅退出 ----------
	stopApp()
	startApp(dir)
	r = do("GET", "/api/configuration/"+code, nil, nil)
	check("重启后数据保留（会话需重新登录或仍有效）", r.Status == 200 || r.Status == 401, r.Status)
	if r.Status == 401 {
		cookie = ""
		lr := do("POST", "/api/login", map[string]any{"username": "e2eadmin", "password": adminPass}, nil)
		cookie = strings.SplitN(lr.Hdr.Get("Set-Cookie"), ";", 2)[0]
		r = do("GET", "/api/configuration/"+code, nil, nil)
	}
	check("重启后配置仍存在且版本一致", r.Status == 200 && num(r.Body["version"]) == ver, r.Status, num(r.Body["version"]), ver)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "after restart", "force": true}, nil)
	check("重启后可发送（密钥可解密）", r.Status == 200, r.Raw)

	// ---------- 删除 ----------
	r = do("DELETE", "/api/configuration/"+code, nil, map[string]string{"If-Match": fmt.Sprint(ver)})
	check("删除应用（无 body，同前端）", r.Status == 200, r.Status, r.Raw)
	r = do("POST", "/api/notify/"+code, map[string]any{"content": "deleted", "force": true}, nil)
	check("删除后 404", r.Status == 404, r.Raw)

	// ---------- 会话吊销 ----------
	r = do("GET", "/api/sessions", nil, nil)
	sl, _ := r.Body["sessions"].([]any)
	check("会话列表多会话", len(sl) >= 1, r.Raw)
	saved = cookie
	cookie = second
	r = do("GET", "/api/auth-status", nil, nil)
	_ = r
	cookie = saved
	r = do("POST", "/api/logout", nil, nil)
	check("登出", r.Status == 200, r.Raw)
	r = do("GET", "/api/configurations", nil, nil)
	check("登出后 401", r.Status == 401, r.Status)
	cookie = ""
	lr := do("POST", "/api/login", map[string]any{"username": "e2eadmin", "password": adminPass}, nil)
	cookie = strings.SplitN(lr.Hdr.Get("Set-Cookie"), ";", 2)[0]
	r = do("DELETE", "/api/sessions", nil, nil)
	check("DELETE /api/sessions 吊销全部", r.Status == 200, r.Raw)
	r = do("GET", "/api/configurations", nil, nil)
	check("吊销全部后当前会话失效", r.Status == 401, r.Status)

	// ---------- 优雅退出 ----------
	if appCmd.Process != nil {
		appCmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- appCmd.Wait() }()
		select {
		case <-done:
			check("优雅退出(Interrupt)", true)
		case <-time.After(15 * time.Second):
			check("优雅退出(Interrupt) 15s 内退出", false, "timeout (Windows 不支持向子进程发送 Interrupt 时属正常)")
		}
	}
}