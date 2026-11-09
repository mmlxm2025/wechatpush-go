package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	assets "qywx-notifier-plus"
	"qywx-notifier-plus/internal/auth"
	"qywx-notifier-plus/internal/bodyparser"
	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/notifyauth"
	"qywx-notifier-plus/internal/ratelimit"
	"qywx-notifier-plus/internal/service"
)

const ContentSecurityPolicyValue = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

var positiveIntRegex = regexp.MustCompile(`^[1-9]\d*$`)

type Server struct {
	cfg                 *config.Config
	notifier            *service.Notifier
	authSvc             *auth.Service
	nonceStore          *notifyauth.NonceStore
	loginRateLimiter    *ratelimit.LoginRateLimiter
	notifyRateLimiter   *ratelimit.RateLimiter
	callbackRateLimiter *ratelimit.RateLimiter
	shuttingDown        atomic.Bool
	stopCleanupCh       chan struct{}
	handler             http.Handler
}

func NewServer(cfg *config.Config, notifier *service.Notifier, authSvc *auth.Service) *Server {
	if cfg == nil {
		cfg = config.FromEnv()
	}
	s := &Server{
		cfg:                 cfg,
		notifier:            notifier,
		authSvc:             authSvc,
		nonceStore:          notifyauth.NewNonceStore(cfg.NotifyTimestampToleranceSec, cfg.NotifyNonceTTLMs, cfg.NotifyNonceHardLimit),
		loginRateLimiter:    ratelimit.NewLoginRateLimiter(cfg.LoginRateWindowMs, cfg.LoginRateMax),
		notifyRateLimiter:   ratelimit.NewRateLimiter(cfg.NotifyRateWindowMs, cfg.NotifyRateMax),
		callbackRateLimiter: ratelimit.NewRateLimiter(cfg.CallbackRateWindowMs, cfg.CallbackRateMax),
		stopCleanupCh:       make(chan struct{}),
	}
	s.handler = s.buildHandler()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) NonceStore() *notifyauth.NonceStore {
	return s.nonceStore
}

func (s *Server) LoginRateLimiter() *ratelimit.LoginRateLimiter {
	return s.loginRateLimiter
}

func (s *Server) NotifyRateLimiter() *ratelimit.RateLimiter {
	return s.notifyRateLimiter
}

func (s *Server) CallbackRateLimiter() *ratelimit.RateLimiter {
	return s.callbackRateLimiter
}

func (s *Server) SetShuttingDown(val bool) {
	s.shuttingDown.Store(val)
}

func (s *Server) StartBackgroundCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.loginRateLimiter.Cleanup()
				s.notifyRateLimiter.Cleanup()
				s.callbackRateLimiter.Cleanup()
				s.nonceStore.Cleanup()
				s.authSvc.CleanupExpiredSessions()
				s.notifier.CleanupExpiredState()
			case <-s.stopCleanupCh:
				return
			}
		}
	}()
}

func (s *Server) StopBackgroundCleanup() {
	select {
	case <-s.stopCleanupCh:
	default:
		close(s.stopCleanupCh)
	}
}

func applySecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	h.Set("Content-Security-Policy", ContentSecurityPolicyValue)
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-XSS-Protection", "0")
}

func applyNoStoreHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, private")
	h.Set("Pragma", "no-cache")
	h.Set("Surrogate-Control", "no-store")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) sendError(w http.ResponseWriter, err error, fallbackStatus int, _ string) {
	// 与 Node 版 routes.js sendError 一致：
	//   - 仅序列化业务错误自带的 code/details，不额外补 *_FAILED 兜底码；
	//   - 5xx 无业务码时补 INTERNAL_ERROR；
	//   - production 下 5xx 统一隐藏为“服务器内部错误”。
	if fallbackStatus <= 0 {
		fallbackStatus = http.StatusInternalServerError
	}
	status := fallbackStatus
	msg := ""
	code := ""
	body := map[string]any{}

	var appErr *service.AppError
	var dbErr *database.DBError
	switch {
	case errors.As(err, &appErr):
		if appErr.StatusCode > 0 {
			status = appErr.StatusCode
		}
		msg = appErr.Message
		code = appErr.Code
		if appErr.ConflictCode != "" {
			body["conflictCode"] = appErr.ConflictCode
		}
		if appErr.Details != nil {
			body["details"] = appErr.Details
		}
	case errors.As(err, &dbErr):
		if dbErr.StatusCode > 0 {
			status = dbErr.StatusCode
		}
		msg = dbErr.Message
		code = dbErr.Code
	case err != nil:
		msg = err.Error()
	}

	if msg == "" {
		msg = "请求失败"
	}
	if status >= 500 && s.cfg.NodeEnv == "production" {
		msg = "服务器内部错误"
	}
	if status >= 500 && code == "" {
		code = "INTERNAL_ERROR"
	}
	body["error"] = msg
	if code != "" {
		body["code"] = code
	}
	writeJSON(w, status, body)
}
func extractExpectedVersion(r *http.Request, body map[string]any) *int {
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	var raw string
	hasRaw := false

	if ifMatch != "" {
		cleaned := strings.TrimPrefix(ifMatch, "W/")
		cleaned = strings.TrimPrefix(cleaned, "w/")
		cleaned = strings.Trim(cleaned, `"`)
		raw = strings.TrimSpace(cleaned)
		hasRaw = true
	} else if body != nil {
		if v, exists := body["version"]; exists && v != nil {
			raw = strings.TrimSpace(fmt.Sprintf("%v", v))
			hasRaw = true
		}
	}

	if !hasRaw {
		return nil
	}
	if !positiveIntRegex.MatchString(raw) {
		invalid := -1
		return &invalid
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		invalid := -1
		return &invalid
	}
	return &n
}

// resolveClientIP 根据 TRUST_PROXY 配置解析客户端真实 IP
func (s *Server) resolveClientIP(r *http.Request) string {
	remoteIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteIP = host
	}
	remoteIP = strings.TrimPrefix(remoteIP, "::ffff:")
	if remoteIP == "" {
		remoteIP = "unknown"
	}

	rawTrust := strings.TrimSpace(s.cfg.TrustProxy)
	lowerTrust := strings.ToLower(rawTrust)
	if rawTrust == "" || lowerTrust == "false" || lowerTrust == "0" {
		return remoteIP
	}

	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return remoteIP
	}
	parts := strings.Split(xff, ",")
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimPrefix(strings.TrimSpace(p), "::ffff:")
		if trimmed != "" {
			ips = append(ips, trimmed)
		}
	}
	if len(ips) == 0 {
		return remoteIP
	}

	if lowerTrust == "true" {
		return ips[0]
	}

	if hops, err := strconv.Atoi(rawTrust); err == nil && hops > 0 {
		idx := len(ips) - hops
		if idx < 0 {
			idx = 0
		}
		return ips[idx]
	}

	if isTrustedProxyIP(remoteIP, rawTrust) {
		// 从右向左跳过受信任代理，返回第一个非受信任代理 IP
		for i := len(ips) - 1; i >= 0; i-- {
			if !isTrustedProxyIP(ips[i], rawTrust) {
				return ips[i]
			}
		}
		return ips[0]
	}

	return remoteIP
}

func isTrustedProxyIP(ipStr, trustSpec string) bool {
	parsedIP := net.ParseIP(strings.TrimPrefix(strings.TrimSpace(ipStr), "::ffff:"))
	if parsedIP == nil {
		return false
	}
	tokens := strings.Split(trustSpec, ",")
	for _, tok := range tokens {
		t := strings.ToLower(strings.TrimSpace(tok))
		if t == "" {
			continue
		}
		if t == "loopback" {
			if parsedIP.IsLoopback() {
				return true
			}
			continue
		}
		if strings.Contains(t, "/") {
			if _, cidrNet, err := net.ParseCIDR(t); err == nil && cidrNet.Contains(parsedIP) {
				return true
			}
		} else if targetIP := net.ParseIP(t); targetIP != nil && targetIP.Equal(parsedIP) {
			return true
		}
	}
	return false
}

func (s *Server) isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	rawTrust := strings.TrimSpace(s.cfg.TrustProxy)
	lowerTrust := strings.ToLower(rawTrust)
	if rawTrust == "" || lowerTrust == "false" || lowerTrust == "0" {
		return false
	}
	remoteIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteIP = host
	}
	remoteIP = strings.TrimPrefix(remoteIP, "::ffff:")

	trusted := false
	if lowerTrust == "true" {
		trusted = true
	} else if hops, err := strconv.Atoi(rawTrust); err == nil && hops > 0 {
		trusted = true
	} else if isTrustedProxyIP(remoteIP, rawTrust) {
		trusted = true
	}
	if !trusted {
		return false
	}
	xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if xfp == "" {
		return false
	}
	firstProto := strings.ToLower(strings.TrimSpace(strings.Split(xfp, ",")[0]))
	return firstProto == "https"
}

func (s *Server) readPublicFile(relPath string) ([]byte, error) {
	cleanRel := strings.TrimPrefix(path.Clean("/"+relPath), "/")
	if strings.Contains(cleanRel, "..") {
		return nil, os.ErrNotExist
	}
	if s.cfg.PublicDir != "" {
		diskPath := filepath.Join(s.cfg.PublicDir, filepath.FromSlash(cleanRel))
		if data, err := os.ReadFile(diskPath); err == nil {
			return data, nil
		}
	}
	return fs.ReadFile(assets.PublicFS, path.Join("public", cleanRel))
}

func (s *Server) servePublicAsset(w http.ResponseWriter, r *http.Request, relPath string, forceNoStore bool) {
	data, err := s.readPublicFile(relPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "未找到资源",
			"code":  "NOT_FOUND",
		})
		return
	}
	if forceNoStore {
		applyNoStoreHeaders(w)
	}
	ext := strings.ToLower(path.Ext(relPath))
	ct := mime.TypeByExtension(ext)
	switch ext {
	case ".html":
		ct = "text/html; charset=utf-8"
	case ".js":
		ct = "application/javascript; charset=utf-8"
	case ".css":
		ct = "text/css; charset=utf-8"
	case ".svg":
		ct = "image/svg+xml"
	case ".json":
		ct = "application/json; charset=utf-8"
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) checkPageSession(r *http.Request) bool {
	token, _ := auth.ExtractTokenFromRequest(r)
	if token == "" {
		return false
	}
	return s.authSvc.ValidateSession(token).Valid
}

func (s *Server) buildHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)

		urlPath := r.URL.Path
		method := r.Method

		if strings.HasPrefix(urlPath, "/api/") || urlPath == "/api" {
			applyNoStoreHeaders(w)
		}

		// 1. 静态资源与页面路由
		if method == http.MethodGet || method == http.MethodHead {
			switch urlPath {
			case "/favicon.ico":
				s.servePublicAsset(w, r, "favicon.svg", false)
				return
			case "/login":
				s.servePublicAsset(w, r, "login.html", false)
				return
			case "/":
				applyNoStoreHeaders(w)
				if !s.checkPageSession(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				s.servePublicAsset(w, r, "index.html", true)
				return
			case "/rules":
				applyNoStoreHeaders(w)
				if !s.checkPageSession(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				s.servePublicAsset(w, r, "rules.html", true)
				return
			case "/api-docs.html":
				applyNoStoreHeaders(w)
				if !s.checkPageSession(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				s.servePublicAsset(w, r, "api-docs.html", true)
				return
			case "/new":
				applyNoStoreHeaders(w)
				if !s.checkPageSession(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				s.servePublicAsset(w, r, "wizard.html", true)
				return
			case "/edit":
				applyNoStoreHeaders(w)
				if !s.checkPageSession(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				s.servePublicAsset(w, r, "edit.html", true)
				return
			case "/health/live":
				writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
				return
			case "/health/version":
				writeJSON(w, http.StatusOK, map[string]any{
					"version":  s.cfg.AppVersion,
					"revision": s.cfg.AppRevision,
				})
				return
			case "/health/ready":
				s.handleHealthReady(w, r)
				return
			}

			if strings.HasPrefix(urlPath, "/public/") {
				rel := strings.TrimPrefix(urlPath, "/public/")
				if rel != "" {
					s.servePublicAsset(w, r, rel, false)
					return
				}
			}
		}

		// 2. API 路由
		if strings.HasPrefix(urlPath, "/api/") {
			s.handleAPI(w, r)
			return
		}

		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "未找到资源",
			"code":  "NOT_FOUND",
		})
	})
}

func (s *Server) handleHealthReady(w http.ResponseWriter, _ *http.Request) {
	// 优雅退出期间返回 503，便于编排摘流（Go 版扩展，Node 版无此状态）。
	if s.shuttingDown.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "shutting_down",
			"error":  "服务正在关闭",
		})
		return
	}

	// 与 Node 版一致：仅验证数据库可读；不向外暴露内部错误细节。
	if _, err := s.notifier.DB().RawExec("SELECT 1"); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  "数据库不可用",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"database": "ready",
	})
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	method := r.Method

	// 1. 公开企业微信回调接口（使用原始文本/XML 流，不走 JSON 解析器）
	if strings.HasPrefix(urlPath, "/api/callback/") {
		code := strings.TrimPrefix(urlPath, "/api/callback/")
		if code != "" && !strings.Contains(code, "/") {
			if method == http.MethodGet {
				s.handleCallbackVerify(w, r, code)
				return
			}
			if method == http.MethodPost {
				s.handleCallbackMessage(w, r, code)
				return
			}
		}
	}

	// 2. 公开外部通知推送接口 POST /api/notify/:code
	if strings.HasPrefix(urlPath, "/api/notify/") && method == http.MethodPost {
		code := strings.TrimPrefix(urlPath, "/api/notify/")
		if code != "" && !strings.Contains(code, "/") {
			s.handleNotify(w, r, code)
			return
		}
	}

	// 3. 登录态探测与登录/登出接口
	if urlPath == "/api/auth-status" && method == http.MethodGet {
		token, _ := auth.ExtractTokenFromRequest(r)
		res := s.authSvc.ValidateSession(token)
		configured := strings.TrimSpace(s.cfg.AdminUsername) != "" && strings.TrimSpace(s.cfg.AdminPassword) != ""
		if res.Valid {
			writeJSON(w, http.StatusOK, map[string]any{
				"loggedIn":      true,
				"configured":    configured,
				"authenticated": true,
				"username":      res.Username,
			})
		} else {
			writeJSON(w, http.StatusOK, map[string]any{
				"loggedIn":      false,
				"configured":    configured,
				"authenticated": false,
			})
		}
		return
	}

	if urlPath == "/api/test-environment" && method == http.MethodGet {
		// QA-001：仅隔离测试实例开放；生产未设置 TEST_INSTANCE_ID 时保持 404。
		testID := strings.TrimSpace(s.cfg.TestInstanceID)
		if testID == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "未找到资源", "code": "NOT_FOUND"})
			return
		}
		token, _ := auth.ExtractTokenFromRequest(r)
		if !s.authSvc.ValidateSession(token).Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录或登录已过期", "code": "AUTH_REQUIRED"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"test_env":    true,
			"instance_id": testID,
		})
		return
	}

	if urlPath == "/api/login" && method == http.MethodPost {
		s.handleLogin(w, r)
		return
	}

	if urlPath == "/api/logout" && method == http.MethodPost {
		token, _ := auth.ExtractTokenFromRequest(r)
		if token != "" {
			s.authSvc.DestroySession(token)
		}
		w.Header().Add("Set-Cookie", auth.BuildClearSessionCookie(s.isSecureRequest(r)))
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "已退出登录",
		})
		return
	}

	// 4. 以下管理端接口均需要登录态鉴权（requireAuth）
	token, _ := auth.ExtractTokenFromRequest(r)
	sessRes := s.authSvc.ValidateSession(token)
	if !sessRes.Valid {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "未登录或登录已过期",
			"code":  "AUTH_REQUIRED",
		})
		return
	}

	s.handleAdminAPI(w, r, token)
}

func (s *Server) parseJSONOrRespond(w http.ResponseWriter, r *http.Request) (*bodyparser.ParsedBody, bool) {
	parsed, err := bodyparser.ReadAndParseJSON(r, bodyparser.DefaultJSONBodyLimit)
	if err != nil {
		if errors.Is(err, bodyparser.ErrPayloadTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"error": err.Error(),
				"code":  "PAYLOAD_TOO_LARGE",
			})
			return nil, false
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
			"code":  "INVALID_INPUT",
		})
		return nil, false
	}
	return parsed, true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.resolveClientIP(r)

	parsed, ok := s.parseJSONOrRespond(w, r)
	if !ok {
		return
	}

	username, _ := parsed.Data["username"].(string)
	password, _ := parsed.Data["password"].(string)
	if username == "" || password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "用户名和密码不能为空",
			"code":  "INVALID_INPUT",
		})
		return
	}

	// SEC-006：与 Node 版一致，按 用户名 + IP 维度限流。
	rateKey := username + ":" + clientIP
	rateCheck := s.loginRateLimiter.Check(rateKey)
	if !rateCheck.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(rateCheck.RetryAfterSec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "登录尝试过于频繁，请稍后再试",
			"code":  "RATE_LIMITED",
		})
		return
	}

	if !s.authSvc.ValidateCredentials(username, password) {
		s.loginRateLimiter.RecordFailure(rateKey)
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "用户名或密码错误",
			"code":  "AUTH_INVALID",
		})
		return
	}

	s.loginRateLimiter.ClearKey(rateKey)
	token, _, _ := s.authSvc.CreateSession(username, auth.SessionMeta{
		IP:        clientIP,
		UserAgent: r.Header.Get("User-Agent"),
	})
	// SEC-002：会话只通过 HttpOnly Cookie 下发，响应体不回传 token（与 Node 版一致）。
	w.Header().Add("Set-Cookie", auth.BuildSessionCookie(token, s.isSecureRequest(r)))
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
func (s *Server) handleAdminAPI(w http.ResponseWriter, r *http.Request, currentToken string) {
	urlPath := r.URL.Path
	method := r.Method

	// 会话管理接口
	if urlPath == "/api/sessions" {
		switch method {
		case http.MethodGet:
			sessions := s.authSvc.ListActiveSessions(currentToken)
			writeJSON(w, http.StatusOK, map[string]any{
				"success":  true,
				"sessions": sessions,
			})
			return
		case http.MethodDelete:
			scope := r.URL.Query().Get("scope")
			if scope != "others" { // 与 Node 版一致：默认吊销全部会话；?scope=others 为 Go 版扩展
				count := s.authSvc.DestroyAllSessions()
				w.Header().Add("Set-Cookie", auth.BuildClearSessionCookie(s.isSecureRequest(r)))
				writeJSON(w, http.StatusOK, map[string]any{
					"success":      true,
					"revokedCount": count,
					"message":      "已注销全部登录会话",
				})
				return
			}
			count := s.authSvc.DestroyOtherSessions(currentToken)
			writeJSON(w, http.StatusOK, map[string]any{
				"success":      true,
				"revokedCount": count,
				"message":      "已注销其他设备的登录会话",
			})
			return
		}
	}

	if strings.HasPrefix(urlPath, "/api/sessions/") && method == http.MethodDelete {
		sessID := strings.TrimPrefix(urlPath, "/api/sessions/")
		if sessID != "" && !strings.Contains(sessID, "/") {
			// 与 Node 版一致：吊销不存在的会话也返回成功（幂等）。
			s.authSvc.DestroySessionByID(sessID)
			writeJSON(w, http.StatusOK, map[string]any{
				"success": true,
				"revoked": true,
				"message": "会话已注销",
			})
			return
		}
	}

	// 验证企业微信凭据 POST /api/validate
	if urlPath == "/api/validate" && method == http.MethodPost {
		// 与 Node 版 routes.js + notifier.validateAndListMembers 一致。
		parsed, ok := s.parseJSONOrRespond(w, r)
		if !ok {
			return
		}
		corpID, _ := parsed.Data["corpid"].(string)
		corpSecret, _ := parsed.Data["corpsecret"].(string)
		agentNum := 0
		switch v := parsed.Data["agentid"].(type) {
		case json.Number:
			if n, err := strconv.Atoi(v.String()); err == nil {
				agentNum = n
			}
		case float64:
			if v == float64(int(v)) {
				agentNum = int(v)
			}
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				agentNum = n
			}
		}
		if corpID == "" || corpSecret == "" || agentNum <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "参数不完整，请填写CorpID、CorpSecret和AgentID",
				"code":  "INVALID_INPUT",
			})
			return
		}
		agentID := strconv.Itoa(agentNum)
		res := s.notifier.ValidateWeChatConfig(corpID, corpSecret, agentID)
		if !res.Valid {
			s.sendError(w, service.WeChatFailureError(res.Error, res.Unavailable), http.StatusBadRequest, "")
			return
		}
		visRes := s.notifier.WeChat().GetVisibleUsers(corpID, corpSecret, agentID)
		if !visRes.Success {
			s.sendError(w, service.WeChatFailureError(visRes.Error, visRes.Unavailable), http.StatusBadRequest, "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"agentid": agentNum,
			"users":   visRes.Users,
		})
		return
	}

	// 生成回调配置 POST /api/generate-callback
	if urlPath == "/api/generate-callback" && method == http.MethodPost {
		parsed, ok := s.parseJSONOrRespond(w, r)
		if !ok {
			return
		}
		proto := "http"
		if s.isSecureRequest(r) {
			proto = "https"
		}
		baseURL := fmt.Sprintf("%s://%s", proto, r.Host)

		status, res, err := s.notifier.GenerateCallbackFromPayload(baseURL, parsed.Data)
		if err != nil {
			s.sendError(w, err, http.StatusBadRequest, "GENERATE_CALLBACK_FAILED")
			return
		}
		if status <= 0 {
			status = http.StatusOK
		}
		writeJSON(w, status, res)
		return
	}

	// 完成配置 POST /api/complete-config
	if urlPath == "/api/complete-config" && method == http.MethodPost {
		parsed, ok := s.parseJSONOrRespond(w, r)
		if !ok {
			return
		}
		code, _ := parsed.Data["code"].(string)
		if expectedVer := extractExpectedVersion(r, parsed.Data); expectedVer != nil {
			parsed.Data["version"] = *expectedVer
		}
		res, err := s.notifier.CompleteConfiguration(code, parsed.Data)
		if err != nil {
			s.sendError(w, err, http.StatusBadRequest, "COMPLETE_CONFIG_FAILED")
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// 直接创建已完成应用 POST /api/configure
	if urlPath == "/api/configure" && method == http.MethodPost {
		parsed, ok := s.parseJSONOrRespond(w, r)
		if !ok {
			return
		}
		res, err := s.notifier.CreateConfiguration(parsed.Data)
		if err != nil {
			s.sendError(w, err, http.StatusBadRequest, "CREATE_CONFIG_FAILED")
			return
		}
		writeJSON(w, http.StatusCreated, res)
		return
	}

	// 获取所有配置摘要 GET /api/configurations
	if urlPath == "/api/configurations" && method == http.MethodGet {
		list, err := s.notifier.GetAllConfigurationsSummary()
		if err != nil {
			s.sendError(w, err, http.StatusInternalServerError, "GET_CONFIGURATIONS_FAILED")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"success":        true,
			"configurations": list,
		})
		return
	}

	// 获取默认首选配置摘要 GET /api/configuration
	if urlPath == "/api/configuration" && method == http.MethodGet {
		summary, err := s.notifier.GetConfigurationSummary("")
		if err != nil {
			s.sendError(w, err, http.StatusInternalServerError, "GET_CONFIG_FAILED")
			return
		}
		if summary == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"error": "尚未创建任何配置",
				"code":  "CONFIG_NOT_FOUND",
			})
			return
		}
		summaryCopy := make(map[string]any, len(summary))
		for k, v := range summary {
			summaryCopy[k] = v
		}
		summary["success"] = true
		summary["configuration"] = summaryCopy
		writeJSON(w, http.StatusOK, summary)
		return
	}

	// 预检自定义推送码可用性 GET /api/rule-api-codes/availability
	if urlPath == "/api/rule-api-codes/availability" && method == http.MethodGet {
		apiCode := r.URL.Query().Get("api_code")
		if apiCode == "" {
			apiCode = r.URL.Query().Get("apiCode")
		}
		var excludeRuleID *int
		rawExclude := strings.TrimSpace(r.URL.Query().Get("rule_id"))
		if rawExclude == "" {
			rawExclude = strings.TrimSpace(r.URL.Query().Get("ruleId"))
		}
		if rawExclude == "" {
			rawExclude = strings.TrimSpace(r.URL.Query().Get("exclude_rule_id"))
		}
		if rawExclude == "" {
			rawExclude = strings.TrimSpace(r.URL.Query().Get("excludeRuleId"))
		}
		if rawExclude != "" {
			if !positiveIntRegex.MatchString(rawExclude) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error": "rule_id 参数格式无效",
					"code":  "INVALID_INPUT",
				})
				return
			}
			idVal, _ := strconv.Atoi(rawExclude)
			excludeRuleID = &idVal
		}
		res, err := s.notifier.CheckRuleAPICodeAvailability(apiCode, excludeRuleID)
		if err != nil {
			s.sendError(w, err, http.StatusBadRequest, "CHECK_RULE_API_CODE_FAILED")
			return
		}
		if reason, _ := res["reason"].(string); reason == "invalid_format" {
			errMsg, _ := res["message"].(string)
			if errMsg == "" {
				errMsg = "自定义推送码格式无效"
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": errMsg,
				"code":  "RULE_API_CODE_INVALID",
			})
			return
		}
		out := map[string]any{
			"success":    true,
			"available":  res["available"],
			"api_code":   res["api_code"],
			"normalized": res["normalized"],
			"reason":     res["ui_reason"],
			"message":    res["message"],
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	// /api/configuration/:code 及其子路由
	if strings.HasPrefix(urlPath, "/api/configuration/") {
		rest := strings.TrimPrefix(urlPath, "/api/configuration/")
		parts := strings.Split(rest, "/")
		code := parts[0]
		if code != "" {
			if len(parts) == 1 {
				switch method {
				case http.MethodGet:
					summary, err := s.notifier.GetConfigurationSummary(code)
					if err != nil {
						s.sendError(w, err, http.StatusInternalServerError, "GET_CONFIG_FAILED")
						return
					}
					if summary == nil {
						writeJSON(w, http.StatusNotFound, map[string]any{
							"error": "找不到对应的配置",
							"code":  "CONFIG_NOT_FOUND",
						})
						return
					}
					summaryCopy := make(map[string]any, len(summary))
					for k, v := range summary {
						summaryCopy[k] = v
					}
					summary["success"] = true
					summary["configuration"] = summaryCopy
					writeJSON(w, http.StatusOK, summary)
					return
				case http.MethodPut:
					parsed, ok := s.parseJSONOrRespond(w, r)
					if !ok {
						return
					}
					expectedVer := extractExpectedVersion(r, parsed.Data)
					res, err := s.notifier.UpdateConfiguration(code, parsed.Data, expectedVer)
					if err != nil {
						s.sendError(w, err, http.StatusBadRequest, "UPDATE_CONFIG_FAILED")
						return
					}
					writeJSON(w, http.StatusOK, res)
					return
				case http.MethodDelete:
					parsed, ok := s.parseJSONOrRespond(w, r)
					if !ok {
						return
					}
					expectedVer := extractExpectedVersion(r, parsed.Data)
					res, err := s.notifier.DeleteConfiguration(code, expectedVer)
					if err != nil {
						s.sendError(w, err, http.StatusBadRequest, "DELETE_CONFIG_FAILED")
						return
					}
					writeJSON(w, http.StatusOK, res)
					return
				}
			} else if len(parts) == 2 {
				sub := parts[1]
				switch sub {
				case "app-enabled":
					if method == http.MethodPut {
						parsed, ok := s.parseJSONOrRespond(w, r)
						if !ok {
							return
						}
						enabledVal, isBool := parsed.Data["enabled"].(bool)
						if !isBool {
							writeJSON(w, http.StatusBadRequest, map[string]any{
								"error": "enabled 参数必须是布尔值",
								"code":  "INVALID_INPUT",
							})
							return
						}
						expectedVer := extractExpectedVersion(r, parsed.Data)
						res, err := s.notifier.SetAppEnabled(code, enabledVal, expectedVer)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "SET_APP_ENABLED_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
				case "code-send":
					if method == http.MethodPut {
						parsed, ok := s.parseJSONOrRespond(w, r)
						if !ok {
							return
						}
						enabledVal, isBool := parsed.Data["enabled"].(bool)
						if !isBool {
							writeJSON(w, http.StatusBadRequest, map[string]any{
								"error": "enabled 参数必须是布尔值",
								"code":  "INVALID_INPUT",
							})
							return
						}
						expectedVer := extractExpectedVersion(r, parsed.Data)
						res, err := s.notifier.SetCodeSendEnabled(code, enabledVal, expectedVer)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "SET_CODE_SEND_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
				case "notify-key":
					if method == http.MethodPost {
						parsed, ok := s.parseJSONOrRespond(w, r)
						if !ok {
							return
						}
						expectedVer := extractExpectedVersion(r, parsed.Data)
						res, err := s.notifier.RegenerateNotifyKey(code, expectedVer)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "ROTATE_NOTIFY_KEY_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
					if method == http.MethodDelete {
						parsed, ok := s.parseJSONOrRespond(w, r)
						if !ok {
							return
						}
						expectedVer := extractExpectedVersion(r, parsed.Data)
						res, err := s.notifier.RevokeNotifyKey(code, expectedVer)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "REVOKE_NOTIFY_KEY_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
				case "users":
					if method == http.MethodGet {
						forceRefresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
						res, err := s.notifier.GetVisibleUsersWithRefresh(code, forceRefresh)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "GET_VISIBLE_USERS_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
				case "rules":
					if method == http.MethodGet {
						rules, err := s.notifier.GetNotificationRules(code)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "GET_RULES_FAILED")
							return
						}
						cfgSummary, _ := s.notifier.GetConfigurationSummary(code)
						writeJSON(w, http.StatusOK, map[string]any{
							"success": true,
							"config":  cfgSummary,
							"rules":   rules,
						})
						return
					}
					if method == http.MethodPost {
						parsed, ok := s.parseJSONOrRespond(w, r)
						if !ok {
							return
						}
						expectedVer := extractExpectedVersion(r, parsed.Data)
						res, err := s.notifier.CreateNotificationRuleFromPayload(code, parsed.Data, expectedVer)
						if err != nil {
							s.sendError(w, err, http.StatusBadRequest, "CREATE_RULE_FAILED")
							return
						}
						writeJSON(w, http.StatusOK, res)
						return
					}
				}
			}
		}
	}

	// /api/rules/:id 及其子路由
	if strings.HasPrefix(urlPath, "/api/rules/") {
		rest := strings.TrimPrefix(urlPath, "/api/rules/")
		parts := strings.Split(rest, "/")
		idStr := parts[0]
		if !positiveIntRegex.MatchString(idStr) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "规则ID格式无效",
				"code":  "INVALID_INPUT",
			})
			return
		}
		ruleID, _ := strconv.Atoi(idStr)

		if len(parts) == 1 {
			switch method {
			case http.MethodPut:
				parsed, ok := s.parseJSONOrRespond(w, r)
				if !ok {
					return
				}
				expectedVer := extractExpectedVersion(r, parsed.Data)
				res, err := s.notifier.UpdateNotificationRuleFromPayload(ruleID, parsed.Data, expectedVer)
				if err != nil {
					s.sendError(w, err, http.StatusBadRequest, "UPDATE_RULE_FAILED")
					return
				}
				writeJSON(w, http.StatusOK, res)
				return
			case http.MethodDelete:
				parsed, ok := s.parseJSONOrRespond(w, r)
				if !ok {
					return
				}
				expectedVer := extractExpectedVersion(r, parsed.Data)
				res, err := s.notifier.DeleteNotificationRule(ruleID, expectedVer)
				if err != nil {
					s.sendError(w, err, http.StatusBadRequest, "DELETE_RULE_FAILED")
					return
				}
				writeJSON(w, http.StatusOK, res)
				return
			}
		} else if len(parts) == 2 {
			sub := parts[1]
			switch sub {
			case "regenerate":
				if method == http.MethodPost {
					parsed, ok := s.parseJSONOrRespond(w, r)
					if !ok {
						return
					}
					apiCode, _ := parsed.Data["api_code"].(string)
					if apiCode == "" {
						apiCode, _ = parsed.Data["apiCode"].(string)
					}
					expectedVer := extractExpectedVersion(r, parsed.Data)
					res, err := s.notifier.RegenerateRuleAPICode(ruleID, expectedVer, apiCode)
					if err != nil {
						s.sendError(w, err, http.StatusBadRequest, "REGENERATE_RULE_FAILED")
						return
					}
					writeJSON(w, http.StatusOK, res)
					return
				}
			case "enabled":
				if method == http.MethodPut {
					parsed, ok := s.parseJSONOrRespond(w, r)
					if !ok {
						return
					}
					enabledVal, isBool := parsed.Data["enabled"].(bool)
					if !isBool {
						writeJSON(w, http.StatusBadRequest, map[string]any{
							"error": "enabled 参数必须是布尔值",
							"code":  "INVALID_INPUT",
						})
						return
					}
					expectedVer := extractExpectedVersion(r, parsed.Data)
					res, err := s.notifier.SetNotificationRuleEnabled(ruleID, enabledVal, expectedVer)
					if err != nil {
						s.sendError(w, err, http.StatusBadRequest, "SET_RULE_ENABLED_FAILED")
						return
					}
					writeJSON(w, http.StatusOK, res)
					return
				}
			}
		}
	}

	writeJSON(w, http.StatusNotFound, map[string]any{
		"error": "未找到资源",
		"code":  "NOT_FOUND",
	})
}

func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request, code string) {
	clientIP := s.resolveClientIP(r)
	rateKey := "notify:" + clientIP
	rateCheck := s.notifyRateLimiter.Check(rateKey)
	if !rateCheck.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(rateCheck.RetryAfterSec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":      fmt.Sprintf("通知调用频率超限，请在 %d 秒后重试", rateCheck.RetryAfterSec),
			"code":       "RATE_LIMITED",
			"retryAfter": rateCheck.RetryAfterSec,
		})
		return
	}

	// BUG-04 修复：非 JSON Content-Type 拒绝时补齐稳定错误码 code: "INVALID_INPUT"
	if !bodyparser.IsJSONContentType(r.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "请求体必须是 JSON 格式（Content-Type: application/json）",
			"code":  "INVALID_INPUT",
		})
		return
	}

	parsed, ok := s.parseJSONOrRespond(w, r)
	if !ok {
		return
	}

	// BUG-03 修复：使用 ResolveNotifyAuthMeta 在鉴权前检测跨表命名空间冲突
	meta, err := s.notifier.ResolveNotifyAuthMeta(code)
	if err != nil {
		s.sendError(w, err, http.StatusInternalServerError, "NOTIFY_FAILED")
		return
	}
	if !meta.Found {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "无效的code，未找到配置",
			"code":  "APP_NOT_FOUND",
		})
		return
	}

	// 三层发送开关前置拦截（避免在通道关闭时消耗 nonce）
	if !meta.AppEnabled {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "该应用已暂停发送",
			"code":  "APP_DISABLED",
		})
		return
	}
	if meta.TargetType == "rule" && !meta.RuleEnabled {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "该规则已被禁用",
			"code":  "RULE_DISABLED",
		})
		return
	}
	if meta.TargetType == "app" && !meta.CodeSendEnabled {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "该应用已关闭 Code 直接发送，请使用规则 API",
			"code":  "DIRECT_SEND_DISABLED",
		})
		return
	}

	if strings.TrimSpace(meta.NotifyKeyHash) != "" {
		authRes := s.nonceStore.VerifyRequestAuth(notifyauth.RequestAuthParams{
			Code:            code,
			ExpectedKeyHash: meta.NotifyKeyHash,
			Headers:         r.Header,
			RawBody:         parsed.RawBody,
		})
		if !authRes.Allowed {
			status := authRes.Status
			if status <= 0 {
				status = http.StatusUnauthorized
			}
			writeJSON(w, status, map[string]any{
				"error": authRes.Error,
				"code":  "AUTH_REQUIRED",
			})
			return
		}
	}

	message, _ := parsed.Data["message"].(string)
	if message == "" {
		message, _ = parsed.Data["content"].(string)
	}
	title, _ := parsed.Data["title"].(string)
	toUser, _ := parsed.Data["toUser"].(string)
	if toUser == "" {
		toUser, _ = parsed.Data["touser"].(string)
	}
	msgType, _ := parsed.Data["msg_type"].(string)
	if msgType == "" {
		msgType, _ = parsed.Data["msgType"].(string)
	}
	if msgType == "" {
		msgType = "text"
	}
	// 与 Node 版 dispatchMessage 一致：text 为 "title\ncontent"，markdown 为 "**title**\n\ncontent"。
	if strings.TrimSpace(title) != "" && message != "" { // content 为空时保持为空，交由校验返回 400（同 Node）
		switch msgType {
		case "text":
			message = fmt.Sprintf("%s\n%s", title, message)
		case "markdown":
			message = fmt.Sprintf("**%s**\n\n%s", title, message)
		}
	}

	mediaID := parsed.Data["media_id"]
	if mediaID == nil {
		mediaID = parsed.Data["mediaId"]
	}
	description := parsed.Data["description"]
	if description == nil {
		description = parsed.Data["content"]
		if description == nil {
			description = parsed.Data["message"]
		}
	}

	extraData := map[string]any{
		"media_id":     mediaID,
		"image_base64": parsed.Data["image_base64"],
		"file_base64":  parsed.Data["file_base64"],
		"filename":     parsed.Data["filename"],
		"force":        parsed.Data["force"],
		"safe":         parsed.Data["safe"],
		"textcard":     parsed.Data["textcard"],
		"title":        parsed.Data["title"],
		"description":  description,
		"url":          parsed.Data["url"],
		"btntxt":       parsed.Data["btntxt"],
		"articles":     parsed.Data["articles"],
	}

	res, err := s.notifier.SendNotification(code, message, toUser, msgType, extraData)
	if err != nil {
		s.sendError(w, err, http.StatusInternalServerError, "")
		return
	}
	// 与 Node 版响应格式一致：{ message: '发送成功', response: <企业微信返回> }
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "发送成功",
		"response": res["response"],
	})
}

func (s *Server) handleCallbackVerify(w http.ResponseWriter, r *http.Request, code string) {
	clientIP := s.resolveClientIP(r)
	rateCheck := s.callbackRateLimiter.Check(fmt.Sprintf("%s:%s", clientIP, code))
	if !rateCheck.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(rateCheck.RetryAfterSec))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("请求过于频繁，请稍后再试"))
		return
	}

	q := r.URL.Query()
	msgSig := q.Get("msg_signature")
	timestamp := q.Get("timestamp")
	nonce := q.Get("nonce")
	echostr := q.Get("echostr")

	decrypted, err := s.notifier.VerifyCallbackURL(code, msgSig, timestamp, nonce, echostr)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("验证失败"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(decrypted))
}

func (s *Server) handleCallbackMessage(w http.ResponseWriter, r *http.Request, code string) {
	clientIP := s.resolveClientIP(r)
	rateCheck := s.callbackRateLimiter.Check(fmt.Sprintf("%s:%s", clientIP, code))
	if !rateCheck.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(rateCheck.RetryAfterSec))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("请求过于频繁，请稍后再试"))
		return
	}

	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if semi := strings.IndexByte(ct, ';'); semi >= 0 {
		ct = strings.TrimSpace(ct[:semi])
	}
	if ct != "" && ct != "text/xml" && ct != "application/xml" && ct != "text/plain" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_, _ = w.Write([]byte("不支持的回调 Content-Type"))
		return
	}

	maxBytes := int64(s.cfg.CallbackMaxBodyBytes)
	if maxBytes <= 0 {
		maxBytes = 100 * 1024
	}
	defer r.Body.Close()
	rawBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("读取回调请求体失败"))
		return
	}
	if int64(len(rawBytes)) > maxBytes {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte("回调请求体过大"))
		return
	}
	xmlBody := string(rawBytes)
	if strings.TrimSpace(xmlBody) == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("回调请求体不能为空"))
		return
	}

	q := r.URL.Query()
	msgSig := q.Get("msg_signature")
	timestamp := q.Get("timestamp")
	nonce := q.Get("nonce")

	reply, err := s.notifier.HandleCallbackMessage(code, msgSig, timestamp, nonce, xmlBody)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("处理失败"))
		return
	}
	if reply != "" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(reply))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}
