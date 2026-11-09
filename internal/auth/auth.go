package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SessionDurationMs  = 24 * 60 * 60 * 1000
	SessionCookieName  = "session"
	LegacyCookieName   = "qywx_session"
	DefaultMaxSessions = 1000
)

type SessionMeta struct {
	IP        string
	UserAgent string
}

type SessionRecord struct {
	ID         string
	Token      string
	Username   string
	IP         string
	UserAgent  string
	CreatedAt  int64
	LastSeenAt int64
	ExpiresAt  int64
}

type SessionPublicView struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	IP         string `json:"ip"`
	UserAgent  string `json:"userAgent"`
	CreatedAt  int64  `json:"createdAt"`
	LastSeenAt int64  `json:"lastSeenAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	Current    bool   `json:"current"`
}

type ValidationResult struct {
	Valid     bool
	Username  string
	SessionID string
}

type Service struct {
	mu            sync.Mutex
	adminUsername string
	adminPassword string
	maxSessions   int
	sessions      map[string]*SessionRecord
	nowFunc       func() int64
}

func NewService(adminUsername, adminPassword string) *Service {
	if adminUsername == "" {
		adminUsername = "admin"
	}
	return &Service{
		adminUsername: adminUsername,
		adminPassword: adminPassword,
		maxSessions:   DefaultMaxSessions,
		sessions:      make(map[string]*SessionRecord),
		nowFunc:       func() int64 { return time.Now().UnixMilli() },
	}
}

func (s *Service) SetNowFunc(fn func() int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nowFunc = fn
}

func (s *Service) SetMaxSessions(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if max > 0 {
		s.maxSessions = max
	}
}

func SafeEquals(a, b string) bool {
	hashA := sha256.Sum256([]byte(a))
	hashB := sha256.Sum256([]byte(b))
	match := subtle.ConstantTimeCompare(hashA[:], hashB[:]) == 1
	return match && len(a) == len(b)
}

func (s *Service) ValidateCredentials(username, password string) bool {
	if username == "" || password == "" || s.adminPassword == "" {
		return false
	}
	userMatch := SafeEquals(username, s.adminUsername)
	passMatch := SafeEquals(password, s.adminPassword)
	return userMatch && passMatch
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) pruneExpiredLocked(now int64) {
	for token, sess := range s.sessions {
		if now > sess.ExpiresAt {
			delete(s.sessions, token)
		}
	}
}

func (s *Service) CreateSession(username string, meta SessionMeta) (token string, sessionID string, expiresAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	// BUG-06 修复：创建新会话前清理过期会话，并在达到上限时淘汰最早创建的会话
	s.pruneExpiredLocked(now)
	for len(s.sessions) >= s.maxSessions && s.maxSessions > 0 {
		var oldestToken string
		var oldestCreated int64
		first := true
		for t, sess := range s.sessions {
			if first || sess.CreatedAt < oldestCreated {
				oldestToken = t
				oldestCreated = sess.CreatedAt
				first = false
			}
		}
		if oldestToken == "" {
			break
		}
		delete(s.sessions, oldestToken)
	}

	token = randomHex(32)
	sessionID = randomHex(16)
	expiresAt = now + SessionDurationMs

	ip := meta.IP
	if ip == "" {
		ip = "unknown"
	}
	ua := meta.UserAgent
	if len(ua) > 256 {
		ua = ua[:256]
	}

	s.sessions[token] = &SessionRecord{
		ID:         sessionID,
		Token:      token,
		Username:   username,
		IP:         ip,
		UserAgent:  ua,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expiresAt,
	}
	return token, sessionID, expiresAt
}

func (s *Service) ValidateSession(token string) ValidationResult {
	if token == "" {
		return ValidationResult{Valid: false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.sessions[token]
	if !exists {
		return ValidationResult{Valid: false}
	}
	now := s.nowFunc()
	if now > sess.ExpiresAt {
		delete(s.sessions, token)
		return ValidationResult{Valid: false}
	}
	sess.LastSeenAt = now
	return ValidationResult{
		Valid:     true,
		Username:  sess.Username,
		SessionID: sess.ID,
	}
}

func (s *Service) DestroySession(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[token]; !exists {
		return false
	}
	delete(s.sessions, token)
	return true
}

func (s *Service) DestroySessionByID(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.ID == sessionID {
			delete(s.sessions, token)
			return true
		}
	}
	return false
}

func (s *Service) DestroyOtherSessions(currentToken string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for token := range s.sessions {
		if token != currentToken {
			delete(s.sessions, token)
			removed++
		}
	}
	return removed
}

func (s *Service) DestroyAllSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.sessions)
	s.sessions = make(map[string]*SessionRecord)
	return count
}

func (s *Service) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(s.nowFunc())
}

func (s *Service) ListActiveSessions(currentToken string) []SessionPublicView {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	s.pruneExpiredLocked(now)

	list := make([]SessionPublicView, 0, len(s.sessions))
	for token, sess := range s.sessions {
		list = append(list, SessionPublicView{
			ID:         sess.ID,
			Username:   sess.Username,
			IP:         sess.IP,
			UserAgent:  sess.UserAgent,
			CreatedAt:  sess.CreatedAt,
			LastSeenAt: sess.LastSeenAt,
			ExpiresAt:  sess.ExpiresAt,
			Current:    token == currentToken,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt > list[j].CreatedAt
	})
	return list
}

func ParseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)
	if cookieHeader == "" {
		return cookies
	}
	pairs := strings.Split(cookieHeader, ";")
	for _, pair := range pairs {
		idx := strings.IndexByte(pair, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(pair[:idx])
		rawVal := strings.TrimSpace(pair[idx+1:])
		if key == "" {
			continue
		}
		decoded, err := url.QueryUnescape(rawVal)
		if err != nil {
			cookies[key] = rawVal
		} else {
			cookies[key] = decoded
		}
	}
	return cookies
}

func ExtractTokenFromRequest(r *http.Request) (token string, source string) {
	if r == nil {
		return "", ""
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		t := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if t != "" {
			return t, "header"
		}
	}
	cookies := ParseCookies(r.Header.Get("Cookie"))
	if cToken := cookies[SessionCookieName]; cToken != "" {
		return cToken, "cookie"
	}
	if cToken := cookies[LegacyCookieName]; cToken != "" {
		return cToken, "cookie"
	}
	return "", ""
}

func BuildSessionCookie(token string, secure bool) string {
	maxAge := SessionDurationMs / 1000
	parts := []string{
		fmt.Sprintf("%s=%s", SessionCookieName, url.QueryEscape(token)),
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		fmt.Sprintf("Max-Age=%d", maxAge),
	}
	if secure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}

func BuildClearSessionCookie(secure bool) string {
	parts := []string{
		fmt.Sprintf("%s=", SessionCookieName),
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		"Max-Age=0",
	}
	if secure {
		parts = append(parts, "Secure")
	}
	return strings.Join(parts, "; ")
}
