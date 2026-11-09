package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestAuthServiceSessionsAndCookies(t *testing.T) {
	now := int64(1000000)
	svc := NewService("admin", "StrongPass!2026")
	svc.SetNowFunc(func() int64 { return now })
	svc.SetMaxSessions(3)

	if !svc.ValidateCredentials("admin", "StrongPass!2026") {
		t.Fatal("expected valid credentials")
	}
	if svc.ValidateCredentials("admin", "wrong") || svc.ValidateCredentials("other", "StrongPass!2026") {
		t.Fatal("expected invalid credentials to fail")
	}

	// Create 3 sessions
	t1, id1, _ := svc.CreateSession("admin", SessionMeta{IP: "1.1.1.1", UserAgent: "UA1"})
	now += 10
	t2, _, _ := svc.CreateSession("admin", SessionMeta{IP: "1.1.1.2", UserAgent: "UA2"})
	now += 10
	t3, _, _ := svc.CreateSession("admin", SessionMeta{IP: "1.1.1.3", UserAgent: "UA3"})

	// Creating 4th session should evict oldest (t1) due to MaxSessions=3 (BUG-06 fix)
	now += 10
	t4, _, _ := svc.CreateSession("admin", SessionMeta{IP: "1.1.1.4", UserAgent: "UA4"})

	if svc.ValidateSession(t1).Valid {
		t.Fatal("expected oldest session t1 to be evicted when maxSessions=3 exceeded")
	}
	if !svc.ValidateSession(t2).Valid || !svc.ValidateSession(t3).Valid || !svc.ValidateSession(t4).Valid {
		t.Fatal("expected newer sessions t2, t3, t4 to remain valid")
	}
	_ = id1

	// Cookie building and parsing
	cookieStr := BuildSessionCookie(t4, true)
	if !strings.Contains(cookieStr, "HttpOnly") || !strings.Contains(cookieStr, "Secure") {
		t.Fatalf("unexpected cookie string: %s", cookieStr)
	}

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", "foo=bar; "+SessionCookieName+"="+t4)
	extToken, source := ExtractTokenFromRequest(req)
	if extToken != t4 || source != "cookie" {
		t.Fatalf("expected token from cookie, got %q %q", extToken, source)
	}

	// Expiration cleanup
	now += SessionDurationMs + 1
	svc.CleanupExpiredSessions()
	if len(svc.ListActiveSessions("")) != 0 {
		t.Fatal("expected all expired sessions to be cleaned up")
	}
}
