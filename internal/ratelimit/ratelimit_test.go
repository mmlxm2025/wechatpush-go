package ratelimit

import "testing"

func TestRateLimiterAndLoginRateLimiter(t *testing.T) {
	now := int64(100000)
	rl := NewRateLimiter(10000, 3)
	rl.SetNowFunc(func() int64 { return now })

	for i := 0; i < 3; i++ {
		res := rl.Check("ip1")
		if !res.Allowed {
			t.Fatalf("expected allowed on call %d", i+1)
		}
	}
	res := rl.Check("ip1")
	if res.Allowed || res.RetryAfterSec <= 0 {
		t.Fatalf("expected blocked on call 4, got %+v", res)
	}

	// Advance time past window
	now += 10001
	res = rl.Check("ip1")
	if !res.Allowed {
		t.Fatal("expected allowed after window expires")
	}

	// Test LoginRateLimiter BUG-05 fix: expired entries pruned during RecordFailure & Check
	lrl := NewLoginRateLimiter(10000, 3)
	lrl.SetNowFunc(func() int64 { return now })

	lrl.RecordFailure("user1")
	lrl.RecordFailure("user1")
	now += 10001 // Previous 2 failures are now expired
	lrl.RecordFailure("user1")
	lrl.RecordFailure("user1")

	// Should still be allowed because only 2 failures are within the active window
	chk := lrl.Check("user1")
	if !chk.Allowed || chk.Remaining != 1 {
		t.Fatalf("BUG-05 regression: expected Allowed=true Remaining=1, got %+v", chk)
	}
}
