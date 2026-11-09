package ratelimit

import (
	"math"
	"sync"
	"time"
)

type CheckResult struct {
	Allowed       bool
	Remaining     int
	RetryAfterMs  int64
	RetryAfterSec int
}

type RateLimiter struct {
	mu       sync.Mutex
	windowMs int64
	max      int
	buckets  map[string][]int64
	nowFunc  func() int64
}

func NewRateLimiter(windowMs int, max int) *RateLimiter {
	if windowMs <= 0 {
		windowMs = 60 * 1000
	}
	if max <= 0 {
		max = 60
	}
	return &RateLimiter{
		windowMs: int64(windowMs),
		max:      max,
		buckets:  make(map[string][]int64),
		nowFunc:  func() int64 { return time.Now().UnixMilli() },
	}
}

func (r *RateLimiter) SetNowFunc(fn func() int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nowFunc = fn
}

func (r *RateLimiter) Check(key string) CheckResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFunc()
	cutoff := now - r.windowMs
	entries := r.buckets[key]
	pruned := entries[:0]
	for _, t := range entries {
		if t > cutoff {
			pruned = append(pruned, t)
		}
	}

	if len(pruned) >= r.max {
		retryAfterMs := pruned[0] + r.windowMs - now
		if retryAfterMs < 1000 {
			retryAfterMs = 1000
		}
		retryAfterSec := int(math.Ceil(float64(retryAfterMs) / 1000.0))
		r.buckets[key] = pruned
		return CheckResult{
			Allowed:       false,
			Remaining:     0,
			RetryAfterMs:  retryAfterMs,
			RetryAfterSec: retryAfterSec,
		}
	}

	pruned = append(pruned, now)
	r.buckets[key] = pruned
	rem := r.max - len(pruned)
	if rem < 0 {
		rem = 0
	}
	return CheckResult{
		Allowed:       true,
		Remaining:     rem,
		RetryAfterMs:  0,
		RetryAfterSec: 0,
	}
}

func (r *RateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFunc()
	cutoff := now - r.windowMs
	for key, entries := range r.buckets {
		pruned := entries[:0]
		for _, t := range entries {
			if t > cutoff {
				pruned = append(pruned, t)
			}
		}
		if len(pruned) == 0 {
			delete(r.buckets, key)
		} else {
			r.buckets[key] = pruned
		}
	}
}

func (r *RateLimiter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buckets = make(map[string][]int64)
}

// LoginRateLimiter 登录失败频率限制器（仅统计失败尝试，成功登录后清理计数）
type LoginRateLimiter struct {
	mu       sync.Mutex
	windowMs int64
	max      int
	failures map[string][]int64
	nowFunc  func() int64
}

func NewLoginRateLimiter(windowMs int, max int) *LoginRateLimiter {
	if windowMs <= 0 {
		windowMs = 5 * 60 * 1000
	}
	if max <= 0 {
		max = 10
	}
	return &LoginRateLimiter{
		windowMs: int64(windowMs),
		max:      max,
		failures: make(map[string][]int64),
		nowFunc:  func() int64 { return time.Now().UnixMilli() },
	}
}

func (l *LoginRateLimiter) SetNowFunc(fn func() int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFunc = fn
}

func (l *LoginRateLimiter) Check(key string) CheckResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	cutoff := now - l.windowMs
	entries, exists := l.failures[key]
	if !exists {
		return CheckResult{
			Allowed:       true,
			Remaining:     l.max,
			RetryAfterMs:  0,
			RetryAfterSec: 0,
		}
	}

	pruned := make([]int64, 0, len(entries))
	for _, t := range entries {
		if t > cutoff {
			pruned = append(pruned, t)
		}
	}

	// BUG-05 修复：始终将过滤后的切片写回 map（或为空时删除），防止过期记录残留
	if len(pruned) == 0 {
		delete(l.failures, key)
		return CheckResult{
			Allowed:       true,
			Remaining:     l.max,
			RetryAfterMs:  0,
			RetryAfterSec: 0,
		}
	}
	l.failures[key] = pruned

	if len(pruned) >= l.max {
		retryAfterMs := pruned[0] + l.windowMs - now
		if retryAfterMs < 1000 {
			retryAfterMs = 1000
		}
		retryAfterSec := int(math.Ceil(float64(retryAfterMs) / 1000.0))
		return CheckResult{
			Allowed:       false,
			Remaining:     0,
			RetryAfterMs:  retryAfterMs,
			RetryAfterSec: retryAfterSec,
		}
	}

	rem := l.max - len(pruned)
	if rem < 0 {
		rem = 0
	}
	return CheckResult{
		Allowed:       true,
		Remaining:     rem,
		RetryAfterMs:  0,
		RetryAfterSec: 0,
	}
}

func (l *LoginRateLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	cutoff := now - l.windowMs
	entries := l.failures[key]
	// BUG-05 修复：记录新失败前先剔除滑窗外过期记录
	pruned := make([]int64, 0, len(entries)+1)
	for _, t := range entries {
		if t > cutoff {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	l.failures[key] = pruned
}

func (l *LoginRateLimiter) ClearKey(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *LoginRateLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	cutoff := now - l.windowMs
	for key, entries := range l.failures {
		pruned := make([]int64, 0, len(entries))
		for _, t := range entries {
			if t > cutoff {
				pruned = append(pruned, t)
			}
		}
		if len(pruned) == 0 {
			delete(l.failures, key)
		} else {
			l.failures[key] = pruned
		}
	}
}

func (l *LoginRateLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = make(map[string][]int64)
}
