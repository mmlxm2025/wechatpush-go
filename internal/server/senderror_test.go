package server

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/service"
)

// 与 Node 版 sendError 对齐：不补 *_FAILED；5xx 补 INTERNAL_ERROR；production 隐藏 5xx 消息。
func TestSendErrorContract(t *testing.T) {
	run := func(env string, err error, fb int) (int, map[string]any) {
		cfg := config.FromEnv()
		cfg.NodeEnv = env
		s := &Server{cfg: cfg}
		rec := httptest.NewRecorder()
		s.sendError(rec, err, fb, "SHOULD_NOT_APPEAR")
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	st, b := run("development", service.NewError("bad", 400, ""), 400)
	if st != 400 || b["code"] != nil || b["error"] != "bad" {
		t.Fatalf("4xx without code: %d %v", st, b)
	}
	st, b = run("development", errors.New("db boom"), 500)
	if st != 500 || b["code"] != "INTERNAL_ERROR" || b["error"] != "db boom" {
		t.Fatalf("dev 5xx: %d %v", st, b)
	}
	st, b = run("production", errors.New("db boom"), 500)
	if st != 500 || b["error"] != "服务器内部错误" {
		t.Fatalf("prod 5xx must be masked: %d %v", st, b)
	}
	st, b = run("production", service.NewError("conflict", 409, "APP_VERSION_CONFLICT"), 400)
	if st != 409 || b["code"] != "APP_VERSION_CONFLICT" || b["error"] != "conflict" {
		t.Fatalf("biz error: %d %v", st, b)
	}
}
