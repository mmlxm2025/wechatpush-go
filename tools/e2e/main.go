package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mode      atomic.Value // ok|cred|rate|down|slow|deptfail
	sendMu    sync.Mutex
	sends     []map[string]any
	uploads   int32
	results   []string
	passN     int
	failN     int
	base      string
	cookie    string
	appCmd    *exec.Cmd
	exePath   string
	envVars   []string
	logFile   *os.File
)

func check(name string, ok bool, detail ...any) {
	if ok {
		passN++
		results = append(results, "PASS | "+name)
	} else {
		failN++
		results = append(results, "FAIL | "+name+" | "+fmt.Sprint(detail...))
	}
}

func mockWeCom() *httptest.Server {
	mode.Store("ok")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := mode.Load().(string)
		if m == "down" {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		if m == "slow" {
			time.Sleep(15 * time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			if m == "cred" {
				enc.Encode(map[string]any{"errcode": 40001, "errmsg": "invalid credential"})
				return
			}
			enc.Encode(map[string]any{"errcode": 0, "access_token": "mocktok", "expires_in": 7200})
		case "/cgi-bin/agent/get":
			enc.Encode(map[string]any{"errcode": 0, "name": "E2E应用", "allow_userinfos": map[string]any{"user": []any{map[string]any{"userid": "u1"}, map[string]any{"userid": "u2"}}}, "allow_partys": map[string]any{"partyid": []any{2}}})
		case "/cgi-bin/user/simplelist":
			if m == "deptfail" {
				enc.Encode(map[string]any{"errcode": 60011, "errmsg": "no privilege"})
				return
			}
			enc.Encode(map[string]any{"errcode": 0, "userlist": []any{map[string]any{"userid": "u3", "name": "张三", "department": []any{2}}}})
		case "/cgi-bin/tag/get":
			enc.Encode(map[string]any{"errcode": 0, "userlist": []any{}})
		case "/cgi-bin/media/upload":
			atomic.AddInt32(&uploads, 1)
			enc.Encode(map[string]any{"errcode": 0, "type": "image", "media_id": "MEDIA123", "created_at": "1"})
		case "/cgi-bin/message/send":
			if m == "rate" {
				enc.Encode(map[string]any{"errcode": 45009, "errmsg": "api freq out of limit"})
				return
			}
			var p map[string]any
			json.NewDecoder(r.Body).Decode(&p)
			sendMu.Lock()
			sends = append(sends, p)
			sendMu.Unlock()
			enc.Encode(map[string]any{"errcode": 0, "errmsg": "ok", "msgid": fmt.Sprintf("msg%d", len(sends))})
		default:
			w.WriteHeader(404)
		}
	}))
}

func lastSend() map[string]any {
	sendMu.Lock()
	defer sendMu.Unlock()
	if len(sends) == 0 {
		return nil
	}
	return sends[len(sends)-1]
}
func sendCount() int { sendMu.Lock(); defer sendMu.Unlock(); return len(sends) }

type resp struct {
	Status int
	Body   map[string]any
	Raw    string
	Hdr    http.Header
}

var client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(method, path string, body any, hdr map[string]string) resp {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
		ct = "application/json"
	case []byte:
		rd = bytes.NewReader(b)
		ct = "application/json"
	default:
		bs, _ := json.Marshal(b)
		rd = bytes.NewReader(bs)
		ct = "application/json"
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return resp{Status: -1, Raw: err.Error()}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return resp{res.StatusCode, m, string(raw), res.Header}
}

func freePort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startApp(dir string) {
	appCmd = exec.Command(exePath)
	appCmd.Dir = dir
	appCmd.Env = append(os.Environ(), envVars...)
	appCmd.Stdout = logFile
	appCmd.Stderr = logFile
	if err := appCmd.Start(); err != nil {
		panic(err)
	}
	for i := 0; i < 100; i++ {
		r := do("GET", "/health/live", nil, nil)
		if r.Status == 200 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	panic("app did not start")
}

func stopApp() {
	if appCmd != nil && appCmd.Process != nil {
		appCmd.Process.Kill()
		appCmd.Wait()
	}
}

func rnd(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

func s(v any) string { return fmt.Sprint(v) }
func num(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	}
	return 0
}

func main() {
	exePath = os.Args[1]
	dir, _ := os.MkdirTemp("", "qe2e-run")
	defer os.RemoveAll(dir)
	logFile, _ = os.Create(filepath.Join(os.Args[2], "app.log"))
	mock := mockWeCom()
	defer mock.Close()
	port := freePort()
	base = fmt.Sprintf("http://127.0.0.1:%d", port)
	adminPass := "E2e!" + rnd(8)
	envVars = []string{
		"PORT=" + fmt.Sprint(port), "DB_PATH=" + filepath.Join(dir, "e2e.db"), "ENCRYPTION_KEY=" + rnd(32),
		"ADMIN_USERNAME=e2eadmin", "ADMIN_PASSWORD=" + adminPass, "NODE_ENV=development",
		"WECHAT_API_BASE=" + mock.URL, "WECHAT_HTTP_TIMEOUT_MS=3000", "TEST_INSTANCE_ID=e2e-instance-0123456789",
		"LOGIN_RATE_MAX=5", "NOTIFY_RATE_MAX=100000", "SEND_DEDUP_TTL_MS=30000", "WECHAT_RATE_BACKOFF_MS=1500",
	}
	startApp(dir)
	defer stopApp()
	run(adminPass, dir)
	out := strings.Join(results, "\n")
	fmt.Println(out)
	fmt.Printf("\nTOTAL pass=%d fail=%d\n", passN, failN)
}