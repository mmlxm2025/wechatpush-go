package notifyauth

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	hex64Regex  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	digitsRegex = regexp.MustCompile(`^\d{1,16}$`)
)

func GenerateNotifyKey() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "nk_" + hex.EncodeToString(b)
}

func HashNotifyKey(plainKey string) string {
	normalized := strings.TrimSpace(plainKey)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func VerifyNotifyKey(candidateKey, expectedHashHex string) bool {
	if candidateKey == "" || expectedHashHex == "" {
		return false
	}
	if !hex64Regex.MatchString(expectedHashHex) {
		return false
	}
	candidateHashHex := HashNotifyKey(candidateKey)
	if len(candidateHashHex) != 64 {
		return false
	}
	bufA, err1 := hex.DecodeString(candidateHashHex)
	bufB, err2 := hex.DecodeString(expectedHashHex)
	if err1 != nil || err2 != nil || len(bufA) != 32 || len(bufB) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(bufA, bufB) == 1
}

func ComputeNotifySignature(signingKeyHex, timestamp, nonce string, rawBody []byte) string {
	key := strings.ToLower(strings.TrimSpace(signingKeyHex))
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(timestamp + "." + nonce + "."))
	if len(rawBody) > 0 {
		mac.Write(rawBody)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyNotifySignature(signingKeyHex, timestamp, nonce string, rawBody []byte, signatureHex string) bool {
	if signingKeyHex == "" || timestamp == "" || nonce == "" || signatureHex == "" {
		return false
	}
	sigClean := strings.TrimSpace(signatureHex)
	if !hex64Regex.MatchString(sigClean) {
		return false
	}
	expectedHex := ComputeNotifySignature(signingKeyHex, timestamp, nonce, rawBody)
	bufA, err1 := hex.DecodeString(expectedHex)
	bufB, err2 := hex.DecodeString(sigClean)
	if err1 != nil || err2 != nil || len(bufA) != 32 || len(bufB) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(bufA, bufB) == 1
}

type nonceEntry struct {
	nonce     string
	expiresAt int64
}

type noncePartition struct {
	order *list.List
	items map[string]*list.Element
}

type NonceStore struct {
	mu                    sync.Mutex
	timestampToleranceSec int64
	nonceTTLMs            int64
	hardLimit             int
	partitions            map[string]*noncePartition
	nowFunc               func() int64
}

func NewNonceStore(timestampToleranceSec int, nonceTTLMs int, hardLimit int) *NonceStore {
	if timestampToleranceSec <= 0 {
		timestampToleranceSec = 300
	}
	if nonceTTLMs <= 0 {
		nonceTTLMs = 10 * 60 * 1000
	}
	if hardLimit <= 0 {
		hardLimit = 10000
	}
	return &NonceStore{
		timestampToleranceSec: int64(timestampToleranceSec),
		nonceTTLMs:            int64(nonceTTLMs),
		hardLimit:             hardLimit,
		partitions:            make(map[string]*noncePartition),
		nowFunc:               func() int64 { return time.Now().UnixMilli() },
	}
}

func (ns *NonceStore) SetNowFunc(fn func() int64) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.nowFunc = fn
}

func (ns *NonceStore) IsAndMarkNonce(code, nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := ns.nowFunc()
	partitionKey := code
	if partitionKey == "" {
		partitionKey = "_default"
	}
	p, exists := ns.partitions[partitionKey]
	if !exists {
		p = &noncePartition{
			order: list.New(),
			items: make(map[string]*list.Element),
		}
		ns.partitions[partitionKey] = p
	}

	// 惰性清理过期项（从最旧的队首开始清理，并扫描剩余过期项）
	for elem := p.order.Front(); elem != nil; {
		next := elem.Next()
		entry := elem.Value.(*nonceEntry)
		if entry.expiresAt <= now {
			p.order.Remove(elem)
			delete(p.items, entry.nonce)
		}
		elem = next
	}

	if elem, dup := p.items[nonce]; dup {
		entry := elem.Value.(*nonceEntry)
		if entry.expiresAt > now {
			return true
		}
		p.order.Remove(elem)
		delete(p.items, nonce)
	}

	for p.order.Len() >= ns.hardLimit && ns.hardLimit > 0 {
		oldest := p.order.Front()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*nonceEntry)
		p.order.Remove(oldest)
		delete(p.items, entry.nonce)
	}

	elem := p.order.PushBack(&nonceEntry{
		nonce:     nonce,
		expiresAt: now + ns.nonceTTLMs,
	})
	p.items[nonce] = elem
	return false
}

func (ns *NonceStore) Cleanup() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := ns.nowFunc()
	for key, p := range ns.partitions {
		for elem := p.order.Front(); elem != nil; {
			next := elem.Next()
			entry := elem.Value.(*nonceEntry)
			if entry.expiresAt <= now {
				p.order.Remove(elem)
				delete(p.items, entry.nonce)
			}
			elem = next
		}
		if p.order.Len() == 0 {
			delete(ns.partitions, key)
		}
	}
}

func (ns *NonceStore) Reset() {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.partitions = make(map[string]*noncePartition)
}

func (ns *NonceStore) GetPartitionSize(code string) int {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	partitionKey := code
	if partitionKey == "" {
		partitionKey = "_default"
	}
	p, exists := ns.partitions[partitionKey]
	if !exists {
		return 0
	}
	return p.order.Len()
}

type RequestAuthParams struct {
	Code            string
	ExpectedKeyHash string
	Headers         http.Header
	RawBody         []byte
}

type RequestAuthResult struct {
	Allowed bool
	Mode    string
	Status  int
	Error   string
}

func (ns *NonceStore) VerifyRequestAuth(params RequestAuthParams) RequestAuthResult {
	if params.ExpectedKeyHash == "" {
		return RequestAuthResult{Allowed: true, Mode: "disabled"}
	}

	var candidateKey, signature, timestamp, nonce string
	if params.Headers != nil {
		candidateKey = strings.TrimSpace(params.Headers.Get("X-Notify-Key"))
		signature = strings.TrimSpace(params.Headers.Get("X-Notify-Signature"))
		timestamp = strings.TrimSpace(params.Headers.Get("X-Notify-Timestamp"))
		nonce = strings.TrimSpace(params.Headers.Get("X-Notify-Nonce"))
	}

	// 模式 1：直接传递 X-Notify-Key
	if candidateKey != "" {
		if VerifyNotifyKey(candidateKey, params.ExpectedKeyHash) {
			return RequestAuthResult{Allowed: true, Mode: "api_key"}
		}
		return RequestAuthResult{
			Allowed: false,
			Status:  http.StatusUnauthorized,
			Error:   "X-Notify-Key 无效",
		}
	}

	// 模式 2：HMAC-SHA256 签名挑战
	if signature != "" || timestamp != "" || nonce != "" {
		if signature == "" || timestamp == "" || nonce == "" {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "HMAC 签名鉴权缺少必要请求头（需同时提供 X-Notify-Timestamp、X-Notify-Nonce、X-Notify-Signature）",
			}
		}

		if !digitsRegex.MatchString(timestamp) {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "X-Notify-Timestamp 格式无效",
			}
		}
		tsNum, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "X-Notify-Timestamp 格式无效",
			}
		}
		tsMs := tsNum
		if tsNum < 1e12 {
			tsMs = tsNum * 1000
		}

		ns.mu.Lock()
		now := ns.nowFunc()
		tolMs := ns.timestampToleranceSec * 1000
		ns.mu.Unlock()

		if int64(math.Abs(float64(now-tsMs))) > tolMs {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "X-Notify-Timestamp 已过期或超出允许的时间窗口",
			}
		}

		if len(nonce) < 8 || len(nonce) > 128 {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "X-Notify-Nonce 长度必须在 8 到 128 字符之间",
			}
		}

		if !VerifyNotifySignature(params.ExpectedKeyHash, timestamp, nonce, params.RawBody, signature) {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "X-Notify-Signature 签名校验失败",
			}
		}

		if ns.IsAndMarkNonce(params.Code, nonce) {
			return RequestAuthResult{
				Allowed: false,
				Status:  http.StatusUnauthorized,
				Error:   "检测到重放请求（X-Notify-Nonce 已使用）",
			}
		}

		return RequestAuthResult{Allowed: true, Mode: "hmac"}
	}

	return RequestAuthResult{
		Allowed: false,
		Status:  http.StatusUnauthorized,
		Error:   "此通知通道已启用鉴权，请提供 X-Notify-Key 请求头或 HMAC 签名头（X-Notify-Timestamp / X-Notify-Nonce / X-Notify-Signature）",
	}
}
