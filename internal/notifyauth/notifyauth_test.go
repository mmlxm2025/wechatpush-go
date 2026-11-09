package notifyauth

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestNotifyAuthAndPartitionedNonce(t *testing.T) {
	key := GenerateNotifyKey()
	if !strings.HasPrefix(key, "nk_") || len(key) != 51 {
		t.Fatalf("unexpected notify key: %q", key)
	}
	hash := HashNotifyKey(key)
	if !VerifyNotifyKey(key, hash) || VerifyNotifyKey("nk_wrong", hash) {
		t.Fatal("VerifyNotifyKey failed")
	}

	now := int64(1700000000000)
	ns := NewNonceStore(300, 600000, 3)
	ns.SetNowFunc(func() int64 { return now })

	rawBody := []byte(`{"message":"hello"}`)
	ts := strconv.FormatInt(now/1000, 10)
	nonce := "nonce-12345678"
	sig := ComputeNotifySignature(hash, ts, nonce, rawBody)

	hdr := make(http.Header)
	hdr.Set("X-Notify-Timestamp", ts)
	hdr.Set("X-Notify-Nonce", nonce)
	hdr.Set("X-Notify-Signature", sig)

	res := ns.VerifyRequestAuth(RequestAuthParams{
		Code:            "app-1",
		ExpectedKeyHash: hash,
		Headers:         hdr,
		RawBody:         rawBody,
	})
	if !res.Allowed || res.Mode != "hmac" {
		t.Fatalf("expected hmac auth allowed, got %+v", res)
	}

	// Replay with same nonce must fail
	resReplay := ns.VerifyRequestAuth(RequestAuthParams{
		Code:            "app-1",
		ExpectedKeyHash: hash,
		Headers:         hdr,
		RawBody:         rawBody,
	})
	if resReplay.Allowed || !strings.Contains(resReplay.Error, "重放") {
		t.Fatalf("expected replay rejection, got %+v", resReplay)
	}

	// Partition isolation: another code should not affect app-1
	ns.IsAndMarkNonce("app-2", "n1-123456")
	ns.IsAndMarkNonce("app-2", "n2-123456")
	ns.IsAndMarkNonce("app-2", "n3-123456")
	ns.IsAndMarkNonce("app-2", "n4-123456")
	if ns.GetPartitionSize("app-2") != 3 {
		t.Fatalf("expected app-2 partition capped at 3, got %d", ns.GetPartitionSize("app-2"))
	}
	if ns.GetPartitionSize("app-1") != 1 {
		t.Fatalf("expected app-1 partition size 1, got %d", ns.GetPartitionSize("app-1"))
	}
}
