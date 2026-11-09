package config

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeEncryptionKey(t *testing.T) {
	// 1. Empty key
	if _, err := DecodeEncryptionKey(""); err == nil {
		t.Fatal("expected error for empty key")
	}

	// 2. Placeholder keys
	for p := range PlaceholderValues {
		if _, err := DecodeEncryptionKey(p); err == nil {
			t.Fatalf("expected error for placeholder key %q", p)
		}
	}

	// 3. Valid 32-byte raw string
	raw32 := "0123456789abcdef0123456789abcdef"
	buf, err := DecodeEncryptionKey(raw32)
	if err != nil || len(buf) != 32 {
		t.Fatalf("expected 32 bytes for raw string, got err=%v len=%d", err, len(buf))
	}

	// 4. Valid 64-char hex
	hex64 := hex.EncodeToString([]byte(raw32))
	buf, err = DecodeEncryptionKey(hex64)
	if err != nil || string(buf) != raw32 {
		t.Fatalf("expected decoded hex to match raw32, got err=%v", err)
	}

	// 5. Valid 44-char base64
	b64 := base64.StdEncoding.EncodeToString([]byte(raw32))
	buf, err = DecodeEncryptionKey(b64)
	if err != nil || string(buf) != raw32 {
		t.Fatalf("expected decoded base64 to match raw32, got err=%v", err)
	}

	// 6. Invalid length
	if _, err := DecodeEncryptionKey("short-key"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestValidateRuntime(t *testing.T) {
	validKey := "0123456789abcdef0123456789abcdef"

	// Missing password and placeholder key
	errs, _ := ValidateRuntime(&Config{
		EncryptionKey: "default-key-for-development-only",
		AdminUsername: "admin",
		AdminPassword: "",
		WechatAPIBase: "https://qyapi.weixin.qq.com",
		NodeEnv:       "production",
	})
	if len(errs) < 2 {
		t.Fatalf("expected at least 2 errors, got %v", errs)
	}

	// Short password & short TEST_INSTANCE_ID
	errs, _ = ValidateRuntime(&Config{
		EncryptionKey:  validKey,
		AdminUsername:  "admin",
		AdminPassword:  "1234567",
		WechatAPIBase:  "https://qyapi.weixin.qq.com",
		NodeEnv:        "development",
		TestInstanceID: "short",
	})
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors for short password and short TEST_INSTANCE_ID, got %v", errs)
	}

	// Production SSRF guard on WECHAT_API_BASE
	errs, warnings := ValidateRuntime(&Config{
		EncryptionKey:            validKey,
		AdminUsername:            "admin",
		AdminPassword:            "strong-pass-12345",
		WechatAPIBase:            "http://evil.example.com",
		AllowCustomWechatAPIBase: false,
		NodeEnv:                  "production",
	})
	if len(errs) != 2 {
		t.Fatalf("expected 2 SSRF errors in production, got %v", errs)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "admin") {
		t.Fatalf("expected default admin warning in production, got %v", warnings)
	}

	// Production with AllowCustomWechatAPIBase = true
	errs, _ = ValidateRuntime(&Config{
		EncryptionKey:            validKey,
		AdminUsername:            "custom_admin",
		AdminPassword:            "strong-pass-12345",
		WechatAPIBase:            "http://127.0.0.1:19999",
		AllowCustomWechatAPIBase: true,
		NodeEnv:                  "production",
		TestInstanceID:           "valid-test-instance-id-12345",
	})
	if len(errs) != 0 {
		t.Fatalf("expected 0 errors when AllowCustomWechatAPIBase=true, got %v", errs)
	}
}
