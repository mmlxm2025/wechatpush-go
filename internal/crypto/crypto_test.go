package crypto

import (
	"strings"
	"testing"
)

func TestCryptoServiceGCMAndLegacyCBC(t *testing.T) {
	svc, err := NewService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	// Empty string
	if enc, err := svc.Encrypt(""); err != nil || enc != "" {
		t.Fatalf("expected empty encrypt, got %q %v", enc, err)
	}
	if dec, err := svc.Decrypt(""); err != nil || dec != "" {
		t.Fatalf("expected empty decrypt, got %q %v", dec, err)
	}

	// GCM roundtrip
	secret := "my-corp-secret-中文-12345"
	enc, err := svc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(enc, "v2:") {
		t.Fatalf("expected v2: prefix, got %q", enc)
	}
	if svc.IsLegacyCiphertext(enc) {
		t.Fatal("expected IsLegacyCiphertext=false for v2 ciphertext")
	}

	dec, err := svc.Decrypt(enc)
	if err != nil || dec != secret {
		t.Fatalf("Decrypt mismatch: got %q err=%v", dec, err)
	}

	// Tamper detection on GCM
	parts := strings.Split(enc, ":")
	lastChar := parts[3][len(parts[3])-1]
	var flipped byte = '0'
	if lastChar == '0' {
		flipped = '1'
	}
	parts[3] = parts[3][:len(parts[3])-1] + string(flipped)
	tampered := strings.Join(parts, ":")
	if _, err := svc.Decrypt(tampered); err == nil {
		t.Fatal("expected tampering to fail GCM decryption")
	}

	// Legacy CBC decryption & ReencryptIfLegacy
	legacyCipher, err := svc.EncryptLegacyCBCForTest(secret)
	if err != nil {
		t.Fatalf("EncryptLegacyCBCForTest failed: %v", err)
	}
	if !svc.IsLegacyCiphertext(legacyCipher) {
		t.Fatal("expected IsLegacyCiphertext=true for CBC ciphertext")
	}
	legacyPlain, err := svc.Decrypt(legacyCipher)
	if err != nil || legacyPlain != secret {
		t.Fatalf("legacy CBC decrypt failed: got %q err=%v", legacyPlain, err)
	}

	reenc, migrated, plain, err := svc.ReencryptIfLegacy(legacyCipher)
	if err != nil || !migrated || plain != secret || !strings.HasPrefix(reenc, "v2:") {
		t.Fatalf("ReencryptIfLegacy failed: migrated=%v plain=%q reenc=%q err=%v", migrated, plain, reenc, err)
	}

	// Calling ReencryptIfLegacy on v2 returns migrated=false
	reenc2, migrated2, plain2, err := svc.ReencryptIfLegacy(reenc)
	if err != nil || migrated2 || plain2 != secret || reenc2 != reenc {
		t.Fatalf("expected no migration for v2 ciphertext, got migrated=%v err=%v", migrated2, err)
	}
}
