package wxcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestWXBizMsgCryptRoundtripAndBounds(t *testing.T) {
	token, aesKey := GenerateCallbackConfig()
	if len(token) != 16 || len(aesKey) != 43 {
		t.Fatalf("unexpected generated config lengths: %d %d", len(token), len(aesKey))
	}

	corpID := "ww1234567890abcdef"
	crypt, err := NewWXBizMsgCrypt(token, aesKey, corpID)
	if err != nil {
		t.Fatalf("NewWXBizMsgCrypt failed: %v", err)
	}

	// VerifyURL roundtrip
	echoPlain := "echostr-verification-12345"
	echoCipher, err := crypt.Encrypt(echoPlain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	sig := Sign(token, "1700000000", "nonce1", echoCipher)
	verified, err := crypt.VerifyURL(sig, "1700000000", "nonce1", echoCipher)
	if err != nil || verified != echoPlain {
		t.Fatalf("VerifyURL failed: got %q err=%v", verified, err)
	}

	// Draft callback with empty receiveID should also accept encrypted echostr from real CorpID
	draftCrypt, err := NewWXBizMsgCrypt(token, aesKey, "")
	if err != nil {
		t.Fatalf("draft NewWXBizMsgCrypt failed: %v", err)
	}
	draftVerified, err := draftCrypt.VerifyURL(sig, "1700000000", "nonce1", echoCipher)
	if err != nil || draftVerified != echoPlain {
		t.Fatalf("draft VerifyURL failed: got %q err=%v", draftVerified, err)
	}

	// EncryptMsg & DecryptMsg roundtrip
	xmlMsg := "<xml><ToUserName><![CDATA[ww123]]></ToUserName><FromUserName><![CDATA[zhangsan]]></FromUserName><CreateTime>1700000000</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[你好]]></Content><MsgId>1001</MsgId></xml>"
	encryptedXML, err := crypt.EncryptMsg(xmlMsg, "1700000000", "nonce2")
	if err != nil {
		t.Fatalf("EncryptMsg failed: %v", err)
	}
	outerFields, err := ParseXMLMessage(encryptedXML)
	if err != nil {
		t.Fatalf("ParseXMLMessage outer failed: %v", err)
	}
	decryptedXML, err := crypt.DecryptMsg(outerFields["MsgSignature"], outerFields["TimeStamp"], outerFields["Nonce"], encryptedXML)
	if err != nil || decryptedXML != xmlMsg {
		t.Fatalf("DecryptMsg failed: got %q err=%v", decryptedXML, err)
	}

	// BUG-08 test: Craft a ciphertext with valid PKCS#7 padding but out-of-bounds msgLen (e.g., 999999)
	rawBlock := make([]byte, 32)
	binary.BigEndian.PutUint32(rawBlock[16:20], 999999) // Out of bounds msgLen
	for i := 20; i < 32; i++ {
		rawBlock[i] = 12 // Valid 12-byte PKCS#7 padding at end of 32-byte block
	}
	block, _ := aes.NewCipher(crypt.key)
	badCipher := make([]byte, 32)
	cipher.NewCBCEncrypter(block, crypt.iv).CryptBlocks(badCipher, rawBlock)
	badBase64 := base64.StdEncoding.EncodeToString(badCipher)

	if _, err := crypt.Decrypt(badBase64); err == nil {
		t.Fatal("BUG-08 regression: expected error for out-of-bounds msgLen in decrypted payload")
	}
}
