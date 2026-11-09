package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"qywx-notifier-plus/internal/config"
)

const (
	gcmIVLength  = 12
	gcmTagLength = 16
	cbcIVLength  = 16
	v2Prefix     = "v2:"
)

var hexEvenRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

type Service struct {
	key []byte
}

func NewService(rawKey string) (*Service, error) {
	key, err := config.DecodeEncryptionKey(rawKey)
	if err != nil {
		return nil, err
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &Service{key: keyCopy}, nil
}

func NewServiceFromBytes(key []byte) (*Service, error) {
	if len(key) != 32 {
		return nil, errors.New("加密密钥长度必须为 32 字节")
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &Service{key: keyCopy}, nil
}

// Encrypt 使用 AES-256-GCM 加密，输出格式: v2:<ivHex>:<tagHex>:<ciphertextHex>
func (s *Service) Encrypt(text string) (string, error) {
	if text == "" {
		return "", nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", fmt.Errorf("加密数据失败: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmIVLength)
	if err != nil {
		return "", fmt.Errorf("加密数据失败: %w", err)
	}
	iv := make([]byte, gcmIVLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("加密数据失败: %w", err)
	}
	sealed := gcm.Seal(nil, iv, []byte(text), nil)
	ciphertext := sealed[:len(sealed)-gcmTagLength]
	tag := sealed[len(sealed)-gcmTagLength:]

	return fmt.Sprintf("%s%x:%x:%x", v2Prefix, iv, tag, ciphertext), nil
}

// Decrypt 解密数据（自动识别 v2 GCM 与旧版 CBC 格式）
func (s *Service) Decrypt(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}
	if strings.HasPrefix(encryptedText, v2Prefix) {
		plain, err := s.decryptGCM(encryptedText)
		if err != nil {
			return "", errors.New("解密数据失败")
		}
		return plain, nil
	}
	plain, err := s.decryptLegacyCBC(encryptedText)
	if err != nil {
		return "", errors.New("解密数据失败")
	}
	return plain, nil
}

func (s *Service) decryptGCM(payload string) (string, error) {
	parts := strings.Split(payload, ":")
	if len(parts) != 4 || parts[0] != "v2" {
		return "", errors.New("无效的 GCM 密文结构")
	}
	ivHex, tagHex, dataHex := parts[1], parts[2], parts[3]
	if len(ivHex) != gcmIVLength*2 || len(tagHex) != gcmTagLength*2 {
		return "", errors.New("无效的 GCM IV 或认证标签长度")
	}
	if dataHex != "" && (len(dataHex)%2 != 0 || !hexEvenRegex.MatchString(dataHex)) {
		return "", errors.New("无效的 GCM 密文十六进制内容")
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != gcmIVLength {
		return "", errors.New("无效的 GCM IV")
	}
	tag, err := hex.DecodeString(tagHex)
	if err != nil || len(tag) != gcmTagLength {
		return "", errors.New("无效的 GCM Tag")
	}
	var data []byte
	if dataHex != "" {
		data, err = hex.DecodeString(dataHex)
		if err != nil {
			return "", errors.New("无效的 GCM 密文")
		}
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmIVLength)
	if err != nil {
		return "", err
	}
	sealed := make([]byte, 0, len(data)+len(tag))
	sealed = append(sealed, data...)
	sealed = append(sealed, tag...)

	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Service) decryptLegacyCBC(payload string) (string, error) {
	parts := strings.Split(payload, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("无效的旧版 CBC 密文格式")
	}
	ivHex, encryptedHex := parts[0], parts[1]
	if len(ivHex) != cbcIVLength*2 || len(encryptedHex)%2 != 0 || !hexEvenRegex.MatchString(encryptedHex) {
		return "", errors.New("无效的旧版 CBC 参数")
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != cbcIVLength {
		return "", errors.New("无效的旧版 CBC IV")
	}
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("无效的旧版 CBC 密文块长度")
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	padLen := int(decrypted[len(decrypted)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(decrypted) {
		return "", errors.New("无效的 PKCS#7 填充长度")
	}
	for i := len(decrypted) - padLen; i < len(decrypted); i++ {
		if decrypted[i] != byte(padLen) {
			return "", errors.New("无效的 PKCS#7 填充字节")
		}
	}
	return string(decrypted[:len(decrypted)-padLen]), nil
}

// IsLegacyCiphertext 判断是否为旧版 CBC 密文
func (s *Service) IsLegacyCiphertext(encryptedText string) bool {
	if encryptedText == "" {
		return false
	}
	return !strings.HasPrefix(encryptedText, v2Prefix) && strings.Contains(encryptedText, ":")
}

// ReencryptIfLegacy 如为旧版 CBC 密文则解密并重加密为 v2 GCM
func (s *Service) ReencryptIfLegacy(encryptedText string) (cipherText string, migrated bool, plainText string, err error) {
	if encryptedText == "" {
		return "", false, "", nil
	}
	plain, err := s.Decrypt(encryptedText)
	if err != nil {
		return "", false, "", err
	}
	if strings.HasPrefix(encryptedText, v2Prefix) {
		return encryptedText, false, plain, nil
	}
	reencrypted, err := s.Encrypt(plain)
	if err != nil {
		return "", false, "", err
	}
	return reencrypted, true, plain, nil
}

// EncryptLegacyCBCForTest 仅用于单元测试构造旧版 CBC 密文
func (s *Service) EncryptLegacyCBCForTest(plain string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, cbcIVLength)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	raw := []byte(plain)
	padLen := aes.BlockSize - (len(raw) % aes.BlockSize)
	padded := make([]byte, len(raw)+padLen)
	copy(padded, raw)
	for i := len(raw); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return fmt.Sprintf("%x:%x", iv, ciphertext), nil
}
