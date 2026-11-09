package wxcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	pkcs7BlockSize = 32
	alnumChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

type WXBizMsgCrypt struct {
	token          string
	encodingAESKey string
	receiveID      string
	key            []byte
	iv             []byte
}

func NewWXBizMsgCrypt(token, encodingAESKey, receiveID string) (*WXBizMsgCrypt, error) {
	if token == "" {
		return nil, errors.New("缺少 token")
	}
	if len(encodingAESKey) != 43 {
		return nil, errors.New("encodingAESKey 长度必须为 43 位")
	}
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil || len(key) != 32 {
		return nil, errors.New("encodingAESKey 解码失败")
	}
	return &WXBizMsgCrypt{
		token:          token,
		encodingAESKey: encodingAESKey,
		receiveID:      receiveID,
		key:            key,
		iv:             key[:16],
	}, nil
}

func Sign(token, timestamp, nonce, encryptMsg string) string {
	arr := []string{token, timestamp, nonce, encryptMsg}
	sort.Strings(arr)
	sum := sha1.Sum([]byte(strings.Join(arr, "")))
	return hex.EncodeToString(sum[:])
}

func (c *WXBizMsgCrypt) Encrypt(xmlMsg string) (string, error) {
	random16 := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random16); err != nil {
		return "", err
	}
	msgBytes := []byte(xmlMsg)
	idBytes := []byte(c.receiveID)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msgBytes)))

	rawLen := 16 + 4 + len(msgBytes) + len(idBytes)
	padLen := pkcs7BlockSize - (rawLen % pkcs7BlockSize)
	if padLen == 0 {
		padLen = pkcs7BlockSize
	}

	buf := make([]byte, 0, rawLen+padLen)
	buf = append(buf, random16...)
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, msgBytes...)
	buf = append(buf, idBytes...)
	for i := 0; i < padLen; i++ {
		buf = append(buf, byte(padLen))
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	encrypted := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, c.iv).CryptBlocks(encrypted, buf)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *WXBizMsgCrypt) Decrypt(encryptStr string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptStr))
	if err != nil || len(cipherBytes) == 0 || len(cipherBytes)%aes.BlockSize != 0 {
		return "", errors.New("密文解码失败 (errCode: -40007)")
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(cipherBytes))
	cipher.NewCBCDecrypter(block, c.iv).CryptBlocks(decrypted, cipherBytes)

	// BUG-08 修复：严格校验 PKCS#7 填充长度与填充字节，以及 16+4+msgLen 边界，避免畸形密文触发越界 panic
	if len(decrypted) < 20 {
		return "", errors.New("解密后数据长度不足 (errCode: -40007)")
	}
	padLen := int(decrypted[len(decrypted)-1])
	if padLen < 1 || padLen > pkcs7BlockSize || padLen > len(decrypted) {
		return "", errors.New("非法 PKCS#7 填充长度 (errCode: -40007)")
	}
	for i := len(decrypted) - padLen; i < len(decrypted); i++ {
		if decrypted[i] != byte(padLen) {
			return "", errors.New("非法 PKCS#7 填充内容 (errCode: -40007)")
		}
	}

	unpadded := decrypted[:len(decrypted)-padLen]
	if len(unpadded) < 20 {
		return "", errors.New("去除填充后数据长度不足 (errCode: -40007)")
	}

	msgLen := int(binary.BigEndian.Uint32(unpadded[16:20]))
	if msgLen < 0 || 20+msgLen > len(unpadded) {
		return "", errors.New("消息长度字段越界 (errCode: -40007)")
	}

	msg := string(unpadded[20 : 20+msgLen])
	fromReceiveID := string(unpadded[20+msgLen:])

	if c.receiveID != "" && fromReceiveID != c.receiveID {
		return "", errors.New("ReceiveId 校验错误 (errCode: -40005)")
	}
	return msg, nil
}

func (c *WXBizMsgCrypt) VerifyURL(msgSignature, timestamp, nonce, echostr string) (string, error) {
	if Sign(c.token, timestamp, nonce, echostr) != msgSignature {
		return "", errors.New("签名验证错误 (errCode: -40001)")
	}
	return c.Decrypt(echostr)
}

func (c *WXBizMsgCrypt) DecryptMsg(msgSignature, timestamp, nonce, postData string) (string, error) {
	fields, err := ParseXMLMessage(postData)
	if err != nil {
		return "", errors.New("XML 解析失败 (errCode: -40002)")
	}
	encryptStr := fields["Encrypt"]
	if encryptStr == "" {
		return "", errors.New("XML 缺少 Encrypt 字段 (errCode: -40002)")
	}
	if Sign(c.token, timestamp, nonce, encryptStr) != msgSignature {
		return "", errors.New("签名验证错误 (errCode: -40001)")
	}
	return c.Decrypt(encryptStr)
}

func (c *WXBizMsgCrypt) EncryptMsg(replyMsg, timestamp, nonce string) (string, error) {
	encryptStr, err := c.Encrypt(replyMsg)
	if err != nil {
		return "", err
	}
	if timestamp == "" {
		timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	}
	if nonce == "" {
		nonce = GenerateRandomDigits(10)
	}
	sig := Sign(c.token, timestamp, nonce, encryptStr)
	return fmt.Sprintf(
		"<xml><Encrypt><![CDATA[%s]]></Encrypt><MsgSignature><![CDATA[%s]]></MsgSignature><TimeStamp>%s</TimeStamp><Nonce><![CDATA[%s]]></Nonce></xml>",
		encryptStr, sig, timestamp, nonce,
	), nil
}

// ParseXMLMessage 解析单层 <xml><Key>Value</Key>...</xml> 消息结构
func ParseXMLMessage(xmlStr string) (map[string]string, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	result := make(map[string]string)

	var inRoot bool
	var currentTag string
	var charBuf bytes.Buffer

	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("解析 XML 消息失败: %w", err)
		}

		switch se := tok.(type) {
		case xml.StartElement:
			if !inRoot {
				if se.Name.Local == "xml" {
					inRoot = true
				}
			} else if currentTag == "" {
				currentTag = se.Name.Local
				charBuf.Reset()
			}
		case xml.CharData:
			if inRoot && currentTag != "" {
				charBuf.Write(se)
			}
		case xml.EndElement:
			if inRoot {
				if se.Name.Local == currentTag && currentTag != "" {
					result[currentTag] = charBuf.String()
					currentTag = ""
					charBuf.Reset()
				} else if se.Name.Local == "xml" {
					inRoot = false
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, errors.New("解析 XML 消息失败: 空文档或缺少 <xml> 根节点")
	}
	return result, nil
}

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = alnumChars[int(b[i])%len(alnumChars)]
	}
	return string(out)
}

func GenerateRandomDigits(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = digits[int(b[i])%len(digits)]
	}
	return string(out)
}

// GenerateCallbackConfig 生成随机回调 Token(16位) 与 EncodingAESKey(43位)
func GenerateCallbackConfig() (token string, encodingAESKey string) {
	return GenerateRandomString(16), GenerateRandomString(43)
}
