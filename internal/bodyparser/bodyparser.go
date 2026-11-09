package bodyparser

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

const DefaultJSONBodyLimit = 256 * 1024 // 256KB

var (
	ErrPayloadTooLarge = errors.New("请求体过大，最大允许 256KB")
	ErrInvalidJSON     = errors.New("请求体 JSON 格式无效（请检查引号转义或将终端编码切换为 UTF-8）")
)

func IsValidUTF8(buf []byte) bool {
	return utf8.Valid(buf)
}

// TranscodeGB18030BodyIfNeeded 检测非 UTF-8 字节流并尝试按 GB18030 解码为合法 JSON UTF-8 字节流
func TranscodeGB18030BodyIfNeeded(buf []byte) ([]byte, bool) {
	if len(buf) == 0 {
		return buf, false
	}
	if utf8.Valid(buf) {
		return buf, false
	}

	decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(buf)
	if err != nil {
		return buf, false
	}
	if !utf8.Valid(decoded) || bytes.ContainsRune(decoded, utf8.RuneError) {
		return buf, false
	}
	if !json.Valid(decoded) {
		return buf, false
	}
	return decoded, true
}

type ParsedBody struct {
	RawBody    []byte
	UTF8Body   []byte
	Transcoded bool
	IsJSON     bool
	Data       map[string]any
}

func IsJSONContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	semi := strings.IndexByte(ct, ';')
	if semi >= 0 {
		ct = strings.TrimSpace(ct[:semi])
	}
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// ReadAndParseJSON 读取请求体（保留原始字节用于 HMAC 验签，支持 GBK/GB18030 自动转码）
func ReadAndParseJSON(r *http.Request, maxBytes int64) (*ParsedBody, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultJSONBodyLimit
	}
	if r == nil || r.Body == nil {
		return &ParsedBody{
			RawBody:  []byte{},
			UTF8Body: []byte{},
			Data:     map[string]any{},
		}, nil
	}
	defer r.Body.Close()

	limited := io.LimitReader(r.Body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	if int64(len(raw)) > maxBytes {
		return nil, ErrPayloadTooLarge
	}

	utf8Bytes, transcoded := TranscodeGB18030BodyIfNeeded(raw)
	res := &ParsedBody{
		RawBody:    raw,
		UTF8Body:   utf8Bytes,
		Transcoded: transcoded,
		IsJSON:     IsJSONContentType(r.Header.Get("Content-Type")),
		Data:       make(map[string]any),
	}

	trimmed := bytes.TrimSpace(utf8Bytes)
	if len(trimmed) == 0 {
		return res, nil
	}

	// Express express.json() 仅允许对象或数组作为顶层 JSON，本项目业务接口均接收 JSON 对象
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return res, ErrInvalidJSON
	}
	// 检查是否有尾随非空白字符
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return res, ErrInvalidJSON
	}
	res.Data = obj
	res.IsJSON = true
	return res, nil
}
