package notifycode

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
)

var RuleAPICodeRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$`)

// NormalizeRuleAPICode 规范化自定义推送码（trim + 小写）
func NormalizeRuleAPICode(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// IsValidRuleAPICode 校验推送码格式：3~64 位，首尾字符 a-z0-9，中间允许 a-z0-9_-
func IsValidRuleAPICode(raw string) bool {
	normalized := NormalizeRuleAPICode(raw)
	if len(normalized) < 3 || len(normalized) > 64 {
		return false
	}
	return RuleAPICodeRegex.MatchString(normalized)
}

// GenerateNotifyCode 生成全小写 UUID v4 通知码
func GenerateNotifyCode() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return strings.ToLower(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}
