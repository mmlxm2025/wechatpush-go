package notifycode

import (
	"regexp"
	"testing"
)

func TestNotifyCodeValidationAndGeneration(t *testing.T) {
	if NormalizeRuleAPICode("  My-Custom_Code-01 ") != "my-custom_code-01" {
		t.Fatal("NormalizeRuleAPICode failed")
	}

	validCases := []string{"abc", "abcd", "0123", "ops-alert_2026", "a234567890123456789012345678901234567890123456789012345678901234"}
	for _, tc := range validCases {
		if !IsValidRuleAPICode(tc) {
			t.Fatalf("expected %q to be valid", tc)
		}
	}

	invalidCases := []string{"", "ab", "-abcd", "_abcd", "abcd-", "abcd_", "ab!cd", "a2345678901234567890123456789012345678901234567890123456789012345"}
	for _, tc := range invalidCases {
		if IsValidRuleAPICode(tc) {
			t.Fatalf("expected %q to be invalid", tc)
		}
	}

	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	c1 := GenerateNotifyCode()
	c2 := GenerateNotifyCode()
	if !uuidRegex.MatchString(c1) || !uuidRegex.MatchString(c2) || c1 == c2 {
		t.Fatalf("unexpected generated UUIDs: %q, %q", c1, c2)
	}
}
