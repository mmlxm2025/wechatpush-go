package service

import "testing"

func TestWeChatFailureErrorMapping(t *testing.T) {
	cases := []struct {
		msg         string
		unavailable bool
		status      int
		code        string
	}{
		{"获取成员列表失败: no privilege (错误码: 60011)", false, 400, "WECHAT_CREDENTIAL_INVALID"},
		{"企业微信API请求失败: 获取access_token失败: invalid corpid (错误码: 40013)", false, 400, "WECHAT_CREDENTIAL_INVALID"},
		{"获取标签成员失败: system busy (错误码: -1)", false, 502, "WECHAT_UNAVAILABLE"},
		{"Get \"http://x/cgi-bin/gettoken\": dial tcp refused", true, 502, "WECHAT_UNAVAILABLE"},
	}
	for _, c := range cases {
		e := WeChatFailureError(c.msg, c.unavailable)
		if e.StatusCode != c.status || e.Code != c.code {
			t.Fatalf("%q => %d %s, want %d %s", c.msg, e.StatusCode, e.Code, c.status, c.code)
		}
	}
}
