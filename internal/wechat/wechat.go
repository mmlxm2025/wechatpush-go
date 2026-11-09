package wechat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	TokenExpireStatuses = map[int]bool{
		40014: true,
		42001: true,
		40001: true,
	}
	RateLimitStatuses = map[int]bool{
		45009: true,
	}
)

type WechatError struct {
	Message       string
	WechatErrCode int
	IsRateLimit   bool
}

func (e *WechatError) Error() string {
	return e.Message
}

type tokenRecord struct {
	token     string
	expiresAt int64
}

type SendOptions struct {
	CorpID     string
	CorpSecret string
	AgentID    string
	MsgType    string
	Content    map[string]any
	ToUser     string
	ToParty    string
	ToTag      string
	Safe       int
}

type SendResult struct {
	Success      bool   `json:"success"`
	MsgID        string `json:"msgid"`
	InvalidUser  string `json:"invaliduser,omitempty"`
	InvalidParty string `json:"invalidparty,omitempty"`
	InvalidTag   string `json:"invalidtag,omitempty"`
}

type ValidateResult struct {
	Valid     bool           `json:"valid"`
	AgentName string         `json:"agentName,omitempty"`
	AgentInfo map[string]any `json:"agentInfo,omitempty"`
	Error     string         `json:"error,omitempty"`
	// Unavailable 为 true 表示网络/上游不可用（非凭证错误），对应 Node 版 WECHAT_UNAVAILABLE。
	Unavailable bool `json:"-"`
}

type VisibleUser struct {
	UserID      string `json:"userid"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Department  []int  `json:"department"`
	Avatar      string `json:"avatar"`
}

type VisibleUsersResult struct {
	Success bool          `json:"success"`
	Users   []VisibleUser `json:"users"`
	Error   string        `json:"error,omitempty"`
	// Unavailable 为 true 表示网络/上游不可用（非企业微信业务错误码）。
	Unavailable bool `json:"-"`
}

type UploadMediaResult struct {
	Success   bool   `json:"success"`
	MediaID   string `json:"mediaId"`
	Type      string `json:"type"`
	CreatedAt any    `json:"createdAt"`
}

type Service struct {
	mu               sync.Mutex
	baseURL          string
	httpTimeout      time.Duration
	maxResponseBytes int64
	maxRequestBytes  int64
	tokens           map[string]tokenRecord
	nowFunc          func() int64
	httpClient       *http.Client
}

func NewService(baseURL string, timeoutMs int, maxResponseBytes int) *Service {
	if baseURL == "" {
		baseURL = "https://qyapi.weixin.qq.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if timeoutMs <= 0 {
		timeoutMs = 10000
	}
	if maxResponseBytes <= 0 {
		maxResponseBytes = 5 * 1024 * 1024
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	return &Service{
		baseURL:          baseURL,
		httpTimeout:      timeout,
		maxResponseBytes: int64(maxResponseBytes),
		maxRequestBytes:  5 * 1024 * 1024,
		tokens:           make(map[string]tokenRecord),
		nowFunc:          func() int64 { return time.Now().UnixMilli() },
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// firstSafe 取可选 safe 参数（与 Node 版一致，默认 0；原样透传给企业微信 safe 字段）。
func firstSafe(safe []int) int {
	if len(safe) > 0 {
		return safe[0]
	}
	return 0
}

// SetMaxRequestBytes 对应 Node 版 axios maxBodyLength（WECHAT_MAX_REQUEST_BYTES，默认 5MB）。
func (s *Service) SetMaxRequestBytes(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 {
		n = 5 * 1024 * 1024
	}
	s.maxRequestBytes = int64(n)
}

func (s *Service) SetBaseURL(baseURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseURL = strings.TrimRight(baseURL, "/")
}

func (s *Service) GetBaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseURL
}

func (s *Service) SetNowFunc(fn func() int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nowFunc = fn
}

func hashSecret(corpSecret string) string {
	sum := sha256.Sum256([]byte(corpSecret))
	return hex.EncodeToString(sum[:])
}

func getCacheKey(corpID, corpSecret string) string {
	return fmt.Sprintf("%s_%s", corpID, hashSecret(corpSecret))
}

func (s *Service) DeleteAccessToken(corpID, corpSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, getCacheKey(corpID, corpSecret))
}

func (s *Service) ClearAllTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]tokenRecord)
}

func (s *Service) doJSONRequest(method, reqURL string, body any) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		if s.maxRequestBytes > 0 && int64(len(b)) > s.maxRequestBytes {
			return nil, fmt.Errorf("请求体超过 WECHAT_MAX_REQUEST_BYTES 限制（%d > %d 字节）", len(b), s.maxRequestBytes)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, s.maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > s.maxResponseBytes {
		return nil, errors.New("响应体超过最大限制")
	}

	var data map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("解析响应 JSON 失败: %w", err)
	}
	return data, nil
}

func extractErrCode(data map[string]any) int {
	if data == nil {
		return -1
	}
	raw, exists := data["errcode"]
	if !exists || raw == nil {
		return 0
	}
	switch v := raw.(type) {
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return int(n)
		}
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return -1
}

func extractString(data map[string]any, key string) string {
	if data == nil {
		return ""
	}
	v, ok := data[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func (s *Service) GetAccessToken(corpID, corpSecret string, forceRefresh bool) (string, error) {
	cacheKey := getCacheKey(corpID, corpSecret)

	s.mu.Lock()
	now := s.nowFunc()
	if !forceRefresh {
		if cached, ok := s.tokens[cacheKey]; ok && now < cached.expiresAt {
			s.mu.Unlock()
			return cached.token, nil
		}
	}
	baseURL := s.baseURL
	s.mu.Unlock()

	q := url.Values{}
	q.Set("corpid", corpID)
	q.Set("corpsecret", corpSecret)
	reqURL := fmt.Sprintf("%s/cgi-bin/gettoken?%s", baseURL, q.Encode())

	data, err := s.doJSONRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("企业微信API请求失败: %s", err.Error())
	}

	errCode := extractErrCode(data)
	if errCode == 0 {
		token := extractString(data, "access_token")
		expiresIn := 7200
		if rawExp, ok := data["expires_in"]; ok {
			switch v := rawExp.(type) {
			case json.Number:
				if n, err := v.Int64(); err == nil {
					expiresIn = int(n)
				}
			case float64:
				expiresIn = int(v)
			}
		}
		s.mu.Lock()
		nowAfter := s.nowFunc()
		s.tokens[cacheKey] = tokenRecord{
			token:     token,
			expiresAt: nowAfter + int64(expiresIn-300)*1000,
		}
		s.mu.Unlock()
		return token, nil
	}

	errMsg := extractString(data, "errmsg")
	return "", &WechatError{
		Message:       fmt.Sprintf("企业微信API请求失败: 获取access_token失败: %s (错误码: %d)", errMsg, errCode),
		WechatErrCode: errCode,
		IsRateLimit:   RateLimitStatuses[errCode],
	}
}

func WithTokenRetry[T any](s *Service, corpID, corpSecret string, op func(accessToken string) (T, error)) (T, error) {
	var zero T
	token, err := s.GetAccessToken(corpID, corpSecret, false)
	if err != nil {
		return zero, err
	}
	res, err := op(token)
	if err == nil {
		return res, nil
	}
	var wxErr *WechatError
	if errors.As(err, &wxErr) && TokenExpireStatuses[wxErr.WechatErrCode] {
		s.DeleteAccessToken(corpID, corpSecret)
		refreshed, err2 := s.GetAccessToken(corpID, corpSecret, true)
		if err2 != nil {
			return zero, err2
		}
		return op(refreshed)
	}
	return zero, err
}

func (s *Service) SendMessage(opts SendOptions) (*SendResult, error) {
	return WithTokenRetry(s, opts.CorpID, opts.CorpSecret, func(accessToken string) (*SendResult, error) {
		reqURL := fmt.Sprintf("%s/cgi-bin/message/send?access_token=%s", s.GetBaseURL(), url.QueryEscape(accessToken))

		var agentIDVal any = opts.AgentID
		if n, err := strconv.Atoi(opts.AgentID); err == nil {
			agentIDVal = n
		}

		payload := map[string]any{
			"msgtype":    opts.MsgType,
			"agentid":    agentIDVal,
			opts.MsgType: opts.Content,
			"safe":       opts.Safe,
		}

		toUser := opts.ToUser
		if toUser == "" && opts.ToParty == "" && opts.ToTag == "" {
			toUser = "@all"
		}
		if toUser != "" {
			payload["touser"] = toUser
		}
		if opts.ToParty != "" {
			payload["toparty"] = opts.ToParty
		}
		if opts.ToTag != "" {
			payload["totag"] = opts.ToTag
		}

		data, err := s.doJSONRequest(http.MethodPost, reqURL, payload)
		if err != nil {
			return nil, fmt.Errorf("发送企业微信消息失败: %s", err.Error())
		}

		errCode := extractErrCode(data)
		if errCode == 0 {
			return &SendResult{
				Success:      true,
				MsgID:        extractString(data, "msgid"),
				InvalidUser:  extractString(data, "invaliduser"),
				InvalidParty: extractString(data, "invalidparty"),
				InvalidTag:   extractString(data, "invalidtag"),
			}, nil
		}

		errMsg := extractString(data, "errmsg")
		return nil, &WechatError{
			Message:       fmt.Sprintf("发送企业微信消息失败: 发送消息失败: %s (错误码: %d)", errMsg, errCode),
			WechatErrCode: errCode,
			IsRateLimit:   RateLimitStatuses[errCode],
		}
	})
}

func (s *Service) SendTextMessage(corpID, corpSecret, agentID, message, toUser string, safe ...int) (*SendResult, error) {
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "text",
		Content:    map[string]any{"content": message},
		ToUser:     toUser,
		Safe:       firstSafe(safe),
	})
}

func (s *Service) SendMarkdownMessage(corpID, corpSecret, agentID, markdown, toUser string, safe ...int) (*SendResult, error) {
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "markdown",
		Content:    map[string]any{"content": markdown},
		ToUser:     toUser,
		Safe:       firstSafe(safe),
	})
}

func (s *Service) SendImageMessage(corpID, corpSecret, agentID, mediaID, toUser string, safe ...int) (*SendResult, error) {
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "image",
		Content:    map[string]any{"media_id": mediaID},
		ToUser:     toUser,
		Safe:       firstSafe(safe),
	})
}

func (s *Service) SendFileMessage(corpID, corpSecret, agentID, mediaID, toUser string, safe ...int) (*SendResult, error) {
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "file",
		Content:    map[string]any{"media_id": mediaID},
		ToUser:     toUser,
		Safe:       firstSafe(safe),
	})
}

func (s *Service) SendTextCardMessage(corpID, corpSecret, agentID string, cardData map[string]any, toUser string, safe ...int) (*SendResult, error) {
	btnTxt := extractString(cardData, "btntxt")
	if btnTxt == "" {
		btnTxt = "详情"
	}
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "textcard",
		Content: map[string]any{
			"title":       extractString(cardData, "title"),
			"description": extractString(cardData, "description"),
			"url":         extractString(cardData, "url"),
			"btntxt":      btnTxt,
		},
		ToUser: toUser,
		Safe:   firstSafe(safe),
	})
}

func (s *Service) SendNewsMessage(corpID, corpSecret, agentID string, articles []map[string]any, toUser string, safe ...int) (*SendResult, error) {
	formatted := make([]map[string]any, 0, len(articles))
	for _, a := range articles {
		formatted = append(formatted, map[string]any{
			"title":       extractString(a, "title"),
			"description": extractString(a, "description"),
			"url":         extractString(a, "url"),
			"picurl":      extractString(a, "picurl"),
		})
	}
	return s.SendMessage(SendOptions{
		CorpID:     corpID,
		CorpSecret: corpSecret,
		AgentID:    agentID,
		MsgType:    "news",
		Content:    map[string]any{"articles": formatted},
		ToUser:     toUser,
		Safe:       firstSafe(safe),
	})
}

func (s *Service) ValidateCredentials(corpID, corpSecret, agentID string) ValidateResult {
	accessToken, err := s.GetAccessToken(corpID, corpSecret, false)
	if err != nil {
		var wxErr *WechatError
		return ValidateResult{Valid: false, Error: err.Error(), Unavailable: !errors.As(err, &wxErr)}
	}
	q := url.Values{}
	q.Set("access_token", accessToken)
	q.Set("agentid", agentID)
	reqURL := fmt.Sprintf("%s/cgi-bin/agent/get?%s", s.GetBaseURL(), q.Encode())

	data, err := s.doJSONRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return ValidateResult{Valid: false, Error: err.Error(), Unavailable: true}
	}
	errCode := extractErrCode(data)
	if errCode == 0 {
		return ValidateResult{
			Valid:     true,
			AgentName: extractString(data, "name"),
			AgentInfo: data,
		}
	}
	errMsg := extractString(data, "errmsg")
	return ValidateResult{
		Valid: false,
		Error: fmt.Sprintf("AgentId验证失败: %s (错误码: %d)", errMsg, errCode),
	}
}

func (s *Service) GetDepartmentUsers(corpID, corpSecret string, departmentID int, fetchChild bool) ([]VisibleUser, error) {
	return WithTokenRetry(s, corpID, corpSecret, func(accessToken string) ([]VisibleUser, error) {
		q := url.Values{}
		q.Set("access_token", accessToken)
		q.Set("department_id", strconv.Itoa(departmentID))
		if fetchChild {
			q.Set("fetch_child", "1")
		} else {
			q.Set("fetch_child", "0")
		}
		reqURL := fmt.Sprintf("%s/cgi-bin/user/simplelist?%s", s.GetBaseURL(), q.Encode())
		data, err := s.doJSONRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		errCode := extractErrCode(data)
		if errCode != 0 {
			return nil, &WechatError{
				Message:       fmt.Sprintf("获取部门成员失败: %s (错误码: %d)", extractString(data, "errmsg"), errCode),
				WechatErrCode: errCode,
				IsRateLimit:   RateLimitStatuses[errCode],
			}
		}
		return parseUserSlice(data["userlist"]), nil
	})
}

func (s *Service) GetTagUsers(corpID, corpSecret string, tagID int) ([]VisibleUser, error) {
	return WithTokenRetry(s, corpID, corpSecret, func(accessToken string) ([]VisibleUser, error) {
		q := url.Values{}
		q.Set("access_token", accessToken)
		q.Set("tagid", strconv.Itoa(tagID))
		reqURL := fmt.Sprintf("%s/cgi-bin/tag/get?%s", s.GetBaseURL(), q.Encode())
		data, err := s.doJSONRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		errCode := extractErrCode(data)
		if errCode != 0 {
			return nil, &WechatError{
				Message:       fmt.Sprintf("获取标签成员失败: %s (错误码: %d)", extractString(data, "errmsg"), errCode),
				WechatErrCode: errCode,
				IsRateLimit:   RateLimitStatuses[errCode],
			}
		}
		return parseUserSlice(data["userlist"]), nil
	})
}

func parseUserSlice(raw any) []VisibleUser {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	users := make([]VisibleUser, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		uid := extractString(m, "userid")
		if uid == "" {
			continue
		}
		name := extractString(m, "name")
		if name == "" {
			name = uid
		}
		var depts []int
		if rawDept, ok := m["department"].([]any); ok {
			for _, d := range rawDept {
				if n, ok := toInt(d); ok {
					depts = append(depts, n)
				}
			}
		}
		if depts == nil {
			depts = []int{}
		}
		disp := uid
		if name != "" && name != uid {
			disp = fmt.Sprintf("%s (%s)", name, uid)
		}
		users = append(users, VisibleUser{
			UserID:      uid,
			Name:        name,
			DisplayName: disp,
			Department:  depts,
			Avatar:      extractString(m, "avatar"),
		})
	}
	return users
}

func toInt(v any) (int, bool) {
	switch val := v.(type) {
	case json.Number:
		n, err := val.Int64()
		return int(n), err == nil
	case float64:
		return int(val), true
	case int:
		return val, true
	case string:
		n, err := strconv.Atoi(val)
		return n, err == nil
	default:
		return 0, false
	}
}

func (s *Service) GetVisibleUsers(corpID, corpSecret, agentID string) VisibleUsersResult {
	agentData, err := WithTokenRetry(s, corpID, corpSecret, func(accessToken string) (map[string]any, error) {
		q := url.Values{}
		q.Set("access_token", accessToken)
		q.Set("agentid", agentID)
		reqURL := fmt.Sprintf("%s/cgi-bin/agent/get?%s", s.GetBaseURL(), q.Encode())
		data, err := s.doJSONRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		errCode := extractErrCode(data)
		if errCode != 0 {
			return nil, &WechatError{
				Message:       fmt.Sprintf("获取应用信息失败: %s (错误码: %d)", extractString(data, "errmsg"), errCode),
				WechatErrCode: errCode,
				IsRateLimit:   RateLimitStatuses[errCode],
			}
		}
		return data, nil
	})
	if err != nil {
		return VisibleUsersResult{
			Success:     false,
			Users:       []VisibleUser{},
			Error:       err.Error(),
			Unavailable: !isWechatError(err),
		}
	}

	userOrder := make([]string, 0)
	usersMap := make(map[string]VisibleUser)
	upsertUser := func(u VisibleUser) {
		if u.UserID == "" {
			return
		}
		existing, exists := usersMap[u.UserID]
		if !exists {
			userOrder = append(userOrder, u.UserID)
			if u.Department == nil {
				u.Department = []int{}
			}
			if u.Name == "" {
				u.Name = u.UserID
			}
			usersMap[u.UserID] = u
			return
		}
		if u.Name != "" && u.Name != u.UserID {
			existing.Name = u.Name
		}
		if len(u.Department) > 0 {
			existing.Department = u.Department
		}
		if u.Avatar != "" {
			existing.Avatar = u.Avatar
		}
		usersMap[u.UserID] = existing
	}

	if allowUsersObj, ok := agentData["allow_userinfos"].(map[string]any); ok {
		for _, u := range parseUserSlice(allowUsersObj["user"]) {
			upsertUser(u)
		}
	}

	// 与 Node 版 getAgentVisibleUsers 一致：部门/标签成员读取失败直接返回错误（不静默跳过）；
	// 应用未配置任何可见范围时回退读取根部门（department_id=1, fetch_child=1）。
	fail := func(err error) VisibleUsersResult {
		return VisibleUsersResult{Success: false, Users: []VisibleUser{}, Error: err.Error(), Unavailable: !isWechatError(err)}
	}
	hasScope := len(userOrder) > 0
	if allowPartysObj, ok := agentData["allow_partys"].(map[string]any); ok {
		if partyArr, ok := allowPartysObj["partyid"].([]any); ok {
			for _, p := range partyArr {
				if pid, ok := toInt(p); ok {
					hasScope = true
					deptUsers, err := s.GetDepartmentUsers(corpID, corpSecret, pid, true)
					if err != nil {
						return fail(err)
					}
					for _, u := range deptUsers {
						upsertUser(u)
					}
				}
			}
		}
	}

	if allowTagsObj, ok := agentData["allow_tags"].(map[string]any); ok {
		if tagArr, ok := allowTagsObj["tagid"].([]any); ok {
			for _, t := range tagArr {
				if tid, ok := toInt(t); ok {
					hasScope = true
					tagUsers, err := s.GetTagUsers(corpID, corpSecret, tid)
					if err != nil {
						return fail(err)
					}
					for _, u := range tagUsers {
						upsertUser(u)
					}
				}
			}
		}
	}

	if !hasScope {
		rootUsers, err := s.GetDepartmentUsers(corpID, corpSecret, 1, true)
		if err != nil {
			return fail(err)
		}
		for _, u := range rootUsers {
			upsertUser(u)
		}
	}

	users := make([]VisibleUser, 0, len(userOrder))
	for _, uid := range userOrder {
		u := usersMap[uid]
		if u.Name != "" && u.Name != u.UserID {
			u.DisplayName = fmt.Sprintf("%s (%s)", u.Name, u.UserID)
		} else {
			u.DisplayName = u.UserID
		}
		users = append(users, u)
	}
	return VisibleUsersResult{
		Success: true,
		Users:   users,
	}
}

func (s *Service) UploadMedia(corpID, corpSecret, mediaType string, fileBuffer []byte, filename, contentType string) (*UploadMediaResult, error) {
	return WithTokenRetry(s, corpID, corpSecret, func(accessToken string) (*UploadMediaResult, error) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		if filename == "" {
			filename = "upload.bin"
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="media"; filename=%q`, filename))
		h.Set("Content-Type", contentType)
		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(fileBuffer); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}

		q := url.Values{}
		q.Set("access_token", accessToken)
		q.Set("type", mediaType)
		reqURL := fmt.Sprintf("%s/cgi-bin/media/upload?%s", s.GetBaseURL(), q.Encode())

		req, err := http.NewRequest(http.MethodPost, reqURL, &buf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("上传企业微信媒体文件失败: %s", err.Error())
		}
		defer resp.Body.Close()

		raw, err := io.ReadAll(io.LimitReader(resp.Body, s.maxResponseBytes+1))
		if err != nil {
			return nil, err
		}
		var data map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return nil, err
		}

		errCode := extractErrCode(data)
		if errCode == 0 {
			return &UploadMediaResult{
				Success:   true,
				MediaID:   extractString(data, "media_id"),
				Type:      extractString(data, "type"),
				CreatedAt: data["created_at"],
			}, nil
		}
		errMsg := extractString(data, "errmsg")
		return nil, &WechatError{
			Message:       fmt.Sprintf("上传企业微信媒体文件失败: 上传媒体文件失败: %s (错误码: %d)", errMsg, errCode),
			WechatErrCode: errCode,
			IsRateLimit:   RateLimitStatuses[errCode],
		}
	})
}

func isWechatError(err error) bool {
	var wxErr *WechatError
	return errors.As(err, &wxErr)
}
