package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/wechat"
	"qywx-notifier-plus/internal/wxcrypt"
)

var (
	callbackDigitsRegex = regexp.MustCompile(`^\d{1,16}$`)
	dataURLPrefixRegex  = regexp.MustCompile(`^data:[^;]+;base64,`)
)

type NotificationTarget struct {
	CorpID          string
	CorpSecret      string
	AgentID         string
	ToUser          string
	ToParty         string
	ToTag           string
	IsAll           bool
	IsCompleted     bool
	TargetType      string
	RuleName        string
	RuleID          int
	ConfigCode      string
	AppEnabled      bool
	CodeSendEnabled bool
	RuleEnabled     bool
}

type NotifyAuthMeta struct {
	Found           bool
	TargetType      string
	ConfigCode      string
	NotifyKeyHash   string
	AppEnabled      bool
	RuleEnabled     bool
	CodeSendEnabled bool
}

// ResolveNotifyAuthMeta 解析通知码对应的鉴权与三层开关元数据（修复 BUG-03：在鉴权前检测跨表命名空间冲突）
func (n *Notifier) ResolveNotifyAuthMeta(requestedCode string) (*NotifyAuthMeta, error) {
	rule, err := n.getRuleByAPICodeCached(requestedCode)
	if err != nil {
		return nil, err
	}
	if rule != nil {
		// BUG-03 修复：若同时存在同名（忽略大小写）的应用级配置，立即拒绝投递以防止串投或误用另一实体的鉴权密钥
		directConfig, err := n.getConfigByCodeCached(requestedCode)
		if err != nil {
			return nil, err
		}
		if directConfig != nil {
			return nil, NewError(
				"检测到历史规则码与应用码冲突，已拒绝投递以防止串投；请联系管理员重新生成规则推送码",
				500,
				"NOTIFY_CODE_NAMESPACE_CORRUPTED",
			)
		}
		return &NotifyAuthMeta{
			Found:           true,
			TargetType:      "rule",
			ConfigCode:      rule.ConfigCode,
			NotifyKeyHash:   rule.NotifyKeyHash,
			AppEnabled:      rule.ConfigEnabled != 0,
			RuleEnabled:     rule.Enabled != 0,
			CodeSendEnabled: rule.CodeSendEnabled != 0,
		}, nil
	}

	cfg, err := n.getConfigByCodeCached(requestedCode)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		return &NotifyAuthMeta{
			Found:           true,
			TargetType:      "app",
			ConfigCode:      cfg.Code,
			NotifyKeyHash:   cfg.NotifyKeyHash,
			AppEnabled:      cfg.Enabled != 0,
			RuleEnabled:     true,
			CodeSendEnabled: cfg.CodeSendEnabled != 0,
		}, nil
	}

	return &NotifyAuthMeta{Found: false}, nil
}

func (n *Notifier) getConfigByCodeCached(code string) (*database.ConfigRow, error) {
	norm := strings.ToLower(strings.TrimSpace(code))
	n.mu.Lock()
	now := n.nowFunc()
	if cached, ok := n.configCache[norm]; ok && cached.expiresAt > now {
		n.mu.Unlock()
		return cached.data, nil
	}
	n.mu.Unlock()

	row, err := n.db.GetConfigurationByCode(code)
	if err != nil {
		return nil, err
	}
	if row != nil {
		n.mu.Lock()
		n.configCache[norm] = cachedConfigEntry{
			data:      row,
			expiresAt: n.nowFunc() + int64(n.cfg.ConfigCacheTTLMs),
		}
		n.mu.Unlock()
	}
	return row, nil
}

func (n *Notifier) getRuleByAPICodeCached(apiCode string) (*database.RuleWithConfigRow, error) {
	norm := strings.ToLower(strings.TrimSpace(apiCode))
	n.mu.Lock()
	now := n.nowFunc()
	if cached, ok := n.ruleCache[norm]; ok && cached.expiresAt > now {
		n.mu.Unlock()
		return cached.data, nil
	}
	n.mu.Unlock()

	rule, err := n.db.GetNotificationRuleByAPICode(apiCode)
	if err != nil {
		return nil, err
	}
	if rule != nil {
		n.mu.Lock()
		n.ruleCache[norm] = cachedRuleEntry{
			data:      rule,
			expiresAt: n.nowFunc() + int64(n.cfg.ConfigCacheTTLMs),
		}
		n.mu.Unlock()
	}
	return rule, nil
}

func (n *Notifier) ResolveNotificationTarget(code string) (*NotificationTarget, error) {
	rule, err := n.getRuleByAPICodeCached(code)
	if err != nil {
		return nil, err
	}
	if rule != nil {
		directConfig, err := n.getConfigByCodeCached(code)
		if err != nil {
			return nil, err
		}
		if directConfig != nil {
			return nil, NewError(
				"检测到历史规则码与应用码冲突，已拒绝投递以防止串投；请联系管理员重新生成规则推送码",
				500,
				"NOTIFY_CODE_NAMESPACE_CORRUPTED",
			)
		}
		var plainCorp, plainSecret string
		if rule.IsCompleted && rule.CorpID != "" && rule.CorpSecret != "" {
			plainMap, err := n.decryptWithLazyMigration(rule.ConfigCode, []encryptedFieldSpec{
				{col: "corp_id", value: rule.CorpID},
				{col: "corp_secret", value: rule.CorpSecret},
			})
			if err != nil {
				return nil, err
			}
			plainCorp = plainMap["corp_id"]
			plainSecret = plainMap["corp_secret"]
		}
		return &NotificationTarget{
			CorpID:          plainCorp,
			CorpSecret:      plainSecret,
			AgentID:         rule.AgentID,
			ToUser:          rule.ToUser,
			ToParty:         rule.ToParty,
			ToTag:           rule.ToTag,
			IsAll:           rule.IsAll != 0,
			IsCompleted:     rule.IsCompleted,
			TargetType:      "rule",
			RuleName:        rule.Name,
			RuleID:          rule.ID,
			ConfigCode:      rule.ConfigCode,
			AppEnabled:      rule.ConfigEnabled != 0,
			CodeSendEnabled: rule.CodeSendEnabled != 0,
			RuleEnabled:     rule.Enabled != 0,
		}, nil
	}

	cfg, err := n.getConfigByCodeCached(code)
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		var plainCorp, plainSecret string
		if cfg.IsCompleted && cfg.CorpID != "" && cfg.CorpSecret != "" {
			plainMap, err := n.decryptWithLazyMigration(cfg.Code, []encryptedFieldSpec{
				{col: "corp_id", value: cfg.CorpID},
				{col: "corp_secret", value: cfg.CorpSecret},
			})
			if err != nil {
				return nil, err
			}
			plainCorp = plainMap["corp_id"]
			plainSecret = plainMap["corp_secret"]
		}
		return &NotificationTarget{
			CorpID:          plainCorp,
			CorpSecret:      plainSecret,
			AgentID:         cfg.AgentID,
			ToUser:          cfg.ToUser,
			IsCompleted:     cfg.IsCompleted,
			TargetType:      "app",
			ConfigCode:      cfg.Code,
			AppEnabled:      cfg.Enabled != 0,
			CodeSendEnabled: cfg.CodeSendEnabled != 0,
			RuleEnabled:     true,
		}, nil
	}

	return nil, nil
}

func (n *Notifier) SendNotification(code, message, customToUser, msgType string, extraData map[string]any) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("代码是必填项", 400, "INVALID_INPUT")
	}
	if strings.TrimSpace(msgType) == "" {
		msgType = "text"
	}

	target, err := n.ResolveNotificationTarget(code)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, NewError("无效的code，未找到配置", 404, "APP_NOT_FOUND")
	}
	if !target.IsCompleted {
		return nil, NewError("应用尚未完成配置", 409, "APP_NOT_COMPLETED")
	}

	// 三层发送开关判定（固定优先级：应用总开关 -> 规则开关 -> 应用级 Code 直发开关）
	if !target.AppEnabled {
		return nil, NewError("该应用已暂停发送", 403, "APP_DISABLED")
	}
	if target.TargetType == "rule" && !target.RuleEnabled {
		return nil, NewError("该规则已被禁用", 403, "RULE_DISABLED")
	}
	if target.TargetType == "app" && !target.CodeSendEnabled {
		return nil, NewError("该应用已关闭 Code 直接发送，请使用规则 API", 403, "DIRECT_SEND_DISABLED")
	}

	// 与 Node 版 recipientFromRule/recipientFromConfig 一致：接收人只来自应用/规则配置，
	// 调用方传入的 toUser/touser 被忽略，不能扩大或改变接收范围。
	_ = customToUser
	toUser := target.ToUser
	if target.TargetType == "rule" {
		if target.IsAll {
			toUser = "@all"
		}
	} else if strings.TrimSpace(toUser) == "" {
		toUser = "@all"
	}

	if err := validateSendPayload(msgType, message, extraData); err != nil {
		return nil, err
	}

	// 与 Node 版一致：force=true 跳过去重缓存与并发合并；safe 原样透传企业微信（默认 0）。
	force := false
	if b, ok := extraData["force"].(bool); ok && b {
		force = true
	}
	keyData := make(map[string]any, len(extraData))
	for k, v := range extraData {
		if k != "force" {
			keyData[k] = v
		}
	}
	keyData["safe"] = safeFromAny(extraData["safe"])
	dedupKey := buildSendDedupKey(code, msgType, toUser, message, keyData)

	var inflight *inflightSendEntry
	if !force {
		n.mu.Lock()
		now := n.nowFunc()
		if cached, ok := n.sendResultCache[dedupKey]; ok {
			if cached.expiresAt > now {
				n.mu.Unlock()
				return withSendFlag(cached.res, "cached"), nil
			}
			delete(n.sendResultCache, dedupKey)
		}
		if existing, ok := n.inflightSends[dedupKey]; ok && existing.expiresAt > now {
			n.mu.Unlock()
			<-existing.done
			if existing.err != nil {
				return nil, existing.err
			}
			return withSendFlag(existing.res, "merged"), nil
		}
		ttl := int64(n.cfg.SendDedupTTLMs)
		if ttl <= 0 {
			ttl = 30000
		}
		inflight = &inflightSendEntry{
			done:      make(chan struct{}),
			expiresAt: now + ttl,
		}
		n.inflightSends[dedupKey] = inflight
		n.mu.Unlock()

		defer func() {
			n.mu.Lock()
			if n.inflightSends[dedupKey] == inflight {
				delete(n.inflightSends, dedupKey)
			}
			n.mu.Unlock()
			close(inflight.done)
		}()
	}

	res, sendErr := n.executeSendNotification(target, toUser, msgType, message, extraData)
	if inflight != nil {
		inflight.res = res
		inflight.err = sendErr
	}
	if sendErr == nil && n.cfg.SendDedupTTLMs > 0 {
		n.mu.Lock()
		n.sendResultCache[dedupKey] = cachedSendEntry{res: res, expiresAt: n.nowFunc() + int64(n.cfg.SendDedupTTLMs)}
		n.mu.Unlock()
	}
	return res, sendErr
}

// safeFromAny 解析 safe 参数：数字/数字字符串原样取整，true 视为 1，其余为 0。
func safeFromAny(v any) int {
	switch t := v.(type) {
	case json.Number:
		if n, err := strconv.Atoi(t.String()); err == nil {
			return n
		}
		if f, err := t.Float64(); err == nil {
			return int(f)
		}
	case float64:
		return int(t)
	case int:
		return t
	case bool:
		if t {
			return 1
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return 0
}

// withSendFlag 复制发送结果并在企业微信返回体（response）上标记 cached/merged，
// 对应 Node 版 { ...result, cached: true } / { ...result, merged: true }。
func withSendFlag(res map[string]any, flag string) map[string]any {
	out := make(map[string]any, len(res)+1)
	for k, v := range res {
		out[k] = v
	}
	respMap := map[string]any{}
	if raw, err := json.Marshal(res["response"]); err == nil {
		_ = json.Unmarshal(raw, &respMap)
	}
	respMap[flag] = true
	out["response"] = respMap
	out[flag] = true
	return out
}
func validateSendPayload(msgType, message string, extraData map[string]any) error {
	switch msgType {
	case "text", "markdown":
		if strings.TrimSpace(message) == "" {
			return NewError("消息内容是必填项", 400, "INVALID_INPUT")
		}
	case "textcard":
		card := extractMap(extraData, "textcard")
		if len(card) == 0 && extraData != nil {
			card = extraData
		}
		if strings.TrimSpace(stringFromMap(card, "title")) == "" ||
			strings.TrimSpace(stringFromMap(card, "description")) == "" ||
			strings.TrimSpace(stringFromMap(card, "url")) == "" {
			return NewError("文本卡片消息需要 title、description 和 url 参数", 400, "INVALID_INPUT")
		}
	case "news":
		articles := extractMapSlice(extraData, "articles")
		if len(articles) == 0 {
			return NewError("图文消息需要 articles 数组参数", 400, "INVALID_INPUT")
		}
		for _, a := range articles {
			if strings.TrimSpace(stringFromMap(a, "title")) == "" || strings.TrimSpace(stringFromMap(a, "url")) == "" {
				return NewError("每篇图文需要 title 和 url 参数", 400, "INVALID_INPUT")
			}
		}
	case "image":
		if strings.TrimSpace(stringFromMap(extraData, "media_id")) == "" &&
			strings.TrimSpace(stringFromMap(extraData, "image_base64")) == "" {
			return NewError("图片消息需要 media_id 或 image_base64 参数", 400, "INVALID_INPUT")
		}
	case "file":
		if strings.TrimSpace(stringFromMap(extraData, "media_id")) == "" &&
			strings.TrimSpace(stringFromMap(extraData, "file_base64")) == "" {
			return NewError("文件消息需要 media_id 或 file_base64 参数", 400, "INVALID_INPUT")
		}
	default:
		return NewError("不支持的消息类型: "+msgType, 400, "INVALID_INPUT")
	}
	return nil
}

func (n *Notifier) executeSendNotification(target *NotificationTarget, toUser, msgType, message string, extraData map[string]any) (map[string]any, error) {
	if err := n.checkWechatRateBackoff(target.CorpID, target.AgentID); err != nil {
		return nil, err
	}

	quotaRes, err := n.checkAndReserveRecipientQuota(target.CorpID, target.AgentID, toUser)
	if err != nil {
		return nil, err
	}

	safe := safeFromAny(extraData["safe"])
	var sendResult *wechat.SendResult
	var sendErr error

	switch msgType {
	case "markdown":
		sendResult, sendErr = n.wechat.SendMarkdownMessage(target.CorpID, target.CorpSecret, target.AgentID, message, toUser, safe)
	case "textcard":
		card := extractMap(extraData, "textcard")
		if len(card) == 0 && extraData != nil {
			card = extraData
		}
		sendResult, sendErr = n.wechat.SendTextCardMessage(target.CorpID, target.CorpSecret, target.AgentID, card, toUser, safe)
	case "news":
		articles := extractMapSlice(extraData, "articles")
		sendResult, sendErr = n.wechat.SendNewsMessage(target.CorpID, target.CorpSecret, target.AgentID, articles, toUser, safe)
	case "image":
		mediaID := strings.TrimSpace(stringFromMap(extraData, "media_id"))
		if mediaID == "" {
			b64Data := dataURLPrefixRegex.ReplaceAllString(stringFromMap(extraData, "image_base64"), "")
			buf, decErr := base64.StdEncoding.DecodeString(b64Data)
			if decErr != nil {
				n.rollbackQuotaReservation(quotaRes)
				return nil, NewError("图片 base64 解码失败", 400, "INVALID_INPUT")
			}
			fname := stringFromMap(extraData, "filename")
			if fname == "" {
				fname = "image.png"
			}
			upRes, upErr := n.wechat.UploadMedia(target.CorpID, target.CorpSecret, "image", buf, fname, "image/png")
			if upErr != nil {
				sendErr = upErr
			} else {
				mediaID = upRes.MediaID
			}
		}
		if sendErr == nil {
			sendResult, sendErr = n.wechat.SendImageMessage(target.CorpID, target.CorpSecret, target.AgentID, mediaID, toUser, safe)
		}
	case "file":
		mediaID := strings.TrimSpace(stringFromMap(extraData, "media_id"))
		if mediaID == "" {
			b64Data := dataURLPrefixRegex.ReplaceAllString(stringFromMap(extraData, "file_base64"), "")
			buf, decErr := base64.StdEncoding.DecodeString(b64Data)
			if decErr != nil {
				n.rollbackQuotaReservation(quotaRes)
				return nil, NewError("文件 base64 解码失败", 400, "INVALID_INPUT")
			}
			fname := stringFromMap(extraData, "filename")
			if fname == "" {
				fname = "file.bin"
			}
			upRes, upErr := n.wechat.UploadMedia(target.CorpID, target.CorpSecret, "file", buf, fname, "application/octet-stream")
			if upErr != nil {
				sendErr = upErr
			} else {
				mediaID = upRes.MediaID
			}
		}
		if sendErr == nil {
			sendResult, sendErr = n.wechat.SendFileMessage(target.CorpID, target.CorpSecret, target.AgentID, mediaID, toUser, safe)
		}
	default:
		sendResult, sendErr = n.wechat.SendTextMessage(target.CorpID, target.CorpSecret, target.AgentID, message, toUser, safe)
	}

	if sendErr != nil {
		n.rollbackQuotaReservation(quotaRes)
		var wxErr *wechat.WechatError
		if errors.As(sendErr, &wxErr) && (wxErr.IsRateLimit || wxErr.WechatErrCode == 45009) {
			n.markWechatRateBackoff(target.CorpID, target.AgentID)
		}
		return nil, wrapWeChatSendError(sendErr)
	}

	return map[string]any{
		"success":    true,
		"msgId":      sendResult.MsgID,
		"message":    "通知发送成功",
		"response":   sendResult,
		"targetType": target.TargetType,
		"ruleName":   target.RuleName,
	}, nil
}

func (n *Notifier) checkWechatRateBackoff(corpID, agentID string) error {
	appKey := fmt.Sprintf("%s:%s", corpID, agentID)
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.nowFunc()
	until, exists := n.wechatBackoffUntil[appKey]
	if !exists {
		return nil
	}
	if until <= now {
		delete(n.wechatBackoffUntil, appKey)
		return nil
	}
	retrySec := int(math.Ceil(float64(until-now) / 1000.0))
	if retrySec < 1 {
		retrySec = 1
	}
	return NewError(
		fmt.Sprintf("企业微信接口触发限流冷却中（45009），请在 %d 秒后重试", retrySec),
		429,
		"WECHAT_BACKOFF",
	)
}

func (n *Notifier) markWechatRateBackoff(corpID, agentID string) {
	appKey := fmt.Sprintf("%s:%s", corpID, agentID)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.wechatBackoffUntil[appKey] = n.nowFunc() + int64(n.cfg.WechatRateBackoffMs)
}

func getLocalDayKey(tsMs int64) string {
	t := time.UnixMilli(tsMs)
	return fmt.Sprintf("%04d-%02d-%02d", t.Year(), int(t.Month()), t.Day())
}

func (n *Notifier) checkAndReserveRecipientQuota(corpID, agentID, toUser string) (*quotaReservation, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := n.nowFunc()
	minuteCutoff := now - 60*1000
	hourCutoff := now - 60*60*1000
	appKey := fmt.Sprintf("%s:%s", corpID, agentID)

	rawUsers := strings.Split(toUser, "|")
	seen := make(map[string]bool)
	var users []string
	for _, u := range rawUsers {
		trimmed := strings.TrimSpace(u)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			users = append(users, trimmed)
		}
	}
	if len(users) == 0 {
		users = []string{"@all"}
	}

	personCount := len(users)
	for _, u := range users {
		if u == "@all" {
			personCount = 1
			if n.cfg.WechatAccountLimit > 1 {
				personCount = n.cfg.WechatAccountLimit
			}
			break
		}
	}

	dayKey := getLocalDayKey(now)
	enforceDaily := n.cfg.WechatAppDailyPersonLimit > 0
	if enforceDaily {
		dc, ok := n.appDailyPersonCounter[appKey]
		if !ok || dc.dayKey != dayKey {
			dc = &dailyCounterEntry{dayKey: dayKey, count: 0}
			n.appDailyPersonCounter[appKey] = dc
		}
		if dc.count+personCount > n.cfg.WechatAppDailyPersonLimit {
			return nil, NewError(
				fmt.Sprintf("已达到应用单日主动发送人次上限（%d 人次/天），请明日再试或调整 WECHAT_APP_DAILY_PERSON_LIMIT", n.cfg.WechatAppDailyPersonLimit),
				429,
				"QUOTA_EXCEEDED",
			)
		}
	}

	reservation := make([]quotaReservationItem, 0, len(users))
	for _, userID := range users {
		bucketKey := fmt.Sprintf("%s:%s", appKey, userID)
		w, ok := n.memberSendWindows[bucketKey]
		if !ok {
			w = &memberWindowEntry{}
			n.memberSendWindows[bucketKey] = w
		}

		minPruned := w.minuteTimestamps[:0]
		for _, t := range w.minuteTimestamps {
			if t > minuteCutoff {
				minPruned = append(minPruned, t)
			}
		}
		w.minuteTimestamps = minPruned

		hrPruned := w.hourTimestamps[:0]
		for _, t := range w.hourTimestamps {
			if t > hourCutoff {
				hrPruned = append(hrPruned, t)
			}
		}
		w.hourTimestamps = hrPruned

		if len(w.minuteTimestamps) >= n.cfg.WechatMemberMinuteLimit {
			return nil, NewError(
				fmt.Sprintf("接收人 %q 发送频率超限（单成员每分钟最多 %d 条）", userID, n.cfg.WechatMemberMinuteLimit),
				429,
				"QUOTA_EXCEEDED",
			)
		}
		if userID != "@all" && len(w.hourTimestamps) >= n.cfg.WechatMemberHourLimit {
			return nil, NewError(
				fmt.Sprintf("接收人 %q 发送频率超限（单成员每小时最多 %d 条）", userID, n.cfg.WechatMemberHourLimit),
				429,
				"QUOTA_EXCEEDED",
			)
		}
		reservation = append(reservation, quotaReservationItem{
			bucketKey: bucketKey,
			userID:    userID,
		})
	}

	for _, item := range reservation {
		w := n.memberSendWindows[item.bucketKey]
		w.minuteTimestamps = append(w.minuteTimestamps, now)
		w.hourTimestamps = append(w.hourTimestamps, now)
	}
	if enforceDaily {
		dc := n.appDailyPersonCounter[appKey]
		dc.count += personCount
	}

	return &quotaReservation{
		appKey:    appKey,
		now:       now,
		dayKey:    dayKey,
		enforced:  enforceDaily,
		reserved:  reservation,
		personCnt: personCount,
	}, nil
}

func (n *Notifier) rollbackQuotaReservation(res *quotaReservation) {
	if res == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, item := range res.reserved {
		w, ok := n.memberSendWindows[item.bucketKey]
		if !ok {
			continue
		}
		for i := len(w.minuteTimestamps) - 1; i >= 0; i-- {
			if w.minuteTimestamps[i] == res.now {
				w.minuteTimestamps = append(w.minuteTimestamps[:i], w.minuteTimestamps[i+1:]...)
				break
			}
		}
		for i := len(w.hourTimestamps) - 1; i >= 0; i-- {
			if w.hourTimestamps[i] == res.now {
				w.hourTimestamps = append(w.hourTimestamps[:i], w.hourTimestamps[i+1:]...)
				break
			}
		}
	}

	if res.enforced {
		if dc, ok := n.appDailyPersonCounter[res.appKey]; ok && dc.dayKey == res.dayKey {
			dc.count -= res.personCnt
			if dc.count < 0 {
				dc.count = 0
			}
		}
	}
}

func buildSendDedupKey(code, msgType, toUser, message string, extraData map[string]any) string {
	extraJSON, _ := json.Marshal(extraData)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s", strings.ToLower(strings.TrimSpace(code)), msgType, toUser, message, string(extraJSON))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (n *Notifier) GetVisibleUsers(code string) (map[string]any, error) {
	return n.GetVisibleUsersWithRefresh(code, false)
}

func (n *Notifier) GetVisibleUsersWithRefresh(code string, forceRefresh bool) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("代码是必填项", 400, "INVALID_INPUT")
	}
	cfg, err := n.getConfigByCodeCached(code)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	}
	if !cfg.IsCompleted {
		return nil, NewError("配置尚未完成，请先完成企业微信配置", 400, "CONFIG_INCOMPLETE")
	}

	buildResponse := func(users []wechat.VisibleUser, cached bool) map[string]any {
		currentList := normalizeRecipientList(cfg.ToUser)
		visibleSet := make(map[string]bool, len(users))
		for _, u := range users {
			visibleSet[u.UserID] = true
		}
		orphanList := make([]string, 0)
		for _, id := range currentList {
			if id != "@all" && !visibleSet[id] {
				orphanList = append(orphanList, id)
			}
		}
		out := map[string]any{
			"success": true,
			"users":   users,
			"current": currentList,
			"orphan":  orphanList,
		}
		if cached {
			out["cached"] = true
		}
		return out
	}

	normCode := strings.ToLower(cfg.Code)
	if !forceRefresh {
		n.mu.Lock()
		now := n.nowFunc()
		if cached, ok := n.memberCache[normCode]; ok && cached.expiresAt > now {
			n.mu.Unlock()
			return buildResponse(cached.users, true), nil
		}
		n.mu.Unlock()
	}

	plainMap, err := n.decryptWithLazyMigration(cfg.Code, []encryptedFieldSpec{
		{col: "corp_id", value: cfg.CorpID},
		{col: "corp_secret", value: cfg.CorpSecret},
	})
	if err != nil {
		return nil, err
	}
	res := n.wechat.GetVisibleUsers(plainMap["corp_id"], plainMap["corp_secret"], cfg.AgentID)
	if !res.Success {
		return nil, errors.New(res.Error)
	}

	n.mu.Lock()
	n.memberCache[normCode] = cachedMemberEntry{
		users:     res.Users,
		expiresAt: n.nowFunc() + int64(n.cfg.MemberCacheTTLMs),
	}
	n.mu.Unlock()

	return buildResponse(res.Users, false), nil
}

func (n *Notifier) validateCallbackTimestamp(timestamp string) error {
	tsClean := strings.TrimSpace(timestamp)
	if !callbackDigitsRegex.MatchString(tsClean) {
		return NewError("回调 timestamp 参数格式无效", 400, "INVALID_INPUT")
	}
	tsNum, err := strconv.ParseInt(tsClean, 10, 64)
	if err != nil {
		return NewError("回调 timestamp 参数格式无效", 400, "INVALID_INPUT")
	}
	tsMs := tsNum
	if tsNum < 1e12 {
		tsMs = tsNum * 1000
	}
	n.mu.Lock()
	now := n.nowFunc()
	n.mu.Unlock()
	tolMs := int64(n.cfg.CallbackTimestampToleranceSec) * 1000
	if int64(math.Abs(float64(now-tsMs))) > tolMs {
		return NewError("回调请求时间戳已过期或超出允许的时间窗口", 400, "INVALID_INPUT")
	}
	return nil
}

func (n *Notifier) isAndMarkCallbackReplay(code, nonce, msgID string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := n.nowFunc()
	ttlMs := int64(n.cfg.CallbackNonceTTLMs)
	hardLimit := n.cfg.CallbackNonceHardLimit

	pruneCallbackList(n.callbackNonceOrder, n.callbackNonceItems, now)
	pruneCallbackList(n.callbackMsgIDOrder, n.callbackMsgIDItems, now)

	nonceKey := ""
	if nonce != "" {
		nonceKey = fmt.Sprintf("%s:%s", code, nonce)
		if elem, ok := n.callbackNonceItems[nonceKey]; ok {
			entry := elem.Value.(*callbackReplayEntry)
			if entry.expiresAt > now {
				return true
			}
			n.callbackNonceOrder.Remove(elem)
			delete(n.callbackNonceItems, nonceKey)
		}
	}

	msgKey := ""
	if msgID != "" {
		msgKey = fmt.Sprintf("%s:%s", code, msgID)
		if elem, ok := n.callbackMsgIDItems[msgKey]; ok {
			entry := elem.Value.(*callbackReplayEntry)
			if entry.expiresAt > now {
				return true
			}
			n.callbackMsgIDOrder.Remove(elem)
			delete(n.callbackMsgIDItems, msgKey)
		}
	}

	if nonceKey != "" {
		for n.callbackNonceOrder.Len() >= hardLimit && hardLimit > 0 {
			oldest := n.callbackNonceOrder.Front()
			if oldest == nil {
				break
			}
			entry := oldest.Value.(*callbackReplayEntry)
			n.callbackNonceOrder.Remove(oldest)
			delete(n.callbackNonceItems, entry.key)
		}
		elem := n.callbackNonceOrder.PushBack(&callbackReplayEntry{
			key:       nonceKey,
			expiresAt: now + ttlMs,
		})
		n.callbackNonceItems[nonceKey] = elem
	}

	if msgKey != "" {
		for n.callbackMsgIDOrder.Len() >= hardLimit && hardLimit > 0 {
			oldest := n.callbackMsgIDOrder.Front()
			if oldest == nil {
				break
			}
			entry := oldest.Value.(*callbackReplayEntry)
			n.callbackMsgIDOrder.Remove(oldest)
			delete(n.callbackMsgIDItems, entry.key)
		}
		elem := n.callbackMsgIDOrder.PushBack(&callbackReplayEntry{
			key:       msgKey,
			expiresAt: now + ttlMs,
		})
		n.callbackMsgIDItems[msgKey] = elem
	}

	return false
}

func (n *Notifier) VerifyCallbackURL(code, msgSignature, timestamp, nonce, echostr string) (string, error) {
	if code == "" || msgSignature == "" || timestamp == "" || nonce == "" || echostr == "" {
		return "", NewError("缺少必要的验证参数", 400, "INVALID_INPUT")
	}
	if err := n.validateCallbackTimestamp(timestamp); err != nil {
		return "", err
	}
	cfg, err := n.getConfigByCodeCached(code)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", NewError("无效的配置代码", 400, "CONFIG_NOT_FOUND")
	}

	specs := []encryptedFieldSpec{
		{col: "token", value: cfg.Token},
		{col: "aes_key", value: cfg.AESKey},
	}
	if cfg.CorpID != "" {
		specs = append(specs, encryptedFieldSpec{col: "corp_id", value: cfg.CorpID})
	}
	plainMap, err := n.decryptWithLazyMigration(cfg.Code, specs)
	if err != nil {
		return "", NewError("验证回调URL失败: "+err.Error(), 400, "INVALID_INPUT")
	}

	crypt, err := wxcrypt.NewWXBizMsgCrypt(plainMap["token"], plainMap["aes_key"], plainMap["corp_id"])
	if err != nil {
		return "", NewError("验证回调URL失败: "+err.Error(), 400, "INVALID_INPUT")
	}
	decryptedEcho, err := crypt.VerifyURL(msgSignature, timestamp, nonce, echostr)
	if err != nil {
		return "", NewError("验证回调URL失败: "+err.Error(), 400, "INVALID_INPUT")
	}

	if _, err := n.db.UpdateConfigurationFields(cfg.Code, map[string]any{"callback_configured": true}, nil); err == nil {
		n.ClearRuntimeCaches()
	}
	return decryptedEcho, nil
}

func (n *Notifier) HandleCallbackMessage(code, msgSignature, timestamp, nonce, xmlData string) (string, error) {
	if code == "" || msgSignature == "" || timestamp == "" || nonce == "" || xmlData == "" {
		return "", NewError("缺少必要的消息处理参数", 400, "INVALID_INPUT")
	}
	if err := n.validateCallbackTimestamp(timestamp); err != nil {
		return "", err
	}

	cfg, err := n.getConfigByCodeCached(code)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", NewError("无效的配置代码", 400, "CONFIG_NOT_FOUND")
	}

	specs := []encryptedFieldSpec{
		{col: "token", value: cfg.Token},
		{col: "aes_key", value: cfg.AESKey},
	}
	if cfg.CorpID != "" {
		specs = append(specs, encryptedFieldSpec{col: "corp_id", value: cfg.CorpID})
	}
	plainMap, err := n.decryptWithLazyMigration(cfg.Code, specs)
	if err != nil {
		return "", NewError("处理回调消息失败: "+err.Error(), 400, "INVALID_INPUT")
	}

	crypt, err := wxcrypt.NewWXBizMsgCrypt(plainMap["token"], plainMap["aes_key"], plainMap["corp_id"])
	if err != nil {
		return "", NewError("处理回调消息失败: "+err.Error(), 400, "INVALID_INPUT")
	}
	decryptedXML, err := crypt.DecryptMsg(msgSignature, timestamp, nonce, xmlData)
	if err != nil {
		return "", NewError("处理回调消息失败: "+err.Error(), 400, "INVALID_INPUT")
	}

	msgFields, err := wxcrypt.ParseXMLMessage(decryptedXML)
	if err != nil {
		return "", NewError("处理回调消息失败: "+err.Error(), 400, "INVALID_INPUT")
	}

	if n.isAndMarkCallbackReplay(cfg.Code, nonce, msgFields["MsgId"]) {
		return "", nil
	}

	if msgFields["MsgType"] == "text" && msgFields["Content"] != "" {
		replyXML := fmt.Sprintf(
			"<xml><ToUserName><![CDATA[%s]]></ToUserName><FromUserName><![CDATA[%s]]></FromUserName><CreateTime>%d</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[收到您的消息: %s]]></Content></xml>",
			msgFields["FromUserName"],
			msgFields["ToUserName"],
			time.Now().Unix(),
			msgFields["Content"],
		)
		encReply, err := crypt.EncryptMsg(replyXML, timestamp, nonce)
		if err != nil {
			return "", NewError("处理回调消息失败: "+err.Error(), 400, "INVALID_INPUT")
		}
		return encReply, nil
	}
	return "", nil
}

func extractMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	sub, _ := raw.(map[string]any)
	return sub
}

func extractMapSlice(m map[string]any, key string) []map[string]any {
	if m == nil {
		return nil
	}
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	switch s := raw.(type) {
	case []map[string]any:
		return s
	case []any:
		out := make([]map[string]any, 0, len(s))
		for _, item := range s {
			if sub, ok := item.(map[string]any); ok {
				out = append(out, sub)
			}
		}
		return out
	default:
		return nil
	}
}

// wrapWeChatSendError 与 Node 版 wrapWeChatError 对齐：将企业微信上游错误归一化为稳定业务码。
//   - 已是业务错误（*AppError）：原样返回
//   - 45009 / 频率限制：429 WECHAT_BACKOFF
//   - 凭证错误（40001/42001/40014/48002/60011 等）：400 WECHAT_CREDENTIAL_INVALID
//   - 其余网络/上游错误：502 WECHAT_UNAVAILABLE
func wrapWeChatSendError(err error) error {
	if err == nil {
		return nil
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	msg := err.Error()
	var wxErr *wechat.WechatError
	if errors.As(err, &wxErr) {
		if wxErr.IsRateLimit || wxErr.WechatErrCode == 45009 {
			return NewError(msg, 429, "WECHAT_BACKOFF")
		}
		switch wxErr.WechatErrCode {
		case 40001, 40014, 42001, 48002, 60011:
			return NewError("企业微信凭证无效或 AgentID 不匹配", 400, "WECHAT_CREDENTIAL_INVALID")
		}
	}
	if strings.Contains(msg, "40001") || strings.Contains(msg, "invalid credential") ||
		strings.Contains(msg, "48002") || strings.Contains(msg, "60011") ||
		strings.Contains(msg, "获取token失败") || strings.Contains(msg, "gettoken") {
		return NewError("企业微信凭证无效或 AgentID 不匹配", 400, "WECHAT_CREDENTIAL_INVALID")
	}
	return NewError("企业微信服务暂时不可用，请稍后重试", 502, "WECHAT_UNAVAILABLE")
}
