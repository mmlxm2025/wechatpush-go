package service

import (
	"container/list"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/crypto"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/notifyauth"
	"qywx-notifier-plus/internal/notifycode"
	"qywx-notifier-plus/internal/wechat"
	"qywx-notifier-plus/internal/wxcrypt"
)

type AppError struct {
	Message      string
	StatusCode   int
	Code         string
	ConflictCode string
	Details      any
}

func (e *AppError) Error() string {
	return e.Message
}

func NewError(message string, statusCode int, code string) *AppError {
	return &AppError{
		Message:    message,
		StatusCode: statusCode,
		Code:       code,
	}
}

type Capabilities struct {
	CanSendByCode      bool `json:"canSendByCode"`
	CanManageRules     bool `json:"canManageRules"`
	CanFetchMembers    bool `json:"canFetchMembers"`
	CanReceiveCallback bool `json:"canReceiveCallback"`
	CanEditCredentials bool `json:"canEditCredentials"`
	CanCompleteSetup   bool `json:"canCompleteSetup"`

	CanEdit           bool `json:"can_edit"`
	CanResume         bool `json:"can_resume"`
	CanPause          bool `json:"can_pause"`
	CanToggle         bool `json:"can_toggle"`
	CanManageRulesSnk bool `json:"can_manage_rules"`
	CanManageSecurity bool `json:"can_manage_security"`
	CanDelete         bool `json:"can_delete"`
}

var encodingAESKeyRegex = regexp.MustCompile(`^[A-Za-z0-9]{43}$`)

type LifecycleInfo struct {
	Status             string       `json:"status"`
	CallbackConfigured bool         `json:"callbackConfigured"`
	IsCompleted        bool         `json:"isCompleted"`
	Enabled            bool         `json:"enabled"`
	CodeSendEnabled    bool         `json:"code_send_enabled"`
	NotifyKeyEnabled   bool         `json:"notify_key_enabled"`
	Version            int          `json:"version"`
	Name               string       `json:"name"`
	Capabilities       Capabilities `json:"capabilities"`
}

func DeriveConfigurationLifecycle(cfg *database.ConfigRow) LifecycleInfo {
	if cfg == nil {
		return LifecycleInfo{
			Status: "unconfigured",
		}
	}
	hasCallback := cfg.Token != "" && cfg.AESKey != ""
	hasCredentials := cfg.CorpID != "" && cfg.CorpSecret != "" && cfg.AgentID != ""
	callbackVerified := cfg.CallbackConfigured
	isCompleted := cfg.IsCompleted && hasCredentials

	status := "partial"
	if !hasCredentials && !isCompleted {
		status = "draft"
	} else if isCompleted {
		status = "completed"
	}

	enabledBool := cfg.Enabled != 0
	codeSendEnabledBool := cfg.CodeSendEnabled != 0
	notifyKeyEnabled := strings.TrimSpace(cfg.NotifyKeyHash) != ""
	version := cfg.Version
	if version <= 0 {
		version = 1
	}

	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		if strings.TrimSpace(cfg.AgentID) != "" {
			name = "应用 " + strings.TrimSpace(cfg.AgentID)
		} else {
			prefix := cfg.Code
			if len(prefix) > 8 {
				prefix = prefix[:8]
			}
			name = "应用 " + prefix
		}
	}

	return LifecycleInfo{
		Status:             status,
		CallbackConfigured: callbackVerified,
		IsCompleted:        isCompleted,
		Enabled:            enabledBool,
		CodeSendEnabled:    codeSendEnabledBool,
		NotifyKeyEnabled:   notifyKeyEnabled,
		Version:            version,
		Name:               name,
		Capabilities: Capabilities{
			CanSendByCode:      isCompleted && enabledBool && codeSendEnabledBool,
			CanManageRules:     isCompleted,
			CanFetchMembers:    isCompleted,
			CanReceiveCallback: hasCallback,
			CanEditCredentials: hasCredentials || isCompleted,
			CanCompleteSetup:   !isCompleted,
			CanEdit:            isCompleted,
			CanResume:          !isCompleted,
			CanPause:           isCompleted && enabledBool,
			CanToggle:          isCompleted,
			CanManageRulesSnk:  isCompleted,
			CanManageSecurity:  isCompleted,
			CanDelete:          true,
		},
	}
}

type cachedConfigEntry struct {
	data      *database.ConfigRow
	expiresAt int64
}

type cachedRuleEntry struct {
	data      *database.RuleWithConfigRow
	expiresAt int64
}

type cachedMemberEntry struct {
	users     []wechat.VisibleUser
	expiresAt int64
}

// cachedSendEntry 对应 Node 版 sendResultCache：SEND_DEDUP_TTL_MS 内相同请求直接返回缓存结果。
type cachedSendEntry struct {
	res       map[string]any
	expiresAt int64
}

type inflightSendEntry struct {
	done      chan struct{}
	res       map[string]any
	err       error
	expiresAt int64
}

type memberWindowEntry struct {
	minuteTimestamps []int64
	hourTimestamps   []int64
}

type dailyCounterEntry struct {
	dayKey string
	count  int
}

type quotaReservationItem struct {
	bucketKey string
	userID    string
}

type quotaReservation struct {
	appKey    string
	now       int64
	dayKey    string
	enforced  bool
	reserved  []quotaReservationItem
	personCnt int
}

type callbackReplayEntry struct {
	key       string
	expiresAt int64
}

type Notifier struct {
	cfg    *config.Config
	db     *database.Database
	crypto *crypto.Service
	wechat *wechat.Service

	mu                    sync.Mutex
	configCache           map[string]cachedConfigEntry
	ruleCache             map[string]cachedRuleEntry
	memberCache           map[string]cachedMemberEntry
	inflightSends         map[string]*inflightSendEntry
	sendResultCache       map[string]cachedSendEntry
	memberSendWindows     map[string]*memberWindowEntry
	appDailyPersonCounter map[string]*dailyCounterEntry
	wechatBackoffUntil    map[string]int64

	callbackNonceOrder *list.List
	callbackNonceItems map[string]*list.Element
	callbackMsgIDOrder *list.List
	callbackMsgIDItems map[string]*list.Element

	nowFunc func() int64
}

func NewNotifier(cfg *config.Config, db *database.Database, cryptoSvc *crypto.Service, wechatSvc *wechat.Service) *Notifier {
	if cfg == nil {
		cfg = config.FromEnv()
	}
	return &Notifier{
		cfg:                   cfg,
		db:                    db,
		crypto:                cryptoSvc,
		wechat:                wechatSvc,
		configCache:           make(map[string]cachedConfigEntry),
		ruleCache:             make(map[string]cachedRuleEntry),
		memberCache:           make(map[string]cachedMemberEntry),
		inflightSends:         make(map[string]*inflightSendEntry),
		sendResultCache:       make(map[string]cachedSendEntry),
		memberSendWindows:     make(map[string]*memberWindowEntry),
		appDailyPersonCounter: make(map[string]*dailyCounterEntry),
		wechatBackoffUntil:    make(map[string]int64),
		callbackNonceOrder:    list.New(),
		callbackNonceItems:    make(map[string]*list.Element),
		callbackMsgIDOrder:    list.New(),
		callbackMsgIDItems:    make(map[string]*list.Element),
		nowFunc:               func() int64 { return time.Now().UnixMilli() },
	}
}

func (n *Notifier) SetNowFunc(fn func() int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nowFunc = fn
}

func (n *Notifier) DB() *database.Database {
	return n.db
}

func (n *Notifier) Crypto() *crypto.Service {
	return n.crypto
}

func (n *Notifier) WeChat() *wechat.Service {
	return n.wechat
}

func (n *Notifier) Init() error {
	if err := n.db.Init(); err != nil {
		return err
	}
	if _, err := n.MigrateLegacyCiphertexts(); err != nil {
		log.Printf("⚠️ 旧版密文自动迁移过程中出现告警: %v", err)
	}
	return nil
}

func (n *Notifier) ClearRuntimeCaches() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.configCache = make(map[string]cachedConfigEntry)
	n.ruleCache = make(map[string]cachedRuleEntry)
	n.memberCache = make(map[string]cachedMemberEntry)
	n.sendResultCache = make(map[string]cachedSendEntry)
}

func (n *Notifier) CleanupExpiredState() {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := n.nowFunc()
	for k, v := range n.configCache {
		if v.expiresAt <= now {
			delete(n.configCache, k)
		}
	}
	for k, v := range n.ruleCache {
		if v.expiresAt <= now {
			delete(n.ruleCache, k)
		}
	}
	for k, v := range n.memberCache {
		if v.expiresAt <= now {
			delete(n.memberCache, k)
		}
	}
	for k, v := range n.sendResultCache {
		if v.expiresAt <= now {
			delete(n.sendResultCache, k)
		}
	}
	for k, v := range n.inflightSends {
		if v.expiresAt <= now {
			delete(n.inflightSends, k)
		}
	}
	for k, until := range n.wechatBackoffUntil {
		if until <= now {
			delete(n.wechatBackoffUntil, k)
		}
	}
	pruneCallbackList(n.callbackNonceOrder, n.callbackNonceItems, now)
	pruneCallbackList(n.callbackMsgIDOrder, n.callbackMsgIDItems, now)
}

func pruneCallbackList(order *list.List, items map[string]*list.Element, now int64) {
	for elem := order.Front(); elem != nil; {
		next := elem.Next()
		entry := elem.Value.(*callbackReplayEntry)
		if entry.expiresAt <= now {
			order.Remove(elem)
			delete(items, entry.key)
		} else {
			break
		}
		elem = next
	}
}

// MigrateLegacyCiphertexts 启动时扫描并升级旧版 AES-CBC 密文为 AES-256-GCM
func (n *Notifier) MigrateLegacyCiphertexts() (int, error) {
	rows, err := n.db.GetAllConfigurations()
	if err != nil {
		return 0, err
	}
	migratedCount := 0
	for _, row := range rows {
		updates := make(map[string]any)
		checkField := func(col, val string) error {
			if val == "" {
				return nil
			}
			cipherText, migrated, _, err := n.crypto.ReencryptIfLegacy(val)
			if err != nil {
				return err
			}
			if migrated {
				updates[col] = cipherText
			}
			return nil
		}
		if err := checkField("corp_id", row.CorpID); err != nil {
			continue
		}
		if err := checkField("corp_secret", row.CorpSecret); err != nil {
			continue
		}
		if err := checkField("token", row.Token); err != nil {
			continue
		}
		if err := checkField("aes_key", row.AESKey); err != nil {
			continue
		}
		if len(updates) > 0 {
			if _, err := n.db.UpdateConfigurationFields(row.Code, updates, nil); err == nil {
				migratedCount++
			}
		}
	}
	if migratedCount > 0 {
		n.ClearRuntimeCaches()
	}
	return migratedCount, nil
}

type encryptedFieldSpec struct {
	col   string
	value string
}

func (n *Notifier) decryptWithLazyMigration(code string, specs []encryptedFieldSpec) (map[string]string, error) {
	plainMap := make(map[string]string, len(specs))
	expectedOld := make(map[string]string)
	newEnc := make(map[string]string)

	for _, sp := range specs {
		if sp.value == "" {
			plainMap[sp.col] = ""
			continue
		}
		cipherText, migrated, plainText, err := n.crypto.ReencryptIfLegacy(sp.value)
		if err != nil {
			return nil, err
		}
		plainMap[sp.col] = plainText
		if migrated {
			expectedOld[sp.col] = sp.value
			newEnc[sp.col] = cipherText
		}
	}

	if len(newEnc) > 0 && code != "" {
		if updated, err := n.db.ConditionalUpdateEncryptedFields(code, expectedOld, newEnc); err == nil && updated {
			n.ClearRuntimeCaches()
		}
	}
	return plainMap, nil
}

func RequireExpectedVersion(expectedVersion *int) (int, error) {
	if expectedVersion == nil {
		return 0, NewError("缺少版本号，请刷新后重试", 428, "APP_VERSION_REQUIRED")
	}
	if *expectedVersion <= 0 {
		return 0, NewError("版本号不合法", 400, "INVALID_INPUT")
	}
	return *expectedVersion, nil
}

func (n *Notifier) ValidateWeChatConfig(corpID, corpSecret, agentID string) wechat.ValidateResult {
	return n.wechat.ValidateCredentials(corpID, corpSecret, agentID)
}

func (n *Notifier) GenerateCallbackURL(baseURL, existingCode, name string) (map[string]any, error) {
	res, err := n.CreateCallbackConfiguration(existingCode, name)
	if err != nil {
		return nil, err
	}
	code := res["code"].(string)
	return map[string]any{
		"success":          true,
		"code":             code,
		"callbackUrl":      fmt.Sprintf("%s/api/callback/%s", strings.TrimRight(baseURL, "/"), code),
		"token":            res["token"],
		"encodingAESKey":   res["encodingAESKey"],
		"version":          res["version"],
		"lifecycle_status": "draft",
	}, nil
}

// GenerateCallbackFromPayload 支持前端向导 Step 1（corpid + callback_token + encoding_aes_key + draft_code/version）以及自动生成回调配置模式
func (n *Notifier) GenerateCallbackFromPayload(baseURL string, data map[string]any) (int, map[string]any, error) {
	corpid := strings.TrimSpace(firstNonEmptyString(data, "corpid", "corpId"))
	callbackToken := strings.TrimSpace(firstNonEmptyString(data, "callback_token", "token"))
	encodingAESKey := strings.TrimSpace(firstNonEmptyString(data, "encoding_aes_key", "encodingAESKey"))
	draftCode := strings.TrimSpace(firstNonEmptyString(data, "draft_code", "code"))
	name := strings.TrimSpace(firstNonEmptyString(data, "name", "description"))

	// 如果未传 corpid/callback_token/encoding_aes_key，回退到自动生成模式（兼容测试与快捷调用）
	if corpid == "" && callbackToken == "" && encodingAESKey == "" {
		res, err := n.GenerateCallbackURL(baseURL, draftCode, name)
		if err != nil {
			return 0, nil, err
		}
		return 200, res, nil
	}

	if corpid == "" || callbackToken == "" || encodingAESKey == "" {
		return 0, nil, NewError("必须填写 CorpID、Token 和 EncodingAESKey", 400, "INVALID_INPUT")
	}
	if !encodingAESKeyRegex.MatchString(encodingAESKey) {
		return 0, nil, NewError("EncodingAESKey 必须为 43 位字母数字字符", 400, "INVALID_INPUT")
	}

	encryptedCorpID, err := n.crypto.Encrypt(corpid)
	if err != nil {
		return 0, nil, err
	}
	encryptedToken, err := n.crypto.Encrypt(callbackToken)
	if err != nil {
		return 0, nil, err
	}
	encryptedAESKey, err := n.crypto.Encrypt(encodingAESKey)
	if err != nil {
		return 0, nil, err
	}

	if draftCode != "" {
		var expectedVerPtr *int
		if rawVer, hasVer := data["version"]; hasVer && rawVer != nil && strings.TrimSpace(fmt.Sprintf("%v", rawVer)) != "" {
			v, ok := parsePositiveIntValue(rawVer)
			if !ok {
				appErr := NewError("草稿版本号不合法", 400, "INVALID_INPUT")
				appErr.Details = map[string]any{"field": "version"}
				return 0, nil, appErr
			}
			expectedVerPtr = &v
		} else {
			return 0, nil, NewError("缺少草稿版本号，请刷新后重试", 428, "APP_VERSION_REQUIRED")
		}

		reuseRes, err := n.db.UpdateDraftCallbackWithVersion(draftCode, encryptedCorpID, encryptedToken, encryptedAESKey, expectedVerPtr, corpid, n.crypto.Decrypt)
		if err != nil {
			var dbErr *database.DBError
			if errors.As(err, &dbErr) {
				switch dbErr.ReuseCause {
				case "not_found":
					return 0, nil, NewError("草稿不存在，请重新生成", 404, "APP_NOT_FOUND")
				case "corpid_mismatch":
					return 0, nil, NewError("草稿与当前填写的企业不匹配", 409, "APP_DRAFT_MISMATCH")
				case "already_completed":
					return 0, nil, NewError("该应用已完成配置，请前往编辑页修改回调", 409, "APP_ALREADY_COMPLETED")
				case "version_conflict":
					appErr := NewError("草稿已在其他页面更新，请刷新后重试", 409, "APP_VERSION_CONFLICT")
					if verNum, ok := dbErr.Details.(int); ok {
						appErr.Details = map[string]any{"version": verNum}
					}
					return 0, nil, appErr
				}
			}
			return 0, nil, err
		}
		n.ClearRuntimeCaches()
		return 200, map[string]any{
			"success":          true,
			"code":             reuseRes.Code,
			"callbackUrl":      "/api/callback/" + reuseRes.Code,
			"token":            callbackToken,
			"encodingAESKey":   encodingAESKey,
			"version":          reuseRes.Version,
			"lifecycle_status": "draft",
		}, nil
	}

	existingDraft, err := n.db.FindIncompleteDraftByCorpID(corpid, n.crypto.Decrypt)
	if err != nil {
		return 0, nil, err
	}
	if existingDraft != nil {
		appErr := NewError("该企业下已有未完成的应用草稿，请继续完成或先删除草稿", 409, "APP_DRAFT_EXISTS")
		appErr.Details = map[string]any{"existing_code": existingDraft.Code}
		return 0, nil, appErr
	}

	var savedCode string
	for attempt := 0; attempt < 5; attempt++ {
		candidateCode := notifycode.GenerateNotifyCode()
		draftName := name
		if draftName == "" {
			draftName = "应用 " + candidateCode[:8]
		}
		_, err := n.db.CreateDraftCallbackAtomic(database.DraftCallbackParams{
			Code:               candidateCode,
			CorpID:             encryptedCorpID,
			Token:              encryptedToken,
			AESKey:             encryptedAESKey,
			CallbackConfigured: true,
			Name:               draftName,
			Enabled:            1,
			CodeSendEnabled:    1,
		})
		if err != nil {
			var dbErr *database.DBError
			if errors.As(err, &dbErr) && dbErr.CreateCause == "notify_code_conflict" {
				continue
			}
			return 0, nil, fmt.Errorf("创建回调配置失败: %w", err)
		}
		savedCode = candidateCode
		break
	}
	if savedCode == "" {
		return 0, nil, NewError("生成唯一应用 Code 失败，请稍后重试", 503, "APP_CODE_GENERATION_FAILED")
	}

	n.ClearRuntimeCaches()
	return 201, map[string]any{
		"success":          true,
		"code":             savedCode,
		"callbackUrl":      "/api/callback/" + savedCode,
		"token":            callbackToken,
		"encodingAESKey":   encodingAESKey,
		"version":          1,
		"lifecycle_status": "draft",
	}, nil
}

// CreateCallbackConfiguration 创建或复用回调草稿（修复 BUG-02：捕获 notify_code_conflict 并最多重试 5 次）
func (n *Notifier) CreateCallbackConfiguration(existingCode, name string) (map[string]any, error) {
	token, encodingAESKey := wxcrypt.GenerateCallbackConfig()
	encryptedToken, err := n.crypto.Encrypt(token)
	if err != nil {
		return nil, fmt.Errorf("创建回调配置失败: %w", err)
	}
	encryptedAESKey, err := n.crypto.Encrypt(encodingAESKey)
	if err != nil {
		return nil, fmt.Errorf("创建回调配置失败: %w", err)
	}

	trimmedExisting := strings.TrimSpace(existingCode)
	if trimmedExisting != "" {
		reuseRes, err := n.db.ReuseDraftCallbackAtomic(trimmedExisting, encryptedToken, encryptedAESKey)
		if err != nil {
			var dbErr *database.DBError
			if errors.As(err, &dbErr) {
				if dbErr.ReuseCause == "not_found" {
					return nil, NewError("指定的草稿 code 不存在，请重新生成回调配置", 404, "CONFIG_NOT_FOUND")
				}
				if dbErr.ReuseCause == "already_completed" {
					return nil, NewError("仅允许复用尚未完成配置的草稿", 409, "CONFIG_ALREADY_COMPLETED")
				}
			}
			return nil, fmt.Errorf("创建回调配置失败: %w", err)
		}
		n.ClearRuntimeCaches()
		return map[string]any{
			"code":           reuseRes.Code,
			"token":          token,
			"encodingAESKey": encodingAESKey,
			"version":        reuseRes.Version,
		}, nil
	}

	var savedCode string
	for attempt := 0; attempt < 5; attempt++ {
		candidateCode := notifycode.GenerateNotifyCode()
		draftName := strings.TrimSpace(name)
		if draftName == "" {
			draftName = "应用 " + candidateCode[:8]
		}
		_, err := n.db.CreateDraftCallbackAtomic(database.DraftCallbackParams{
			Code:            candidateCode,
			Token:           encryptedToken,
			AESKey:          encryptedAESKey,
			Name:            draftName,
			Enabled:         1,
			CodeSendEnabled: 1,
		})
		if err != nil {
			var dbErr *database.DBError
			if errors.As(err, &dbErr) && dbErr.CreateCause == "notify_code_conflict" {
				continue
			}
			return nil, fmt.Errorf("创建回调配置失败: %w", err)
		}
		savedCode = candidateCode
		break
	}

	if savedCode == "" {
		return nil, NewError("生成唯一应用 Code 失败，请稍后重试", 503, "APP_CODE_GENERATION_FAILED")
	}

	n.ClearRuntimeCaches()
	return map[string]any{
		"code":           savedCode,
		"token":          token,
		"encodingAESKey": encodingAESKey,
		"version":        1,
	}, nil
}

func (n *Notifier) CompleteConfiguration(code string, configData map[string]any) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}

	existing, err := n.db.GetConfigurationByCode(code)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, NewError("找不到对应的回调配置", 404, "APP_NOT_FOUND")
	}
	if existing.IsCompleted {
		return nil, NewError("该配置已完成初始化，请使用 PUT /api/configuration/:code 编辑", 409, "APP_ALREADY_COMPLETED")
	}

	if rawVer, hasVer := configData["version"]; hasVer && rawVer != nil && strings.TrimSpace(fmt.Sprintf("%v", rawVer)) != "" {
		v, ok := parsePositiveIntValue(rawVer)
		if !ok {
			appErr := NewError("草稿版本号不合法", 400, "INVALID_INPUT")
			appErr.Details = map[string]any{"field": "version"}
			return nil, appErr
		}
		if v != existing.Version {
			appErr := NewError("草稿已在其他页面更新，请刷新后重试", 409, "APP_VERSION_CONFLICT")
			appErr.Details = map[string]any{"version": existing.Version}
			return nil, appErr
		}
	}

	corpID := strings.TrimSpace(firstNonEmptyString(configData, "corpid", "corpId"))
	if corpID == "" && existing.CorpID != "" {
		if decCorp, decErr := n.crypto.Decrypt(existing.CorpID); decErr == nil {
			corpID = strings.TrimSpace(decCorp)
		}
	}
	corpSecret := strings.TrimSpace(firstNonEmptyString(configData, "corpsecret", "corpSecret"))
	agentID := strings.TrimSpace(firstNonEmptyString(configData, "agentid", "agentId"))
	toUser := normalizeRecipientString(configData["touser"], configData["toUser"], "@all")
	name := strings.TrimSpace(firstNonEmptyString(configData, "description", "name"))

	if corpID == "" || corpSecret == "" || agentID == "" {
		return nil, NewError("企业ID、应用Secret和AgentId都是必填项", 400, "INVALID_INPUT")
	}

	var notifyKeyHashPtr *string
	if rawNK, hasNK := configData["notifyKey"]; hasNK && rawNK != nil {
		nkStr, ok := rawNK.(string)
		if ok && strings.TrimSpace(nkStr) != "" {
			trimmedKey := strings.TrimSpace(nkStr)
			if len(trimmedKey) < 16 {
				return nil, NewError("通知鉴权密钥长度不能少于 16 位", 400, "INVALID_INPUT")
			}
			h := notifyauth.HashNotifyKey(trimmedKey)
			notifyKeyHashPtr = &h
		}
	}

	valRes := n.ValidateWeChatConfig(corpID, corpSecret, agentID)
	if !valRes.Valid {
		return nil, WeChatFailureError(valRes.Error, valRes.Unavailable)
	}

	encryptedCorpID, err := n.crypto.Encrypt(corpID)
	if err != nil {
		return nil, err
	}
	encryptedCorpSecret, err := n.crypto.Encrypt(corpSecret)
	if err != nil {
		return nil, err
	}

	resolvedName := name
	if resolvedName == "" {
		if strings.TrimSpace(valRes.AgentName) != "" {
			resolvedName = strings.TrimSpace(valRes.AgentName)
		} else if strings.TrimSpace(existing.Name) != "" {
			resolvedName = strings.TrimSpace(existing.Name)
		} else {
			resolvedName = "应用 " + agentID
		}
	}

	compRes, err := n.db.CompleteConfigurationAtomic(database.CompleteConfigParams{
		Code:          existing.Code,
		PlainCorpID:   corpID,
		PlainAgentID:  agentID,
		CorpID:        encryptedCorpID,
		CorpSecret:    encryptedCorpSecret,
		AgentID:       agentID,
		ToUser:        toUser,
		Name:          resolvedName,
		NotifyKeyHash: notifyKeyHashPtr,
	}, n.crypto.Decrypt)
	if err != nil {
		var dbErr *database.DBError
		if errors.As(err, &dbErr) {
			switch dbErr.CompleteCause {
			case "not_found":
				return nil, NewError("找不到对应的回调配置", 404, "APP_NOT_FOUND")
			case "already_completed":
				return nil, NewError("该配置已完成初始化，请使用 PUT /api/configuration/:code 编辑", 409, "APP_ALREADY_COMPLETED")
			case "identity_conflict":
				appErr := NewError("该企业下此 AgentID 已创建过应用，请直接编辑现有应用", 409, "APP_IDENTITY_CONFLICT")
				if conflictRow, ok := dbErr.Details.(*database.ConfigRow); ok && conflictRow != nil {
					appErr.ConflictCode = conflictRow.Code
					appErr.Details = map[string]any{"existing_code": conflictRow.Code}
				}
				return nil, appErr
			}
		}
		return nil, err
	}

	n.ClearRuntimeCaches()
	nkConfigured := strings.TrimSpace(existing.NotifyKeyHash) != ""
	if notifyKeyHashPtr != nil {
		nkConfigured = *notifyKeyHashPtr != ""
	}

	// BUG-07 修复：返回数据库规范 code
	return map[string]any{
		"success":             true,
		"code":                compRes.Code,
		"apiUrl":              "/api/notify/" + compRes.Code,
		"callbackUrl":         "/api/callback/" + compRes.Code,
		"agentName":           valRes.AgentName,
		"notifyKeyConfigured": nkConfigured,
		"notify_key_enabled":  nkConfigured,
		"version":             compRes.Version,
		"lifecycle_status":    "active",
		"message":             "企业微信配置完成",
	}, nil
}

// CreateConfiguration 直接创建已完成应用配置（修复 BUG-01：仅当原子写入成功时赋值 savedCode 并清理运行时缓存）
func (n *Notifier) CreateConfiguration(configData map[string]any) (map[string]any, error) {
	corpID := strings.TrimSpace(firstNonEmptyString(configData, "corpid", "corpId"))
	corpSecret := strings.TrimSpace(firstNonEmptyString(configData, "corpsecret", "corpSecret"))
	agentID := strings.TrimSpace(firstNonEmptyString(configData, "agentid", "agentId"))
	toUser := normalizeRecipientString(configData["touser"], configData["toUser"], "@all")
	name := strings.TrimSpace(firstNonEmptyString(configData, "description", "name"))
	token := strings.TrimSpace(firstNonEmptyString(configData, "callback_token", "token"))
	encodingAESKey := strings.TrimSpace(firstNonEmptyString(configData, "encoding_aes_key", "encodingAESKey"))

	if corpID == "" || corpSecret == "" || agentID == "" {
		return nil, NewError("企业ID、应用Secret和AgentId都是必填项", 400, "INVALID_INPUT")
	}

	callbackConfigured := token != "" && encodingAESKey != ""
	if v, ok := boolFromMap(configData, "callback_enabled"); ok {
		callbackConfigured = v
	}

	notifyKeyHash := ""
	if rawNK, hasNK := configData["notifyKey"]; hasNK && rawNK != nil {
		if nkStr, ok := rawNK.(string); ok && strings.TrimSpace(nkStr) != "" {
			trimmedKey := strings.TrimSpace(nkStr)
			if len(trimmedKey) < 16 {
				return nil, NewError("通知鉴权密钥长度不能少于 16 位", 400, "INVALID_INPUT")
			}
			notifyKeyHash = notifyauth.HashNotifyKey(trimmedKey)
		}
	}

	valRes := n.ValidateWeChatConfig(corpID, corpSecret, agentID)
	if !valRes.Valid {
		return nil, WeChatFailureError(valRes.Error, valRes.Unavailable)
	}

	if token == "" || encodingAESKey == "" {
		genTok, genAES := wxcrypt.GenerateCallbackConfig()
		if token == "" {
			token = genTok
		}
		if encodingAESKey == "" {
			encodingAESKey = genAES
		}
	}

	encryptedCorpID, err := n.crypto.Encrypt(corpID)
	if err != nil {
		return nil, err
	}
	encryptedCorpSecret, err := n.crypto.Encrypt(corpSecret)
	if err != nil {
		return nil, err
	}
	encryptedToken, err := n.crypto.Encrypt(token)
	if err != nil {
		return nil, err
	}
	encryptedAESKey, err := n.crypto.Encrypt(encodingAESKey)
	if err != nil {
		return nil, err
	}

	resolvedName := name
	if resolvedName == "" {
		if strings.TrimSpace(valRes.AgentName) != "" {
			resolvedName = strings.TrimSpace(valRes.AgentName)
		} else {
			resolvedName = "应用 " + agentID
		}
	}

	enabledInt := 1
	if v, ok := boolFromMap(configData, "enabled"); ok && !v {
		enabledInt = 0
	} else if v, ok := boolFromMap(configData, "app_enabled"); ok && !v {
		enabledInt = 0
	}
	codeSendInt := 1
	if v, ok := boolFromMap(configData, "code_send_enabled"); ok && !v {
		codeSendInt = 0
	}

	// BUG-01 修复：使用 savedCode 记录真正写入成功的 code，避免 5 次冲突后仍非空而误返回 201
	var savedCode string
	for attempt := 0; attempt < 5; attempt++ {
		candidateCode := notifycode.GenerateNotifyCode()
		_, err := n.db.CreateConfigurationAtomic(database.CreateConfigParams{
			Code:               candidateCode,
			PlainCorpID:        corpID,
			PlainAgentID:       agentID,
			CorpID:             encryptedCorpID,
			CorpSecret:         encryptedCorpSecret,
			AgentID:            agentID,
			ToUser:             toUser,
			Token:              encryptedToken,
			AESKey:             encryptedAESKey,
			CallbackConfigured: callbackConfigured,
			IsCompleted:        true,
			NotifyKeyHash:      notifyKeyHash,
			Name:               resolvedName,
			Enabled:            enabledInt,
			CodeSendEnabled:    codeSendInt,
		}, n.crypto.Decrypt)
		if err != nil {
			var dbErr *database.DBError
			if errors.As(err, &dbErr) {
				if dbErr.CreateCause == "identity_conflict" {
					appErr := NewError("同一企业下该 AgentId 已存在配置", 409, "APP_IDENTITY_CONFLICT")
					if conflictRow, ok := dbErr.Details.(*database.ConfigRow); ok && conflictRow != nil {
						appErr.ConflictCode = conflictRow.Code
						appErr.Details = map[string]any{"existing_code": conflictRow.Code}
					}
					return nil, appErr
				}
				if dbErr.CreateCause == "notify_code_conflict" {
					continue
				}
			}
			return nil, err
		}
		savedCode = candidateCode
		break
	}

	if savedCode == "" {
		return nil, NewError("生成唯一应用 Code 失败，请稍后重试", 503, "APP_CODE_GENERATION_FAILED")
	}

	// BUG-01 修复：成功后清理运行时缓存
	n.ClearRuntimeCaches()

	return map[string]any{
		"success":             true,
		"code":                savedCode,
		"apiUrl":              "/api/notify/" + savedCode,
		"callbackUrl":         "/api/callback/" + savedCode,
		"name":                resolvedName,
		"agentName":           valRes.AgentName,
		"notifyKeyConfigured": notifyKeyHash != "",
		"notify_key_enabled":  notifyKeyHash != "",
		"version":             1,
		"message":             "应用创建成功",
	}, nil
}

func (n *Notifier) SetAppEnabled(code string, enabled bool, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	res, err := n.db.UpdateConfigurationFields(code, map[string]any{"enabled": enabled}, &ver)
	if err != nil {
		return nil, err
	}
	if res.Outcome == "not_found" {
		return nil, NewError("配置不存在", 404, "APP_NOT_FOUND")
	}
	if res.Outcome == "version_conflict" {
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	msg := "已暂停该应用的消息发送"
	if enabled {
		msg = "已启用该应用的消息发送"
	}
	return map[string]any{
		"success":     true,
		"code":        res.Code,
		"enabled":     enabled,
		"app_enabled": enabled,
		"version":     res.NewVersion,
		"message":     msg,
	}, nil
}

func (n *Notifier) DeleteConfiguration(code string, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	existing, err := n.db.GetConfigurationByCode(code)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, NewError("配置不存在", 404, "APP_NOT_FOUND")
	}

	delRes, err := n.db.DeleteConfigurationWithCascade(existing.Code, ver)
	if err != nil {
		return nil, err
	}
	if delRes.Outcome == "not_found" {
		return nil, NewError("配置不存在", 404, "APP_NOT_FOUND")
	}
	if delRes.Outcome == "version_conflict" {
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}

	if existing.CorpID != "" && existing.CorpSecret != "" {
		corpID, err1 := n.crypto.Decrypt(existing.CorpID)
		corpSecret, err2 := n.crypto.Decrypt(existing.CorpSecret)
		if err1 == nil && err2 == nil {
			n.wechat.DeleteAccessToken(corpID, corpSecret)
		}
	}
	n.ClearRuntimeCaches()

	return map[string]any{
		"success":                true,
		"code":                   existing.Code,
		"configurations_deleted": 1,
		"rules_deleted":          delRes.DeletedRules,
		"deletedRules":           delRes.DeletedRules,
		"message":                "应用及关联转发规则已删除",
	}, nil
}

func (n *Notifier) UpdateConfiguration(code string, fields map[string]any, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}

	if hasNonNullKey(fields, "corpId") || hasNonNullKey(fields, "corp_id") || hasNonNullKey(fields, "corpid") {
		return nil, NewError("企业（CorpID）不可修改，请新建应用", 400, "CORPID_IMMUTABLE")
	}
	if hasKey(fields, "notifyKey") {
		return nil, NewError("请通过专用接口管理通知密钥（POST/DELETE /api/configuration/:code/notify-key）", 400, "NOTIFY_KEY_ENDPOINT_REQUIRED")
	}

	configRow, err := n.db.GetConfigurationByCode(code)
	if err != nil {
		return nil, err
	}
	if configRow == nil {
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	}
	if configRow.Version != ver {
		appErr := NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
		appErr.Details = map[string]any{"version": configRow.Version}
		return nil, appErr
	}

	var currentCorpID, currentCorpSecret string
	if configRow.CorpID != "" {
		currentCorpID, _ = n.crypto.Decrypt(configRow.CorpID)
	}
	if configRow.CorpSecret != "" {
		currentCorpSecret, _ = n.crypto.Decrypt(configRow.CorpSecret)
	}
	currentAgentID := configRow.AgentID

	updates := make(map[string]any)
	rawSecret := strings.TrimSpace(firstNonEmptyString(fields, "corpsecret", "corpSecret"))
	rawAgent := strings.TrimSpace(firstNonEmptyString(fields, "agentid", "agentId"))

	nextCorpID := currentCorpID
	nextCorpSecret := currentCorpSecret
	if rawSecret != "" {
		nextCorpSecret = rawSecret
	}
	nextAgentID := currentAgentID
	if rawAgent != "" {
		nextAgentID = rawAgent
	}

	secretChanged := rawSecret != "" && rawSecret != currentCorpSecret
	agentChanged := rawAgent != "" && rawAgent != strings.TrimSpace(currentAgentID)
	credentialChanged := secretChanged || agentChanged

	if credentialChanged {
		if nextCorpID == "" || nextCorpSecret == "" || nextAgentID == "" {
			return nil, NewError("该配置尚未填写完整凭据，请先通过初始化流程完成配置", 400, "CONFIG_INCOMPLETE")
		}
		valRes := n.ValidateWeChatConfig(nextCorpID, nextCorpSecret, nextAgentID)
		if !valRes.Valid {
			return nil, WeChatFailureError(valRes.Error, valRes.Unavailable)
		}
		if secretChanged {
			encSec, err := n.crypto.Encrypt(nextCorpSecret)
			if err != nil {
				return nil, err
			}
			updates["corp_secret"] = encSec
		}
		if agentChanged {
			updates["agent_id"] = nextAgentID
		}
		updates["is_completed"] = true
	}

	if hasNonNullKey(fields, "touser") || hasNonNullKey(fields, "toUser") {
		tu := normalizeRecipientString(fields["touser"], fields["toUser"], "")
		if tu == "" {
			tu = "@all"
		}
		updates["to_user"] = tu
	}
	if hasNonNullKey(fields, "name") {
		trimmedName := strings.TrimSpace(stringFromMap(fields, "name"))
		if trimmedName == "" {
			return nil, NewError("应用名称不能为空", 400, "INVALID_INPUT")
		}
		updates["name"] = trimmedName
	} else if hasNonNullKey(fields, "description") {
		updates["name"] = strings.TrimSpace(stringFromMap(fields, "description"))
	}
	if v, ok := boolFromMap(fields, "callback_enabled"); ok {
		updates["callback_configured"] = v
	}
	if hasNonNullKey(fields, "callback_token") || hasNonNullKey(fields, "token") {
		rawTok := strings.TrimSpace(firstNonEmptyString(fields, "callback_token", "token"))
		if rawTok != "" {
			encTok, err := n.crypto.Encrypt(rawTok)
			if err != nil {
				return nil, err
			}
			updates["token"] = encTok
		}
	}
	if hasNonNullKey(fields, "encoding_aes_key") || hasNonNullKey(fields, "encodingAESKey") {
		rawAES := strings.TrimSpace(firstNonEmptyString(fields, "encoding_aes_key", "encodingAESKey"))
		if rawAES != "" {
			if !encodingAESKeyRegex.MatchString(rawAES) {
				return nil, NewError("EncodingAESKey 必须为 43 位字母数字字符", 400, "INVALID_INPUT")
			}
			encAES, err := n.crypto.Encrypt(rawAES)
			if err != nil {
				return nil, err
			}
			updates["aes_key"] = encAES
		}
	}
	if v, ok := boolFromMap(fields, "enabled"); ok {
		updates["enabled"] = v
	} else if v, ok := boolFromMap(fields, "app_enabled"); ok {
		updates["enabled"] = v
	}
	if v, ok := boolFromMap(fields, "code_send_enabled"); ok {
		updates["code_send_enabled"] = v
	}

	if len(updates) == 0 {
		return nil, NewError("未提供任何需要更新的字段", 400, "INVALID_INPUT")
	}

	res, err := n.db.UpdateConfigFieldsWithAuditAtomic(configRow.Code, updates, ver, n.crypto.Decrypt)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case "not_found":
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	case "version_conflict":
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	case "identity_conflict":
		appErr := NewError("同一企业下该 AgentId 已存在配置", 409, "APP_IDENTITY_CONFLICT")
		if res.Conflict != nil {
			appErr.ConflictCode = res.Conflict.Code
			appErr.Details = map[string]any{"existing_code": res.Conflict.Code}
		}
		return nil, appErr
	}

	if secretChanged && currentCorpID != "" && currentCorpSecret != "" {
		n.wechat.DeleteAccessToken(currentCorpID, currentCorpSecret)
	}
	n.ClearRuntimeCaches()

	return map[string]any{
		"success":     true,
		"code":        configRow.Code,
		"version":     res.NewVersion,
		"callbackUrl": "/api/callback/" + configRow.Code,
		"message":     "配置已更新",
	}, nil
}

func (n *Notifier) RegenerateNotifyKey(code string, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	plainKey := notifyauth.GenerateNotifyKey()
	notifyKeyHash := notifyauth.HashNotifyKey(plainKey)

	res, err := n.db.UpdateConfigurationFields(code, map[string]any{"notify_key_hash": notifyKeyHash}, &ver)
	if err != nil {
		return nil, err
	}
	if res.Outcome == "not_found" {
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	}
	if res.Outcome == "version_conflict" {
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	return map[string]any{
		"success":            true,
		"code":               res.Code,
		"notifyKey":          plainKey,
		"notify_key":         plainKey,
		"notify_key_enabled": true,
		"version":            res.NewVersion,
		"message":            "新的通知鉴权密钥已生成，请妥善保存（仅本次展示明文）",
	}, nil
}

func (n *Notifier) RevokeNotifyKey(code string, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	res, err := n.db.UpdateConfigurationFields(code, map[string]any{"notify_key_hash": ""}, &ver)
	if err != nil {
		return nil, err
	}
	if res.Outcome == "not_found" {
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	}
	if res.Outcome == "version_conflict" {
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	return map[string]any{
		"success":            true,
		"code":               res.Code,
		"notify_key_enabled": false,
		"version":            res.NewVersion,
		"message":            "已撤销通知密钥",
	}, nil
}

func (n *Notifier) SetCodeSendEnabled(code string, enabled bool, expectedVersion *int) (map[string]any, error) {
	if strings.TrimSpace(code) == "" {
		return nil, NewError("缺少配置代码", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	res, err := n.db.UpdateConfigurationFields(code, map[string]any{"code_send_enabled": enabled}, &ver)
	if err != nil {
		return nil, err
	}
	if res.Outcome == "not_found" {
		return nil, NewError("配置不存在", 404, "CONFIG_NOT_FOUND")
	}
	if res.Outcome == "version_conflict" {
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	msg := "已关闭应用级 Code 直接发送"
	if enabled {
		msg = "已开启应用级 Code 直接发送"
	}
	return map[string]any{
		"success":           true,
		"code":              res.Code,
		"code_send_enabled": enabled,
		"version":           res.NewVersion,
		"message":           msg,
	}, nil
}

func (n *Notifier) GetConfigurationSummary(code string) (map[string]any, error) {
	var cfg *database.ConfigRow
	var err error
	if strings.TrimSpace(code) != "" {
		cfg, err = n.db.GetConfigurationByCode(code)
	} else {
		cfg, err = n.db.GetPrimaryConfiguration()
	}
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	var plainCorpID string
	if cfg.CorpID != "" {
		if plainMap, err := n.decryptWithLazyMigration(cfg.Code, []encryptedFieldSpec{
			{col: "corp_id", value: cfg.CorpID},
		}); err == nil {
			plainCorpID = plainMap["corp_id"]
		}
	}

	maskedCorpID := ""
	if len(plainCorpID) > 6 {
		maskedCorpID = plainCorpID[:4] + "****" + plainCorpID[len(plainCorpID)-2:]
	} else if plainCorpID != "" {
		maskedCorpID = "****"
	}

	lc := DeriveConfigurationLifecycle(cfg)
	toUser := cfg.ToUser
	if toUser == "" {
		toUser = "@all"
	}

	var touserList []string
	if lc.IsCompleted {
		touserList = normalizeRecipientList(cfg.ToUser)
	} else {
		touserList = []string{}
	}

	var agentIDVal any
	if strings.TrimSpace(cfg.AgentID) != "" {
		if num, err := strconv.Atoi(strings.TrimSpace(cfg.AgentID)); err == nil && num > 0 {
			agentIDVal = num
		}
	}

	rules, _ := n.db.GetNotificationRulesByConfigCode(cfg.Code)
	ruleCount := len(rules)
	enabledRuleCount := 0
	for _, r := range rules {
		if r.Enabled != 0 {
			enabledRuleCount++
		}
	}

	warnings := []string{}
	if lc.IsCompleted && plainCorpID != "" && strings.TrimSpace(cfg.AgentID) != "" {
		if dup, err := n.db.CheckIdentityConflict(plainCorpID, cfg.AgentID, cfg.Code, n.crypto.Decrypt); err == nil && dup != nil {
			warnings = append(warnings, "duplicate_identity")
		}
	}

	lifecycleStatus := "draft"
	if lc.IsCompleted {
		if lc.Enabled {
			lifecycleStatus = "active"
		} else {
			lifecycleStatus = "paused"
		}
	}

	callbackEnabled := cfg.CallbackConfigured || (!lc.IsCompleted && cfg.Token != "" && cfg.AESKey != "")

	return map[string]any{
		"id":                          cfg.ID,
		"code":                        cfg.Code,
		"name":                        lc.Name,
		"description":                 cfg.Name,
		"enabled":                     lc.Enabled,
		"app_enabled":                 lc.Enabled,
		"code_send_enabled":           lc.CodeSendEnabled,
		"version":                     lc.Version,
		"corpid":                      plainCorpID,
		"corpId":                      maskedCorpID,
		"corpSecretConfigured":        cfg.CorpSecret != "",
		"corpsecret_configured":       cfg.CorpSecret != "",
		"callback_token_configured":   cfg.Token != "",
		"encoding_aes_key_configured": cfg.AESKey != "",
		"agentId":                     cfg.AgentID,
		"agentid":                     agentIDVal,
		"toUser":                      toUser,
		"touser":                      touserList,
		"recipient_count":             len(touserList),
		"rule_count":                  ruleCount,
		"rules_count":                 ruleCount,
		"enabled_rule_count":          enabledRuleCount,
		"status":                      lc.Status,
		"lifecycle_status":            lifecycleStatus,
		"warnings":                    warnings,
		"callbackConfigured":          lc.CallbackConfigured,
		"callback_enabled":            callbackEnabled,
		"isCompleted":                 lc.IsCompleted,
		"completed":                   lc.IsCompleted,
		"notifyKeyConfigured":         lc.NotifyKeyEnabled,
		"notify_key_enabled":          lc.NotifyKeyEnabled,
		"capabilities":                lc.Capabilities,
		"callbackUrl":                 "/api/callback/" + cfg.Code,
		"callbackUrlPath":             "/api/callback/" + cfg.Code,
		"apiUrl":                      "/api/notify/" + cfg.Code,
		"notifyUrlPath":               "/api/notify/" + cfg.Code,
		"created_at":                  cfg.CreatedAt,
		"createdAt":                   cfg.CreatedAt,
		"updated_at":                  cfg.UpdatedAt,
		"updatedAt":                   cfg.UpdatedAt,
	}, nil
}

func (n *Notifier) GetAllConfigurationsSummary() ([]map[string]any, error) {
	rows, err := n.db.GetAllConfigurations()
	if err != nil {
		return nil, err
	}
	results := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		summary, err := n.GetConfigurationSummary(r.Code)
		if err != nil || summary == nil {
			continue
		}
		results = append(results, summary)
	}
	return results, nil
}

func (n *Notifier) CheckRuleAPICodeAvailability(rawAPICode string, excludeRuleID *int) (map[string]any, error) {
	normalized := notifycode.NormalizeRuleAPICode(rawAPICode)
	if !notifycode.IsValidRuleAPICode(normalized) {
		return map[string]any{
			"available":  false,
			"api_code":   normalized,
			"normalized": normalized,
			"reason":     "invalid_format",
			"message":    "自定义推送码需为 3~64 位小写字母、数字、连字符(-)或下划线(_)，且首尾为字母或数字",
		}, nil
	}
	available, reason, err := n.db.CheckNotifyCodeAvailability(normalized, excludeRuleID)
	if err != nil {
		return nil, err
	}
	messageMap := map[string]string{
		"ok":                      "推送码可用",
		"conflicts_with_app_code": "不能与应用级 Code 相同",
		"already_in_use":          "该推送码已被其他规则占用",
		"retired":                 "该推送码曾被使用并已作废，为避免误路由不允许复用",
	}
	msg := messageMap[reason]
	if msg == "" {
		msg = "推送码不可用"
	}
	uiReason := reason
	switch reason {
	case "conflicts_with_app_code":
		uiReason = "configuration"
	case "already_in_use":
		uiReason = "rule"
	}
	return map[string]any{
		"available":  available,
		"api_code":   normalized,
		"normalized": normalized,
		"reason":     reason,
		"ui_reason":  uiReason,
		"message":    msg,
	}, nil
}

func (n *Notifier) assertValidAndAvailableCustomAPICode(rawAPICode string, excludeRuleID *int) (string, error) {
	check, err := n.CheckRuleAPICodeAvailability(rawAPICode, excludeRuleID)
	if err != nil {
		return "", err
	}
	avail, _ := check["available"].(bool)
	if !avail {
		reason, _ := check["reason"].(string)
		msg, _ := check["message"].(string)
		status := 409
		code := "RULE_API_CODE_CONFLICT"
		if reason == "invalid_format" {
			status = 400
			code = "RULE_API_CODE_INVALID"
		}
		return "", NewError(msg, status, code)
	}
	norm, _ := check["normalized"].(string)
	return norm, nil
}

func serializeRuleMap(r *database.RuleRow) map[string]any {
	if r == nil {
		return nil
	}
	est := r.EstimatedCount
	if est <= 0 {
		est = 1
	}
	return map[string]any{
		"id":              r.ID,
		"config_code":     r.ConfigCode,
		"api_code":        r.APICode,
		"apiUrl":          "/api/notify/" + r.APICode,
		"name":            r.Name,
		"to_user":         r.ToUser,
		"touser":          normalizeRecipientList(r.ToUser),
		"toparty":         normalizeRecipientList(r.ToParty),
		"totag":           normalizeRecipientList(r.ToTag),
		"is_all":          r.IsAll != 0,
		"estimated_count": est,
		"enabled":         r.Enabled != 0,
		"created_at":      r.CreatedAt,
		"updated_at":      r.UpdatedAt,
	}
}

func (n *Notifier) CreateNotificationRule(configCode, name, toUser string, expectedVersion *int, customAPICode string, enabled *bool) (map[string]any, error) {
	payload := map[string]any{
		"name":     name,
		"to_user":  toUser,
		"api_code": customAPICode,
	}
	if enabled != nil {
		payload["enabled"] = *enabled
	}
	return n.CreateNotificationRuleFromPayload(configCode, payload, expectedVersion)
}

func (n *Notifier) CreateNotificationRuleFromPayload(configCode string, payload map[string]any, expectedVersion *int) (map[string]any, error) {
	name := strings.TrimSpace(stringFromMap(payload, "name"))
	isAllBool, _ := boolFromMap(payload, "is_all")
	toUser := normalizeRecipientString(payload["touser"], payload["to_user"], "")
	if toUser == "" {
		toUser = normalizeRecipientString(payload["toUser"], nil, "")
	}
	toParty := normalizeRecipientString(payload["toparty"], payload["to_party"], "")
	toTag := normalizeRecipientString(payload["totag"], payload["to_tag"], "")

	if strings.TrimSpace(configCode) == "" || name == "" {
		return nil, NewError("配置代码和规则名称都是必填项", 400, "INVALID_INPUT")
	}
	if !isAllBool && toUser == "" && toParty == "" && toTag == "" {
		return nil, NewError("请至少选择一个接收人、部门、标签或启用 @all", 400, "INVALID_INPUT")
	}
	if isAllBool && toUser == "" {
		toUser = "@all"
	}

	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}

	appRow, err := n.db.GetConfigurationByCode(configCode)
	if err != nil {
		return nil, err
	}
	if appRow == nil {
		return nil, NewError("找不到对应的配置", 404, "APP_NOT_FOUND")
	}
	if !appRow.IsCompleted {
		return nil, NewError("草稿应用尚未完成凭据配置，暂不可创建转发规则", 409, "APP_NOT_COMPLETED")
	}

	customAPICode := strings.TrimSpace(firstNonEmptyString(payload, "api_code", "apiCode"))
	hasCustom := customAPICode != ""
	var normalizedCustom string
	if hasCustom {
		normalizedCustom, err = n.assertValidAndAvailableCustomAPICode(customAPICode, nil)
		if err != nil {
			return nil, err
		}
	}

	enabledInt := 1
	if enBool, ok := boolFromMap(payload, "enabled"); ok && !enBool {
		enabledInt = 0
	}
	isAllInt := 0
	if isAllBool {
		isAllInt = 1
	}
	estCount := 1
	if rawEst, ok := payload["estimated_count"]; ok && rawEst != nil {
		if v, ok := parsePositiveIntValue(rawEst); ok {
			estCount = v
		}
	}

	maxAttempts := 5
	if hasCustom {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		apiCode := normalizedCustom
		if !hasCustom {
			apiCode = notifycode.GenerateNotifyCode()
			avail, _, err := n.db.CheckNotifyCodeAvailability(apiCode, nil)
			if err != nil {
				return nil, err
			}
			if !avail {
				continue
			}
		}

		res, err := n.db.CreateRuleFullWithVersionCheck(appRow.Code, ver, database.RuleWriteParams{
			Name:           name,
			ToUser:         toUser,
			ToParty:        toParty,
			ToTag:          toTag,
			IsAll:          isAllInt,
			EstimatedCount: estCount,
			APICode:        apiCode,
			Enabled:        enabledInt,
		})
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "NOTIFY_CODE_CONFLICT") || strings.Contains(msg, "UNIQUE constraint failed: notification_rules.api_code") {
				if hasCustom {
					return nil, NewError("该推送码已被占用或已作废，请更换其他推送码", 409, "RULE_API_CODE_CONFLICT")
				}
				continue
			}
			return nil, err
		}

		switch res.Outcome {
		case "not_found":
			return nil, NewError("找不到对应的配置", 404, "APP_NOT_FOUND")
		case "version_conflict":
			return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
		}

		n.ClearRuntimeCaches()
		return map[string]any{
			"success":     true,
			"id":          res.Rule.ID,
			"api_code":    res.Rule.APICode,
			"apiUrl":      "/api/notify/" + res.Rule.APICode,
			"rule":        serializeRuleMap(res.Rule),
			"version":     res.NewVersion,
			"app_version": res.NewVersion,
		}, nil
	}

	return nil, NewError("生成唯一规则推送码失败，请稍后重试", 503, "RULE_API_CODE_GENERATION_FAILED")
}

func (n *Notifier) GetNotificationRules(configCode string) ([]map[string]any, error) {
	if strings.TrimSpace(configCode) == "" {
		return nil, NewError("配置代码是必填项", 400, "INVALID_INPUT")
	}
	rules, err := n.db.GetNotificationRulesByConfigCode(configCode)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, serializeRuleMap(r))
	}
	return out, nil
}

func (n *Notifier) UpdateNotificationRule(ruleID int, name, toUser string, expectedVersion *int, customAPICode *string) (map[string]any, error) {
	payload := map[string]any{
		"name":    name,
		"to_user": toUser,
	}
	if customAPICode != nil {
		payload["api_code"] = *customAPICode
	}
	return n.UpdateNotificationRuleFromPayload(ruleID, payload, expectedVersion)
}

func (n *Notifier) UpdateNotificationRuleFromPayload(ruleID int, payload map[string]any, expectedVersion *int) (map[string]any, error) {
	name := strings.TrimSpace(stringFromMap(payload, "name"))
	isAllBool, _ := boolFromMap(payload, "is_all")
	toUser := normalizeRecipientString(payload["touser"], payload["to_user"], "")
	if toUser == "" {
		toUser = normalizeRecipientString(payload["toUser"], nil, "")
	}
	toParty := normalizeRecipientString(payload["toparty"], payload["to_party"], "")
	toTag := normalizeRecipientString(payload["totag"], payload["to_tag"], "")

	if ruleID <= 0 || name == "" {
		return nil, NewError("规则ID和名称都是必填项", 400, "INVALID_INPUT")
	}
	if !isAllBool && toUser == "" && toParty == "" && toTag == "" {
		return nil, NewError("请至少选择一个接收人、部门、标签或启用 @all", 400, "INVALID_INPUT")
	}
	if isAllBool && toUser == "" {
		toUser = "@all"
	}

	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}

	var normalizedCustomPtr *string
	rawCustom := strings.TrimSpace(firstNonEmptyString(payload, "api_code", "apiCode"))
	if rawCustom != "" {
		norm, err := n.assertValidAndAvailableCustomAPICode(rawCustom, &ruleID)
		if err != nil {
			return nil, err
		}
		normalizedCustomPtr = &norm
	}

	isAllInt := 0
	if isAllBool {
		isAllInt = 1
	}
	estCount := 1
	if rawEst, ok := payload["estimated_count"]; ok && rawEst != nil {
		if v, ok := parsePositiveIntValue(rawEst); ok {
			estCount = v
		}
	}

	res, err := n.db.UpdateRuleFullWithVersionCheck(ruleID, ver, database.RuleWriteParams{
		Name:           name,
		ToUser:         toUser,
		ToParty:        toParty,
		ToTag:          toTag,
		IsAll:          isAllInt,
		EstimatedCount: estCount,
	}, normalizedCustomPtr)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "NOTIFY_CODE_CONFLICT") || strings.Contains(msg, "UNIQUE constraint failed: notification_rules.api_code") {
			return nil, NewError("该推送码已被占用或已作废，请更换其他推送码", 409, "RULE_API_CODE_CONFLICT")
		}
		return nil, err
	}

	switch res.Outcome {
	case "rule_not_found", "not_found":
		return nil, NewError("找不到对应的规则", 404, "RULE_NOT_FOUND")
	case "version_conflict":
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}

	n.ClearRuntimeCaches()
	apiCodeChanged := strings.ToLower(res.Rule.APICode) != strings.ToLower(res.OldAPICode)
	return map[string]any{
		"success":          true,
		"id":               res.Rule.ID,
		"api_code":         res.Rule.APICode,
		"apiUrl":           "/api/notify/" + res.Rule.APICode,
		"api_code_changed": apiCodeChanged,
		"rule":             serializeRuleMap(res.Rule),
		"version":          res.NewVersion,
		"app_version":      res.NewVersion,
	}, nil
}

func (n *Notifier) DeleteNotificationRule(ruleID int, expectedVersion *int) (map[string]any, error) {
	if ruleID <= 0 {
		return nil, NewError("规则ID是必填项", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	res, err := n.db.DeleteRuleWithVersionCheck(ruleID, ver)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case "rule_not_found", "not_found":
		return nil, NewError("找不到对应的规则", 404, "RULE_NOT_FOUND")
	case "version_conflict":
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	return map[string]any{
		"success":     true,
		"id":          ruleID,
		"api_code":    res.OldAPICode,
		"version":     res.NewVersion,
		"app_version": res.NewVersion,
	}, nil
}

func (n *Notifier) RegenerateRuleAPICode(ruleID int, expectedVersion *int, customAPICode string) (map[string]any, error) {
	if ruleID <= 0 {
		return nil, NewError("规则ID是必填项", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}

	hasCustom := strings.TrimSpace(customAPICode) != ""
	var normalizedCustom string
	if hasCustom {
		normalizedCustom, err = n.assertValidAndAvailableCustomAPICode(customAPICode, &ruleID)
		if err != nil {
			return nil, err
		}
	}

	maxAttempts := 5
	if hasCustom {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		nextCode := normalizedCustom
		if !hasCustom {
			nextCode = notifycode.GenerateNotifyCode()
			avail, _, err := n.db.CheckNotifyCodeAvailability(nextCode, &ruleID)
			if err != nil {
				return nil, err
			}
			if !avail {
				continue
			}
		}

		res, err := n.db.RegenerateRuleWithVersionCheck(ruleID, ver, nextCode)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "NOTIFY_CODE_CONFLICT") || strings.Contains(msg, "UNIQUE constraint failed: notification_rules.api_code") {
				if hasCustom {
					return nil, NewError("该推送码已被占用或已作废，请更换其他推送码", 409, "RULE_API_CODE_CONFLICT")
				}
				continue
			}
			return nil, err
		}

		switch res.Outcome {
		case "rule_not_found", "not_found":
			return nil, NewError("找不到对应的规则", 404, "RULE_NOT_FOUND")
		case "version_conflict":
			return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
		}

		n.ClearRuntimeCaches()
		return map[string]any{
			"success":     true,
			"id":          ruleID,
			"api_code":    nextCode,
			"apiUrl":      "/api/notify/" + nextCode,
			"version":     res.NewVersion,
			"app_version": res.NewVersion,
		}, nil
	}

	return nil, NewError("生成唯一规则推送码失败，请稍后重试", 503, "RULE_API_CODE_GENERATION_FAILED")
}

func (n *Notifier) SetNotificationRuleEnabled(ruleID int, enabled bool, expectedVersion *int) (map[string]any, error) {
	if ruleID <= 0 {
		return nil, NewError("规则ID是必填项", 400, "INVALID_INPUT")
	}
	ver, err := RequireExpectedVersion(expectedVersion)
	if err != nil {
		return nil, err
	}
	res, err := n.db.SetRuleEnabledWithVersionCheck(ruleID, ver, enabled)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case "rule_not_found", "not_found":
		return nil, NewError("找不到对应的规则", 404, "RULE_NOT_FOUND")
	case "version_conflict":
		return nil, NewError("配置已被其他会话修改，请刷新后重试", 409, "APP_VERSION_CONFLICT")
	}
	n.ClearRuntimeCaches()
	return map[string]any{
		"success":     true,
		"id":          ruleID,
		"enabled":     enabled,
		"version":     res.NewVersion,
		"app_version": res.NewVersion,
	}, nil
}

func firstNonEmptyString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		s := strings.TrimSpace(stringFromMap(m, k))
		if s != "" {
			return s
		}
	}
	return ""
}

func parsePositiveIntValue(v any) (int, bool) {
	if v == nil {
		return 0, false
	}
	raw := strings.TrimSpace(fmt.Sprintf("%v", v))
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func normalizeRecipientList(raw any) []string {
	if raw == nil {
		return []string{}
	}
	var items []string
	switch v := raw.(type) {
	case string:
		items = strings.Split(v, "|")
	case []string:
		items = v
	case []any:
		for _, elem := range v {
			if elem != nil {
				items = append(items, fmt.Sprintf("%v", elem))
			}
		}
	default:
		items = strings.Split(fmt.Sprintf("%v", v), "|")
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(items))
	for _, item := range items {
		t := strings.TrimSpace(item)
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func normalizeRecipientString(primary, fallback any, defaultVal string) string {
	list := normalizeRecipientList(primary)
	if len(list) == 0 && fallback != nil {
		list = normalizeRecipientList(fallback)
	}
	if len(list) == 0 {
		return defaultVal
	}
	return strings.Join(list, "|")
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, exists := m[key]
	if !exists || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func boolFromMap(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	v, exists := m[key]
	if !exists || v == nil {
		return false, false
	}
	switch b := v.(type) {
	case bool:
		return b, true
	default:
		return false, false
	}
}

func hasKey(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	_, exists := m[key]
	return exists
}

func hasNonNullKey(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, exists := m[key]
	return exists && v != nil
}

// WeChatFailureError 与 Node 版 wrapWeChatError 一致：将企业微信校验/成员读取失败归一化。
//   - 网络/上游不可用，或非凭证类错误 → 502 WECHAT_UNAVAILABLE
//   - 凭证错误（40001/48002/60011/invalid credential/获取token失败）→ 400 WECHAT_CREDENTIAL_INVALID
//
// 对外消息固定，不回显上游原文（避免泄露请求 URL 等细节）。
func WeChatFailureError(errMsg string, unavailable bool) *AppError {
	if !unavailable {
		for _, k := range []string{"40001", "invalid credential", "48002", "60011", "获取token失败", "获取access_token失败", "gettoken"} {
			if strings.Contains(errMsg, k) {
				return NewError("企业微信凭证无效或 AgentID 不匹配", 400, "WECHAT_CREDENTIAL_INVALID")
			}
		}
	}
	return NewError("企业微信服务暂时不可用，请稍后重试", 502, "WECHAT_UNAVAILABLE")
}
