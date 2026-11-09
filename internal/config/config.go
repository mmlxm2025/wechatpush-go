package config

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var PlaceholderValues = map[string]struct{}{
	"default-key-for-development-only":       {},
	"change-this-to-a-random-32-char-string": {},
	"your-32-character-encryption-key-here":  {},
	"change-this-to-a-strong-password":       {},
	"your-secure-password":                   {},
}

var (
	hex64Regex    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	base6444Regex = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

type Config struct {
	Port                     int
	DBPath                   string
	EncryptionKey            string
	AdminUsername            string
	AdminPassword            string
	WechatAPIBase            string
	AllowCustomWechatAPIBase bool
	NodeEnv                  string
	TestInstanceID           string
	AppRevision              string
	AppVersion               string
	TrustProxy               string
	PublicDir                string
	ShutdownTimeoutMs        int
	CallbackMaxBodyBytes     int

	// 速率限制与防刷参数
	LoginRateWindowMs    int
	LoginRateMax         int
	NotifyRateWindowMs   int
	NotifyRateMax        int
	CallbackRateWindowMs int
	CallbackRateMax      int

	// 缓存与去重参数
	ConfigCacheTTLMs int
	MemberCacheTTLMs int
	SendDedupTTLMs   int

	// 企微限流配额与退避参数
	WechatMemberMinuteLimit   int
	WechatMemberHourLimit     int
	WechatAccountLimit        int
	WechatAppDailyPersonLimit int
	WechatRateBackoffMs       int
	WechatHTTPTimeoutMs       int
	WechatMaxResponseBytes    int
	WechatMaxRequestBytes     int
	SkipStartupValidation     bool

	// 回调与通知防重放参数
	CallbackTimestampToleranceSec int
	CallbackNonceTTLMs            int
	CallbackNonceHardLimit        int
	NotifyTimestampToleranceSec   int
	NotifyNonceTTLMs              int
	NotifyNonceHardLimit          int
}

// LoadDotEnv 加载 .env 文件（仅当环境变量尚未设置时注入，与 Node dotenv.config() 行为一致）
func LoadDotEnv(filePath string) error {
	if filePath == "" {
		filePath = ".env"
	}
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
	return scanner.Err()
}

func envOrDefault(key, def string) string {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return def
	}
	return val
}

func envIntOrDefault(key string, def int) int {
	val, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(val) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return def
	}
	return n
}

func envPositiveIntOrDefault(key string, def int) int {
	n := envIntOrDefault(key, def)
	if n <= 0 {
		return def
	}
	return n
}

func envNonNegativeIntOrDefault(key string, def int) int {
	val, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(val) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil || n < 0 {
		return def
	}
	return n
}

// FromEnv 从当前进程环境变量构建配置快照
func FromEnv() *Config {
	accountLimit := envNonNegativeIntOrDefault("WECHAT_ACCOUNT_LIMIT", 0)
	dailyDefault := 0
	if accountLimit > 0 {
		dailyDefault = accountLimit * 200
	}
	dailyPersonLimit := envNonNegativeIntOrDefault("WECHAT_APP_DAILY_PERSON_LIMIT", dailyDefault)

	shutdownTimeout := envIntOrDefault("SHUTDOWN_TIMEOUT_MS", 10000)
	if shutdownTimeout < 1000 || shutdownTimeout > 60000 {
		shutdownTimeout = 10000
	}

	callbackMaxBody := envPositiveIntOrDefault("CALLBACK_MAX_BODY_BYTES", 102400)

	return &Config{
		Port:                          envPositiveIntOrDefault("PORT", 3000),
		DBPath:                        envOrDefault("DB_PATH", "./database/notifier.db"),
		EncryptionKey:                 os.Getenv("ENCRYPTION_KEY"),
		AdminUsername:                 envOrDefault("ADMIN_USERNAME", "admin"),
		AdminPassword:                 os.Getenv("ADMIN_PASSWORD"),
		WechatAPIBase:                 envOrDefault("WECHAT_API_BASE", "https://qyapi.weixin.qq.com"),
		AllowCustomWechatAPIBase:      os.Getenv("WECHAT_ALLOW_CUSTOM_API_BASE") == "1",
		NodeEnv:                       envOrDefault("NODE_ENV", "production"),
		TestInstanceID:                os.Getenv("TEST_INSTANCE_ID"),
		AppRevision:                   envOrDefault("APP_REVISION", "release"),
		AppVersion:                    envOrDefault("APP_VERSION", "2.0.0"),
		TrustProxy:                    os.Getenv("TRUST_PROXY"),
		PublicDir:                     os.Getenv("PUBLIC_DIR"),
		ShutdownTimeoutMs:             shutdownTimeout,
		CallbackMaxBodyBytes:          callbackMaxBody,
		LoginRateWindowMs:             envPositiveIntOrDefault("LOGIN_RATE_WINDOW_MS", 5*60*1000),
		LoginRateMax:                  envPositiveIntOrDefault("LOGIN_RATE_MAX", 10),
		NotifyRateWindowMs:            envPositiveIntOrDefault("NOTIFY_RATE_WINDOW_MS", 60*1000),
		NotifyRateMax:                 envPositiveIntOrDefault("NOTIFY_RATE_MAX", 60),
		CallbackRateWindowMs:          envPositiveIntOrDefault("CALLBACK_RATE_WINDOW_MS", 60*1000),
		CallbackRateMax:               envPositiveIntOrDefault("CALLBACK_RATE_MAX", 120),
		ConfigCacheTTLMs:              envPositiveIntOrDefault("CONFIG_CACHE_TTL_MS", 60*1000),
		MemberCacheTTLMs:              envPositiveIntOrDefault("MEMBER_CACHE_TTL_MS", 5*60*1000),
		SendDedupTTLMs:                envPositiveIntOrDefault("SEND_DEDUP_TTL_MS", 30*1000),
		WechatMemberMinuteLimit:       envPositiveIntOrDefault("WECHAT_MEMBER_MINUTE_LIMIT", 30),
		WechatMemberHourLimit:         envPositiveIntOrDefault("WECHAT_MEMBER_HOUR_LIMIT", 1000),
		WechatAccountLimit:            accountLimit,
		WechatAppDailyPersonLimit:     dailyPersonLimit,
		WechatRateBackoffMs:           envPositiveIntOrDefault("WECHAT_RATE_BACKOFF_MS", 60*1000),
		WechatHTTPTimeoutMs:           envPositiveIntOrDefault("WECHAT_HTTP_TIMEOUT_MS", 10000),
		WechatMaxResponseBytes:        envPositiveIntOrDefault("WECHAT_MAX_RESPONSE_BYTES", 5*1024*1024),
		WechatMaxRequestBytes:         envPositiveIntOrDefault("WECHAT_MAX_REQUEST_BYTES", 5*1024*1024),
		SkipStartupValidation:         os.Getenv("SKIP_STARTUP_VALIDATION") == "1",
		CallbackTimestampToleranceSec: envPositiveIntOrDefault("CALLBACK_TIMESTAMP_TOLERANCE_SEC", 300),
		CallbackNonceTTLMs:            envPositiveIntOrDefault("CALLBACK_NONCE_TTL_MS", 10*60*1000),
		CallbackNonceHardLimit:        envPositiveIntOrDefault("CALLBACK_NONCE_HARD_LIMIT", 50000),
		NotifyTimestampToleranceSec:   envPositiveIntOrDefault("NOTIFY_TIMESTAMP_TOLERANCE_SEC", 300),
		NotifyNonceTTLMs:              envPositiveIntOrDefault("NOTIFY_NONCE_TTL_MS", 10*60*1000),
		NotifyNonceHardLimit:          envPositiveIntOrDefault("NOTIFY_NONCE_HARD_LIMIT", 10000),
	}
}

func isPlaceholder(value string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return false
	}
	_, exists := PlaceholderValues[trimmed]
	return exists
}

// DecodeEncryptionKey 解析并校验加密密钥：支持 32 字节原始字符、64 位 hex 或 44 位 base64
func DecodeEncryptionKey(rawKey string) ([]byte, error) {
	if rawKey == "" {
		return nil, errors.New("未设置 ENCRYPTION_KEY")
	}
	if isPlaceholder(rawKey) {
		return nil, errors.New("ENCRYPTION_KEY 使用了不安全的示例占位值，请生成高强度随机密钥")
	}

	trimmed := strings.TrimSpace(rawKey)

	if hex64Regex.MatchString(trimmed) {
		buf, err := hex.DecodeString(trimmed)
		if err == nil && len(buf) == 32 {
			return buf, nil
		}
	}

	if base6444Regex.MatchString(trimmed) {
		buf, err := base64.StdEncoding.DecodeString(trimmed)
		if err == nil && len(buf) == 32 {
			return buf, nil
		}
	}

	rawBuf := []byte(rawKey)
	if len(rawBuf) == 32 {
		return rawBuf, nil
	}

	return nil, errors.New("ENCRYPTION_KEY 必须解码为 32 字节（支持 32 字节原始字符、64 位 hex 或 44 位 base64）")
}

// ValidateRuntime 校验运行时配置，返回 errors 和 warnings 切片
func ValidateRuntime(cfg *Config) ([]string, []string) {
	if cfg == nil {
		cfg = FromEnv()
	}
	var errs []string
	var warnings []string

	if _, err := DecodeEncryptionKey(cfg.EncryptionKey); err != nil {
		errs = append(errs, err.Error())
	}

	if cfg.AdminPassword == "" {
		errs = append(errs, "ADMIN_PASSWORD 不能为空，请设置管理员登录密码")
	} else if isPlaceholder(cfg.AdminPassword) {
		errs = append(errs, "ADMIN_PASSWORD 使用了不安全的示例占位值，请设置高强度密码")
	} else if len(cfg.AdminPassword) < 8 {
		errs = append(errs, "ADMIN_PASSWORD 长度不能少于 8 位")
	}

	if strings.TrimSpace(cfg.AdminUsername) == "" {
		errs = append(errs, "ADMIN_USERNAME 不能为空")
	}

	parsedURL, err := url.Parse(cfg.WechatAPIBase)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		errs = append(errs, "WECHAT_API_BASE 必须是合法的 HTTP(S) URL")
	} else if cfg.NodeEnv == "production" && !cfg.AllowCustomWechatAPIBase {
		if parsedURL.Scheme != "https" {
			errs = append(errs, "生产环境下 WECHAT_API_BASE 必须使用 https 协议")
		}
		if parsedURL.Hostname() != "qyapi.weixin.qq.com" {
			errs = append(errs, "生产环境下 WECHAT_API_BASE 仅允许 qyapi.weixin.qq.com（如需自定义代理请显式设置 WECHAT_ALLOW_CUSTOM_API_BASE=1）")
		}
	}

	if cfg.TestInstanceID != "" {
		if len(strings.TrimSpace(cfg.TestInstanceID)) < 16 {
			errs = append(errs, "TEST_INSTANCE_ID 长度不能少于 16 位")
		}
	}

	if cfg.AdminUsername == "admin" && cfg.NodeEnv == "production" {
		warnings = append(warnings, "生产环境仍在使用默认管理员用户名 admin，建议修改 ADMIN_USERNAME")
	}

	return errs, warnings
}

// MustValidateRuntime 校验失败时返回聚合错误
func MustValidateRuntime(cfg *Config) error {
	errs, _ := ValidateRuntime(cfg)
	if len(errs) > 0 {
		return fmt.Errorf("启动前安全配置校验失败:\n - %s", strings.Join(errs, "\n - "))
	}
	return nil
}
