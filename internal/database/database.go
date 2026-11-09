package database

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

type DBError struct {
	Message       string
	Code          string
	StatusCode    int
	CreateCause   string
	ReuseCause    string
	CompleteCause string
	Details       any
}

func (e *DBError) Error() string {
	return e.Message
}

type ConfigRow struct {
	ID                 int
	Code               string
	CorpID             string
	CorpSecret         string
	AgentID            string
	ToUser             string
	Token              string
	AESKey             string
	CallbackConfigured bool
	IsCompleted        bool
	NotifyKeyHash      string
	Name               string
	Enabled            int
	CodeSendEnabled    int
	Version            int
	CreatedAt          string
	UpdatedAt          string
}

type RuleRow struct {
	ID             int    `json:"id"`
	ConfigCode     string `json:"config_code"`
	Name           string `json:"name"`
	ToUser         string `json:"to_user"`
	ToParty        string `json:"toparty"`
	ToTag          string `json:"totag"`
	IsAll          int    `json:"is_all"`
	EstimatedCount int    `json:"estimated_count"`
	APICode        string `json:"api_code"`
	Enabled        int    `json:"enabled"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type RuleWithConfigRow struct {
	RuleRow
	CorpID             string
	CorpSecret         string
	AgentID            string
	CallbackConfigured bool
	IsCompleted        bool
	NotifyKeyHash      string
	ConfigEnabled      int
	CodeSendEnabled    int
	ConfigName         string
	ConfigVersion      int
}

type NamespaceConflict struct {
	Type       string `json:"type"`
	NormCode   string `json:"normCode"`
	Count      int    `json:"count,omitempty"`
	Detail     string `json:"detail,omitempty"`
	RuleID     int    `json:"ruleId,omitempty"`
	RuleCode   string `json:"ruleCode,omitempty"`
	ConfigID   int    `json:"configId,omitempty"`
	ConfigCode string `json:"configCode,omitempty"`
}

type UpdateConfigResult struct {
	Outcome    string
	Changes    int
	NewVersion int
	Code       string
	Conflict   *ConfigRow
}

type DeleteConfigResult struct {
	Outcome      string
	DeletedRules int
}

type RuleVersionResult struct {
	Outcome    string
	NewVersion int
	ConfigCode string
	Rule       *RuleRow
	OldAPICode string
}

type queryExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

type Database struct {
	dbPath     string
	sqlDB      *sql.DB
	txMu       sync.Mutex
	opMu       sync.Mutex
	txOwnerGID int64
}

func curGID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	field := bytes.Fields(bytes.TrimPrefix(buf[:n], []byte("goroutine ")))[0]
	id, _ := strconv.ParseInt(string(field), 10, 64)
	return id
}

func New(dbPath string) *Database {
	if dbPath == "" {
		dbPath = "./database/notifier.db"
	}
	return &Database{
		dbPath: dbPath,
	}
}

func (d *Database) DBPath() string {
	return d.dbPath
}

func (d *Database) Init() error {
	d.txMu.Lock()
	defer d.txMu.Unlock()
	d.opMu.Lock()
	defer d.opMu.Unlock()

	if d.sqlDB != nil {
		return nil
	}

	if d.dbPath != ":memory:" && !strings.HasPrefix(d.dbPath, "file::memory:") {
		dir := filepath.Dir(d.dbPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("创建数据库目录失败: %w", err)
			}
		}
	}

	sqlDB, err := sql.Open("sqlite", d.dbPath)
	if err != nil {
		return fmt.Errorf("数据库连接失败: %w", err)
	}
	// 单连接串行模式：确保 PRAGMA 与事务在同一连接上严格串行执行
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	if _, err := sqlDB.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		_ = sqlDB.Close()
		return err
	}
	if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = sqlDB.Close()
		return err
	}

	d.sqlDB = sqlDB
	if err := d.createTablesLocked(); err != nil {
		_ = sqlDB.Close()
		d.sqlDB = nil
		return err
	}
	return nil
}

func (d *Database) Close() error {
	d.txMu.Lock()
	defer d.txMu.Unlock()
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.sqlDB == nil {
		return nil
	}
	err := d.sqlDB.Close()
	d.sqlDB = nil
	return err
}

// WithTransaction 在互斥锁保护下执行 BEGIN IMMEDIATE 独占事务，支持同协程事务重入且跨协程严格串行
func (d *Database) WithTransaction(fn func() error) error {
	gid := curGID()
	d.opMu.Lock()
	if d.txOwnerGID == gid && gid != 0 {
		// 同协程事务内重入：直接执行
		d.opMu.Unlock()
		return fn()
	}
	d.opMu.Unlock()

	d.txMu.Lock()
	defer d.txMu.Unlock()

	d.opMu.Lock()
	if d.sqlDB == nil {
		d.opMu.Unlock()
		return errors.New("数据库尚未初始化")
	}
	if _, err := d.sqlDB.Exec("BEGIN IMMEDIATE"); err != nil {
		d.opMu.Unlock()
		return err
	}
	d.txOwnerGID = gid
	d.opMu.Unlock()

	var fnErr error
	panicked := true
	defer func() {
		d.opMu.Lock()
		d.txOwnerGID = 0
		if panicked || fnErr != nil {
			_, _ = d.sqlDB.Exec("ROLLBACK")
		}
		d.opMu.Unlock()
	}()

	fnErr = fn()
	panicked = false
	if fnErr != nil {
		return fnErr
	}

	d.opMu.Lock()
	_, commitErr := d.sqlDB.Exec("COMMIT")
	if commitErr != nil {
		_, _ = d.sqlDB.Exec("ROLLBACK")
	}
	d.opMu.Unlock()
	return commitErr
}

func (d *Database) withLock(fn func() error) error {
	gid := curGID()
	d.opMu.Lock()
	if d.txOwnerGID == gid && gid != 0 {
		defer d.opMu.Unlock()
		if d.sqlDB == nil {
			return errors.New("数据库尚未初始化")
		}
		return fn()
	}
	d.opMu.Unlock()

	d.txMu.Lock()
	defer d.txMu.Unlock()
	d.opMu.Lock()
	defer d.opMu.Unlock()
	if d.sqlDB == nil {
		return errors.New("数据库尚未初始化")
	}
	return fn()
}

func (d *Database) RawExec(query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := d.withLock(func() error {
		var e error
		res, e = d.sqlDB.Exec(query, args...)
		return e
	})
	return res, err
}

func (d *Database) RawQuery(query string, args ...any) (*sql.Rows, error) {
	return d.sqlDB.Query(query, args...)
}

func (d *Database) createTablesLocked() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS configurations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code TEXT UNIQUE NOT NULL,
			corp_id TEXT,
			corp_secret TEXT,
			agent_id TEXT,
			to_user TEXT DEFAULT '@all',
			token TEXT NOT NULL,
			aes_key TEXT NOT NULL,
			callback_configured BOOLEAN DEFAULT 0,
			is_completed BOOLEAN DEFAULT 0,
			notify_key_hash TEXT DEFAULT '',
			name TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			code_send_enabled INTEGER DEFAULT 1,
			version INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS notification_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			config_code TEXT NOT NULL,
			name TEXT NOT NULL,
			to_user TEXT NOT NULL,
			to_party TEXT DEFAULT '',
			to_tag TEXT DEFAULT '',
			is_all INTEGER DEFAULT 0,
			estimated_count INTEGER DEFAULT 1,
			api_code TEXT UNIQUE NOT NULL,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (config_code) REFERENCES configurations (code) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS retired_notify_codes (
			code TEXT PRIMARY KEY COLLATE NOCASE,
			owner_type TEXT NOT NULL,
			owner_ref TEXT DEFAULT '',
			retired_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, s := range stmts {
		if _, err := d.sqlDB.Exec(s); err != nil {
			return err
		}
	}

	if err := d.ensureColumnsLocked(); err != nil {
		return err
	}

	conflicts, err := d.auditNotifyCodeNamespaceLocked()
	if err != nil {
		return err
	}
	if len(conflicts) > 0 {
		return &DBError{
			Message: fmt.Sprintf("通知码命名空间存在冲突，服务拒绝启动: %+v", conflicts),
			Code:    "NOTIFY_CODE_NAMESPACE_CONFLICT",
			Details: conflicts,
		}
	}

	indexAndTriggerStmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_notification_rules_config_code ON notification_rules (config_code)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_rules_api_code ON notification_rules (api_code)`,
		`CREATE INDEX IF NOT EXISTS idx_retired_notify_codes_owner ON retired_notify_codes (owner_type, owner_ref)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ux_notification_rules_api_code_nocase ON notification_rules (api_code COLLATE NOCASE)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ux_configurations_code_nocase ON configurations (code COLLATE NOCASE)`,

		`CREATE TRIGGER IF NOT EXISTS trg_rule_api_code_vs_config_insert
		BEFORE INSERT ON notification_rules
		WHEN EXISTS (
			SELECT 1 FROM configurations WHERE lower(code) = lower(NEW.api_code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:api_code_conflicts_with_config_code');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_rule_api_code_vs_config_update
		BEFORE UPDATE OF api_code ON notification_rules
		WHEN EXISTS (
			SELECT 1 FROM configurations WHERE lower(code) = lower(NEW.api_code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:api_code_conflicts_with_config_code');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_rule_api_code_vs_retired_insert
		BEFORE INSERT ON notification_rules
		WHEN EXISTS (
			SELECT 1 FROM retired_notify_codes WHERE lower(code) = lower(NEW.api_code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:api_code_retired');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_rule_api_code_vs_retired_update
		BEFORE UPDATE OF api_code ON notification_rules
		WHEN lower(NEW.api_code) != lower(OLD.api_code) AND EXISTS (
			SELECT 1 FROM retired_notify_codes
			WHERE lower(code) = lower(NEW.api_code)
			  AND NOT (owner_type = 'rule' AND (owner_ref = CAST(NEW.id AS TEXT) OR owner_ref LIKE '%:' || CAST(NEW.id AS TEXT)))
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:api_code_retired');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_config_code_vs_rules_insert
		BEFORE INSERT ON configurations
		WHEN EXISTS (
			SELECT 1 FROM notification_rules WHERE lower(api_code) = lower(NEW.code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:config_code_conflicts_with_rule_api_code');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_config_code_vs_rules_update
		BEFORE UPDATE OF code ON configurations
		WHEN lower(NEW.code) != lower(OLD.code) AND EXISTS (
			SELECT 1 FROM notification_rules WHERE lower(api_code) = lower(NEW.code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:config_code_conflicts_with_rule_api_code');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_config_code_vs_retired_insert
		BEFORE INSERT ON configurations
		WHEN EXISTS (
			SELECT 1 FROM retired_notify_codes WHERE lower(code) = lower(NEW.code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:config_code_retired');
		END`,

		`CREATE TRIGGER IF NOT EXISTS trg_config_code_vs_retired_update
		BEFORE UPDATE OF code ON configurations
		WHEN lower(NEW.code) != lower(OLD.code) AND EXISTS (
			SELECT 1 FROM retired_notify_codes WHERE lower(code) = lower(NEW.code)
		)
		BEGIN
			SELECT RAISE(ABORT, 'NOTIFY_CODE_CONFLICT:config_code_retired');
		END`,
	}

	for _, s := range indexAndTriggerStmts {
		if _, err := d.sqlDB.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) getColumnSetLocked(tableName string) (map[string]bool, error) {
	rows, err := d.sqlDB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func (d *Database) ensureColumnsLocked() error {
	cfgCols, err := d.getColumnSetLocked("configurations")
	if err != nil {
		return err
	}
	alterCfg := []struct {
		col string
		sql string
	}{
		{"notify_key_hash", "ALTER TABLE configurations ADD COLUMN notify_key_hash TEXT DEFAULT ''"},
		{"name", "ALTER TABLE configurations ADD COLUMN name TEXT DEFAULT ''"},
		{"enabled", "ALTER TABLE configurations ADD COLUMN enabled INTEGER DEFAULT 1"},
		{"code_send_enabled", "ALTER TABLE configurations ADD COLUMN code_send_enabled INTEGER DEFAULT 1"},
		{"version", "ALTER TABLE configurations ADD COLUMN version INTEGER DEFAULT 1"},
	}
	for _, item := range alterCfg {
		if !cfgCols[item.col] {
			if _, err := d.sqlDB.Exec(item.sql); err != nil {
				return err
			}
		}
	}

	_, err = d.sqlDB.Exec(`
		UPDATE configurations
		SET name = CASE
			WHEN agent_id IS NOT NULL AND TRIM(agent_id) != '' THEN '应用 ' || TRIM(agent_id)
			ELSE '应用 ' || SUBSTR(code, 1, 8)
		END
		WHERE name IS NULL OR TRIM(name) = ''
	`)
	if err != nil {
		return err
	}

	ruleCols, err := d.getColumnSetLocked("notification_rules")
	if err != nil {
		return err
	}
	alterRule := []struct {
		col string
		sql string
	}{
		{"enabled", "ALTER TABLE notification_rules ADD COLUMN enabled INTEGER DEFAULT 1"},
		{"to_party", "ALTER TABLE notification_rules ADD COLUMN to_party TEXT DEFAULT ''"},
		{"to_tag", "ALTER TABLE notification_rules ADD COLUMN to_tag TEXT DEFAULT ''"},
		{"is_all", "ALTER TABLE notification_rules ADD COLUMN is_all INTEGER DEFAULT 0"},
		{"estimated_count", "ALTER TABLE notification_rules ADD COLUMN estimated_count INTEGER DEFAULT 1"},
	}
	for _, item := range alterRule {
		if !ruleCols[item.col] {
			if _, err := d.sqlDB.Exec(item.sql); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Database) AuditNotifyCodeNamespace() ([]NamespaceConflict, error) {
	var conflicts []NamespaceConflict
	err := d.withLock(func() error {
		var e error
		conflicts, e = d.auditNotifyCodeNamespaceLocked()
		return e
	})
	return conflicts, err
}

func (d *Database) auditNotifyCodeNamespaceLocked() ([]NamespaceConflict, error) {
	var conflicts []NamespaceConflict

	// 1. rule_duplicate
	r1, err := d.sqlDB.Query(`
		SELECT lower(api_code) AS norm_code, COUNT(*) AS cnt, GROUP_CONCAT(id || ':' || api_code) AS detail
		FROM notification_rules
		GROUP BY lower(api_code)
		HAVING COUNT(*) > 1
	`)
	if err != nil {
		return nil, err
	}
	for r1.Next() {
		var c NamespaceConflict
		c.Type = "rule_duplicate"
		if err := r1.Scan(&c.NormCode, &c.Count, &c.Detail); err != nil {
			r1.Close()
			return nil, err
		}
		conflicts = append(conflicts, c)
	}
	r1.Close()

	// 2. config_duplicate
	r2, err := d.sqlDB.Query(`
		SELECT lower(code) AS norm_code, COUNT(*) AS cnt, GROUP_CONCAT(id || ':' || code) AS detail
		FROM configurations
		GROUP BY lower(code)
		HAVING COUNT(*) > 1
	`)
	if err != nil {
		return nil, err
	}
	for r2.Next() {
		var c NamespaceConflict
		c.Type = "config_duplicate"
		if err := r2.Scan(&c.NormCode, &c.Count, &c.Detail); err != nil {
			r2.Close()
			return nil, err
		}
		conflicts = append(conflicts, c)
	}
	r2.Close()

	// 3. cross_table
	r3, err := d.sqlDB.Query(`
		SELECT lower(r.api_code) AS norm_code, r.id AS rule_id, r.api_code AS rule_code, c.id AS config_id, c.code AS config_code
		FROM notification_rules r
		INNER JOIN configurations c ON lower(r.api_code) = lower(c.code)
	`)
	if err != nil {
		return nil, err
	}
	for r3.Next() {
		var c NamespaceConflict
		c.Type = "cross_table"
		if err := r3.Scan(&c.NormCode, &c.RuleID, &c.RuleCode, &c.ConfigID, &c.ConfigCode); err != nil {
			r3.Close()
			return nil, err
		}
		conflicts = append(conflicts, c)
	}
	r3.Close()

	return conflicts, nil
}

func scanConfigRow(scanner interface{ Scan(dest ...any) error }) (*ConfigRow, error) {
	var row ConfigRow
	var corpID, corpSecret, agentID, toUser, notifyKeyHash, name, createdAt, updatedAt sql.NullString
	var callbackCfg, isComp, enabled, codeSendEnabled, version sql.NullInt64

	err := scanner.Scan(
		&row.ID,
		&row.Code,
		&corpID,
		&corpSecret,
		&agentID,
		&toUser,
		&row.Token,
		&row.AESKey,
		&callbackCfg,
		&isComp,
		&notifyKeyHash,
		&name,
		&enabled,
		&codeSendEnabled,
		&version,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	row.CorpID = corpID.String
	row.CorpSecret = corpSecret.String
	row.AgentID = agentID.String
	if toUser.Valid {
		row.ToUser = toUser.String
	} else {
		row.ToUser = "@all"
	}
	row.CallbackConfigured = callbackCfg.Int64 != 0
	row.IsCompleted = isComp.Int64 != 0
	row.NotifyKeyHash = notifyKeyHash.String
	row.Name = name.String
	if enabled.Valid {
		row.Enabled = int(enabled.Int64)
	} else {
		row.Enabled = 1
	}
	if codeSendEnabled.Valid {
		row.CodeSendEnabled = int(codeSendEnabled.Int64)
	} else {
		row.CodeSendEnabled = 1
	}
	if version.Valid {
		row.Version = int(version.Int64)
	} else {
		row.Version = 1
	}
	row.CreatedAt = createdAt.String
	row.UpdatedAt = updatedAt.String
	return &row, nil
}

const selectConfigColumns = `
	id, code, corp_id, corp_secret, agent_id, to_user, token, aes_key,
	callback_configured, is_completed, notify_key_hash, name, enabled,
	code_send_enabled, version, created_at, updated_at
`

func (d *Database) GetConfigurationByCode(code string) (*ConfigRow, error) {
	var row *ConfigRow
	err := d.withLock(func() error {
		var e error
		row, e = d.getConfigurationByCodeLocked(code)
		return e
	})
	return row, err
}

func (d *Database) getConfigurationByCodeLocked(code string) (*ConfigRow, error) {
	r := d.sqlDB.QueryRow(
		"SELECT "+selectConfigColumns+" FROM configurations WHERE lower(code) = lower(?)",
		code,
	)
	return scanConfigRow(r)
}

func (d *Database) GetPrimaryConfiguration() (*ConfigRow, error) {
	var row *ConfigRow
	err := d.withLock(func() error {
		r := d.sqlDB.QueryRow(
			"SELECT " + selectConfigColumns + " FROM configurations ORDER BY is_completed DESC, id ASC LIMIT 1",
		)
		var e error
		row, e = scanConfigRow(r)
		return e
	})
	return row, err
}

func (d *Database) GetAllConfigurations() ([]*ConfigRow, error) {
	var list []*ConfigRow
	err := d.withLock(func() error {
		var e error
		list, e = d.getAllConfigurationsLocked()
		return e
	})
	return list, err
}

func (d *Database) getAllConfigurationsLocked() ([]*ConfigRow, error) {
	rows, err := d.sqlDB.Query("SELECT " + selectConfigColumns + " FROM configurations ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*ConfigRow
	for rows.Next() {
		row, err := scanConfigRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, row)
	}
	return list, rows.Err()
}

// CheckIdentityConflict 检查 (corp_id, agent_id) 业务身份是否与库中已有记录冲突
func (d *Database) CheckIdentityConflict(corpID, agentID, excludeCode string, decryptFn func(string) (string, error)) (*ConfigRow, error) {
	var matched *ConfigRow
	err := d.withLock(func() error {
		var e error
		matched, e = d.checkIdentityConflictLocked(corpID, agentID, excludeCode, decryptFn)
		return e
	})
	return matched, err
}

func (d *Database) checkIdentityConflictLocked(corpID, agentID, excludeCode string, decryptFn func(string) (string, error)) (*ConfigRow, error) {
	if strings.TrimSpace(corpID) == "" || strings.TrimSpace(agentID) == "" {
		return nil, nil
	}
	normCorp := strings.TrimSpace(corpID)
	normAgent := strings.TrimSpace(agentID)
	normExclude := strings.ToLower(strings.TrimSpace(excludeCode))

	rows, err := d.getAllConfigurationsLocked()
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if !r.IsCompleted {
			continue
		}
		if normExclude != "" && strings.ToLower(r.Code) == normExclude {
			continue
		}
		if r.CorpID == "" || strings.TrimSpace(r.AgentID) != normAgent {
			continue
		}
		if decryptFn == nil {
			continue
		}
		plainCorp, decErr := decryptFn(r.CorpID)
		if decErr != nil {
			continue
		}
		if strings.TrimSpace(plainCorp) == normCorp {
			return r, nil
		}
	}
	return nil, nil
}

// FindIncompleteDraftByCorpID 查找指定企业下尚未完成配置的草稿
func (d *Database) FindIncompleteDraftByCorpID(plainCorpID string, decryptFn func(string) (string, error)) (*ConfigRow, error) {
	var matched *ConfigRow
	err := d.withLock(func() error {
		normCorp := strings.TrimSpace(plainCorpID)
		if normCorp == "" || decryptFn == nil {
			return nil
		}
		rows, err := d.getAllConfigurationsLocked()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.IsCompleted || r.CorpID == "" {
				continue
			}
			decCorp, decErr := decryptFn(r.CorpID)
			if decErr == nil && strings.TrimSpace(decCorp) == normCorp {
				matched = r
				return nil
			}
		}
		return nil
	})
	return matched, err
}

type DraftCallbackParams struct {
	Code               string
	CorpID             string
	Token              string
	AESKey             string
	CallbackConfigured bool
	Name               string
	Enabled            int
	CodeSendEnabled    int
}

type DraftCallbackResult struct {
	ID      int64
	Code    string
	Version int
}

// CreateDraftCallbackAtomic 原子创建草稿回调记录（修复 BUG-02：捕获 NOTIFY_CODE_CONFLICT 与 UNIQUE 冲突并标记 CreateCause）
func (d *Database) CreateDraftCallbackAtomic(p DraftCallbackParams) (*DraftCallbackResult, error) {
	var out *DraftCallbackResult
	err := d.WithTransaction(func() error {
		cbInt := 0
		if p.CallbackConfigured {
			cbInt = 1
		}
		res, err := d.sqlDB.Exec(`
			INSERT INTO configurations (
				code, corp_id, corp_secret, agent_id, to_user,
				token, aes_key, callback_configured, is_completed,
				notify_key_hash, name, enabled, code_send_enabled, version
			) VALUES (?, ?, '', '', '@all', ?, ?, ?, 0, '', ?, ?, ?, 1)
		`, p.Code, p.CorpID, p.Token, p.AESKey, cbInt, p.Name, p.Enabled, p.CodeSendEnabled)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "NOTIFY_CODE_CONFLICT") || strings.Contains(msg, "UNIQUE constraint failed: configurations.code") {
				return &DBError{
					Message:     msg,
					CreateCause: "notify_code_conflict",
				}
			}
			return err
		}
		lastID, _ := res.LastInsertId()
		out = &DraftCallbackResult{
			ID:      lastID,
			Code:    p.Code,
			Version: 1,
		}
		return nil
	})
	return out, err
}

// ReuseDraftCallbackAtomic 原子复用已有未完成草稿
func (d *Database) ReuseDraftCallbackAtomic(code, token, aesKey string) (*DraftCallbackResult, error) {
	return d.UpdateDraftCallbackWithVersion(code, "", token, aesKey, nil, "", nil)
}

func (d *Database) UpdateDraftCallbackWithVersion(code, encCorpID, token, aesKey string, expectedVersion *int, plainCorpID string, decryptFn func(string) (string, error)) (*DraftCallbackResult, error) {
	var out *DraftCallbackResult
	err := d.WithTransaction(func() error {
		existing, err := d.getConfigurationByCodeLocked(code)
		if err != nil {
			return err
		}
		if existing == nil {
			return &DBError{Message: "草稿不存在", ReuseCause: "not_found"}
		}
		if existing.IsCompleted || (existing.CorpSecret != "" && existing.AgentID != "") {
			return &DBError{Message: "仅允许复用尚未完成配置的草稿", ReuseCause: "already_completed"}
		}
		if plainCorpID != "" && existing.CorpID != "" && decryptFn != nil {
			if decCorp, decErr := decryptFn(existing.CorpID); decErr == nil && strings.TrimSpace(decCorp) != "" && strings.TrimSpace(decCorp) != strings.TrimSpace(plainCorpID) {
				return &DBError{Message: "草稿与当前填写的企业不匹配", ReuseCause: "corpid_mismatch"}
			}
		}
		if expectedVersion != nil && existing.Version != *expectedVersion {
			return &DBError{Message: "版本冲突", ReuseCause: "version_conflict", Details: existing.Version}
		}

		nextCorpID := existing.CorpID
		if encCorpID != "" {
			nextCorpID = encCorpID
		}
		cbCfg := 0
		if existing.CallbackConfigured || encCorpID != "" {
			cbCfg = 1
		}

		res, err := d.sqlDB.Exec(`
			UPDATE configurations
			SET corp_id = ?, token = ?, aes_key = ?, callback_configured = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP
			WHERE id = ? AND is_completed = 0 AND version = ?
		`, nextCorpID, token, aesKey, cbCfg, existing.ID, existing.Version)
		if err != nil {
			return err
		}
		changes, _ := res.RowsAffected()
		if changes == 0 {
			return &DBError{Message: "草稿状态已变更", ReuseCause: "version_conflict", Details: existing.Version}
		}
		out = &DraftCallbackResult{
			ID:      int64(existing.ID),
			Code:    existing.Code,
			Version: existing.Version + 1,
		}
		return nil
	})
	return out, err
}

type CreateConfigParams struct {
	Code               string
	PlainCorpID        string
	PlainAgentID       string
	CorpID             string
	CorpSecret         string
	AgentID            string
	ToUser             string
	Token              string
	AESKey             string
	CallbackConfigured bool
	IsCompleted        bool
	NotifyKeyHash      string
	Name               string
	Enabled            int
	CodeSendEnabled    int
}

func (d *Database) CreateConfigurationAtomic(p CreateConfigParams, decryptFn func(string) (string, error)) (*DraftCallbackResult, error) {
	var out *DraftCallbackResult
	err := d.WithTransaction(func() error {
		if p.PlainCorpID != "" && p.PlainAgentID != "" {
			conflict, err := d.checkIdentityConflictLocked(p.PlainCorpID, p.PlainAgentID, "", decryptFn)
			if err != nil {
				return err
			}
			if conflict != nil {
				return &DBError{
					Message:     "同一企业下该 AgentId 已存在配置",
					CreateCause: "identity_conflict",
					Details:     conflict,
				}
			}
		}

		cbInt := 0
		if p.CallbackConfigured {
			cbInt = 1
		}
		compInt := 0
		if p.IsCompleted {
			compInt = 1
		}
		toUser := p.ToUser
		if toUser == "" {
			toUser = "@all"
		}

		res, err := d.sqlDB.Exec(`
			INSERT INTO configurations (
				code, corp_id, corp_secret, agent_id, to_user,
				token, aes_key, callback_configured, is_completed,
				notify_key_hash, name, enabled, code_send_enabled, version
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
		`, p.Code, p.CorpID, p.CorpSecret, p.AgentID, toUser,
			p.Token, p.AESKey, cbInt, compInt,
			p.NotifyKeyHash, p.Name, p.Enabled, p.CodeSendEnabled)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "NOTIFY_CODE_CONFLICT") || strings.Contains(msg, "UNIQUE constraint failed: configurations.code") {
				return &DBError{
					Message:     msg,
					CreateCause: "notify_code_conflict",
				}
			}
			return err
		}
		lastID, _ := res.LastInsertId()
		out = &DraftCallbackResult{
			ID:      lastID,
			Code:    p.Code,
			Version: 1,
		}
		return nil
	})
	return out, err
}

func (d *Database) SaveConfiguration(p CreateConfigParams) (*DraftCallbackResult, error) {
	var out *DraftCallbackResult
	err := d.withLock(func() error {
		cbInt := 0
		if p.CallbackConfigured {
			cbInt = 1
		}
		compInt := 0
		if p.IsCompleted {
			compInt = 1
		}
		toUser := p.ToUser
		if toUser == "" {
			toUser = "@all"
		}
		res, err := d.sqlDB.Exec(`
			INSERT OR REPLACE INTO configurations (
				code, corp_id, corp_secret, agent_id, to_user,
				token, aes_key, callback_configured, is_completed,
				notify_key_hash, name, enabled, code_send_enabled, version, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
		`, p.Code, p.CorpID, p.CorpSecret, p.AgentID, toUser,
			p.Token, p.AESKey, cbInt, compInt,
			p.NotifyKeyHash, p.Name, p.Enabled, p.CodeSendEnabled)
		if err != nil {
			return err
		}
		lastID, _ := res.LastInsertId()
		out = &DraftCallbackResult{
			ID:      lastID,
			Code:    p.Code,
			Version: 1,
		}
		return nil
	})
	return out, err
}

type CompleteConfigParams struct {
	Code          string
	PlainCorpID   string
	PlainAgentID  string
	CorpID        string
	CorpSecret    string
	AgentID       string
	ToUser        string
	Name          string
	NotifyKeyHash *string
}

type CompleteConfigResult struct {
	Code    string
	Version int
}

func (d *Database) CompleteConfigurationAtomic(p CompleteConfigParams, decryptFn func(string) (string, error)) (*CompleteConfigResult, error) {
	var out *CompleteConfigResult
	err := d.WithTransaction(func() error {
		existing, err := d.getConfigurationByCodeLocked(p.Code)
		if err != nil {
			return err
		}
		if existing == nil {
			return &DBError{Message: "找不到对应的回调配置", CompleteCause: "not_found"}
		}
		if existing.IsCompleted {
			return &DBError{Message: "该配置已完成初始化，请使用 PUT /api/configuration/:code 编辑", CompleteCause: "already_completed"}
		}

		conflict, err := d.checkIdentityConflictLocked(p.PlainCorpID, p.PlainAgentID, existing.Code, decryptFn)
		if err != nil {
			return err
		}
		if conflict != nil {
			return &DBError{
				Message:       "同一企业下该 AgentId 已存在配置",
				CompleteCause: "identity_conflict",
				Details:       conflict,
			}
		}

		toUser := p.ToUser
		if toUser == "" {
			toUser = "@all"
		}
		nameVal := p.Name
		if nameVal == "" {
			nameVal = existing.Name
		}

		setParts := []string{
			"corp_id = ?",
			"corp_secret = ?",
			"agent_id = ?",
			"to_user = ?",
			"name = ?",
			"is_completed = 1",
		}
		args := []any{p.CorpID, p.CorpSecret, p.AgentID, toUser, nameVal}
		if p.NotifyKeyHash != nil {
			setParts = append(setParts, "notify_key_hash = ?")
			args = append(args, *p.NotifyKeyHash)
		}
		setParts = append(setParts, "version = version + 1", "updated_at = CURRENT_TIMESTAMP")
		args = append(args, existing.ID)

		sqlStr := fmt.Sprintf("UPDATE configurations SET %s WHERE id = ? AND is_completed = 0", strings.Join(setParts, ", "))
		res, err := d.sqlDB.Exec(sqlStr, args...)
		if err != nil {
			return err
		}
		changes, _ := res.RowsAffected()
		if changes == 0 {
			return &DBError{Message: "配置状态已变更", CompleteCause: "already_completed"}
		}
		out = &CompleteConfigResult{
			Code:    existing.Code,
			Version: existing.Version + 1,
		}
		return nil
	})
	return out, err
}

var allowedConfigFields = []string{
	"corp_id", "corp_secret", "agent_id", "to_user",
	"token", "aes_key", "callback_configured", "is_completed",
	"notify_key_hash", "name", "enabled", "code_send_enabled",
}

func (d *Database) UpdateConfigurationFields(code string, fields map[string]any, expectedVersion *int) (*UpdateConfigResult, error) {
	var out *UpdateConfigResult
	err := d.withLock(func() error {
		var e error
		out, e = d.updateConfigurationFieldsLocked(code, fields, expectedVersion)
		return e
	})
	return out, err
}

func (d *Database) updateConfigurationFieldsLocked(code string, fields map[string]any, expectedVersion *int) (*UpdateConfigResult, error) {
	setClauses := make([]string, 0, len(fields)+2)
	values := make([]any, 0, len(fields)+2)

	for _, key := range allowedConfigFields {
		val, exists := fields[key]
		if !exists || val == nil {
			continue
		}
		setClauses = append(setClauses, key+" = ?")
		if key == "callback_configured" || key == "is_completed" || key == "enabled" || key == "code_send_enabled" {
			switch b := val.(type) {
			case bool:
				if b {
					values = append(values, 1)
				} else {
					values = append(values, 0)
				}
			case int:
				if b != 0 {
					values = append(values, 1)
				} else {
					values = append(values, 0)
				}
			default:
				values = append(values, val)
			}
		} else {
			values = append(values, val)
		}
	}

	if len(setClauses) == 0 {
		return &UpdateConfigResult{Outcome: "noop", Changes: 0}, nil
	}

	hasVersionLock := expectedVersion != nil
	if hasVersionLock {
		setClauses = append(setClauses, "version = version + 1")
	}
	setClauses = append(setClauses, "updated_at = CURRENT_TIMESTAMP")

	whereClause := "WHERE lower(code) = lower(?)"
	values = append(values, code)
	if hasVersionLock {
		whereClause += " AND version = ?"
		values = append(values, *expectedVersion)
	}

	sqlStr := fmt.Sprintf("UPDATE configurations SET %s %s", strings.Join(setClauses, ", "), whereClause)
	res, err := d.sqlDB.Exec(sqlStr, values...)
	if err != nil {
		return nil, err
	}
	changes, _ := res.RowsAffected()
	if changes > 0 {
		row, err := d.getConfigurationByCodeLocked(code)
		if err != nil {
			return nil, err
		}
		newVer := 1
		canonicalCode := code
		if row != nil {
			newVer = row.Version
			canonicalCode = row.Code
		} else if hasVersionLock {
			newVer = *expectedVersion + 1
		}
		return &UpdateConfigResult{
			Outcome:    "updated",
			Changes:    int(changes),
			NewVersion: newVer,
			Code:       canonicalCode,
		}, nil
	}

	if !hasVersionLock {
		return &UpdateConfigResult{Outcome: "not_found", Changes: 0}, nil
	}

	existing, err := d.getConfigurationByCodeLocked(code)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return &UpdateConfigResult{Outcome: "not_found", Changes: 0}, nil
	}
	return &UpdateConfigResult{Outcome: "version_conflict", Changes: 0, Code: existing.Code}, nil
}

func (d *Database) UpdateConfigFieldsWithAuditAtomic(code string, fields map[string]any, expectedVersion int, decryptFn func(string) (string, error)) (*UpdateConfigResult, error) {
	var out *UpdateConfigResult
	err := d.WithTransaction(func() error {
		current, err := d.getConfigurationByCodeLocked(code)
		if err != nil {
			return err
		}
		if current == nil {
			out = &UpdateConfigResult{Outcome: "not_found", Changes: 0}
			return nil
		}
		if current.Version != expectedVersion {
			out = &UpdateConfigResult{Outcome: "version_conflict", Changes: 0, Code: current.Code}
			return nil
		}

		if rawAgent, hasAgent := fields["agent_id"]; hasAgent && rawAgent != nil {
			targetAgent := strings.TrimSpace(fmt.Sprintf("%v", rawAgent))
			currentAgent := strings.TrimSpace(current.AgentID)
			if targetAgent != "" && targetAgent != currentAgent && current.CorpID != "" && decryptFn != nil {
				plainCorpID, err := decryptFn(current.CorpID)
				if err != nil {
					return err
				}
				conflict, err := d.checkIdentityConflictLocked(plainCorpID, targetAgent, current.Code, decryptFn)
				if err != nil {
					return err
				}
				if conflict != nil {
					out = &UpdateConfigResult{
						Outcome:  "identity_conflict",
						Changes:  0,
						Code:     current.Code,
						Conflict: conflict,
					}
					return nil
				}
			}
		}

		res, err := d.updateConfigurationFieldsLocked(current.Code, fields, &expectedVersion)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// ConditionalUpdateEncryptedFields 惰性迁移 CAS 写回（不递增 version）
func (d *Database) ConditionalUpdateEncryptedFields(code string, expectedOldValues, newEncryptedValues map[string]string) (bool, error) {
	allowedEnc := []string{"corp_id", "corp_secret", "token", "aes_key"}
	setClauses := make([]string, 0, 4)
	whereClauses := []string{"code = ?"}
	setParams := make([]any, 0, 4)
	whereParams := []any{code}

	for _, col := range allowedEnc {
		newVal, hasNew := newEncryptedValues[col]
		oldVal, hasOld := expectedOldValues[col]
		if hasNew && newVal != "" && hasOld && oldVal != "" {
			setClauses = append(setClauses, col+" = ?")
			setParams = append(setParams, newVal)
			whereClauses = append(whereClauses, col+" = ?")
			whereParams = append(whereParams, oldVal)
		}
	}
	if len(setClauses) == 0 {
		return false, nil
	}
	setClauses = append(setClauses, "updated_at = CURRENT_TIMESTAMP")
	args := append(setParams, whereParams...)
	sqlStr := fmt.Sprintf("UPDATE configurations SET %s WHERE %s", strings.Join(setClauses, ", "), strings.Join(whereClauses, " AND "))

	var updated bool
	err := d.withLock(func() error {
		res, err := d.sqlDB.Exec(sqlStr, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		updated = n > 0
		return nil
	})
	return updated, err
}

func (d *Database) BumpConfigurationVersion(code string, expectedVersion int) (*UpdateConfigResult, error) {
	var out *UpdateConfigResult
	err := d.withLock(func() error {
		var e error
		out, e = d.bumpConfigurationVersionLocked(code, expectedVersion)
		return e
	})
	return out, err
}

func (d *Database) bumpConfigurationVersionLocked(code string, expectedVersion int) (*UpdateConfigResult, error) {
	res, err := d.sqlDB.Exec(`
		UPDATE configurations
		SET version = version + 1, updated_at = CURRENT_TIMESTAMP
		WHERE lower(code) = lower(?) AND version = ?
	`, code, expectedVersion)
	if err != nil {
		return nil, err
	}
	changes, _ := res.RowsAffected()
	if changes > 0 {
		return &UpdateConfigResult{
			Outcome:    "updated",
			Changes:    int(changes),
			NewVersion: expectedVersion + 1,
		}, nil
	}
	existing, err := d.getConfigurationByCodeLocked(code)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return &UpdateConfigResult{Outcome: "not_found"}, nil
	}
	return &UpdateConfigResult{Outcome: "version_conflict"}, nil
}

func (d *Database) DeleteConfigurationWithCascade(code string, expectedVersion int) (*DeleteConfigResult, error) {
	var out *DeleteConfigResult
	err := d.WithTransaction(func() error {
		existing, err := d.getConfigurationByCodeLocked(code)
		if err != nil {
			return err
		}
		if existing == nil {
			out = &DeleteConfigResult{Outcome: "not_found", DeletedRules: 0}
			return nil
		}
		if existing.Version != expectedVersion {
			out = &DeleteConfigResult{Outcome: "version_conflict", DeletedRules: 0}
			return nil
		}

		canonicalCode := existing.Code
		rules, err := d.getNotificationRulesByConfigCodeLocked(canonicalCode)
		if err != nil {
			return err
		}

		for _, r := range rules {
			if err := d.recordRetiredNotifyCodeLocked(r.APICode, "rule", fmt.Sprintf("%s:%d", canonicalCode, r.ID)); err != nil {
				return err
			}
		}
		if err := d.recordRetiredNotifyCodeLocked(canonicalCode, "app", canonicalCode); err != nil {
			return err
		}

		delRulesRes, err := d.sqlDB.Exec("DELETE FROM notification_rules WHERE config_code = ?", canonicalCode)
		if err != nil {
			return err
		}
		deletedRules, _ := delRulesRes.RowsAffected()

		delCfgRes, err := d.sqlDB.Exec("DELETE FROM configurations WHERE id = ? AND version = ?", existing.ID, expectedVersion)
		if err != nil {
			return err
		}
		cfgChanges, _ := delCfgRes.RowsAffected()
		if cfgChanges == 0 {
			return &DBError{Message: "版本冲突", Code: "APP_VERSION_CONFLICT"}
		}

		out = &DeleteConfigResult{
			Outcome:      "deleted",
			DeletedRules: int(deletedRules),
		}
		return nil
	})
	if err != nil {
		var dbErr *DBError
		if errors.As(err, &dbErr) && dbErr.Code == "APP_VERSION_CONFLICT" {
			return &DeleteConfigResult{Outcome: "version_conflict", DeletedRules: 0}, nil
		}
		return nil, err
	}
	return out, nil
}

const selectRuleColumns = `id, config_code, name, to_user, to_party, to_tag, is_all, estimated_count, api_code, enabled, created_at, updated_at`

func scanRuleRow(scanner interface{ Scan(dest ...any) error }) (*RuleRow, error) {
	var r RuleRow
	var toParty, toTag, createdAt, updatedAt sql.NullString
	var isAll, estCount, enabled sql.NullInt64
	err := scanner.Scan(&r.ID, &r.ConfigCode, &r.Name, &r.ToUser, &toParty, &toTag, &isAll, &estCount, &r.APICode, &enabled, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.ToParty = toParty.String
	r.ToTag = toTag.String
	r.IsAll = int(isAll.Int64)
	if estCount.Valid && estCount.Int64 > 0 {
		r.EstimatedCount = int(estCount.Int64)
	} else {
		r.EstimatedCount = 1
	}
	if enabled.Valid {
		r.Enabled = int(enabled.Int64)
	} else {
		r.Enabled = 1
	}
	r.CreatedAt = createdAt.String
	r.UpdatedAt = updatedAt.String
	return &r, nil
}

type RuleWriteParams struct {
	Name           string
	ToUser         string
	ToParty        string
	ToTag          string
	IsAll          int
	EstimatedCount int
	APICode        string
	Enabled        int
}

func (d *Database) CreateNotificationRule(configCode, name, toUser, apiCode string, enabled int) (*RuleRow, error) {
	var out *RuleRow
	err := d.withLock(func() error {
		var e error
		out, e = d.createNotificationRuleFullLocked(configCode, RuleWriteParams{
			Name:           name,
			ToUser:         toUser,
			EstimatedCount: 1,
			APICode:        apiCode,
			Enabled:        enabled,
		})
		return e
	})
	return out, err
}

func (d *Database) createNotificationRuleLocked(configCode, name, toUser, apiCode string, enabled int) (*RuleRow, error) {
	return d.createNotificationRuleFullLocked(configCode, RuleWriteParams{
		Name:           name,
		ToUser:         toUser,
		EstimatedCount: 1,
		APICode:        apiCode,
		Enabled:        enabled,
	})
}

func (d *Database) createNotificationRuleFullLocked(configCode string, p RuleWriteParams) (*RuleRow, error) {
	en := 1
	if p.Enabled == 0 {
		en = 0
	}
	est := p.EstimatedCount
	if est <= 0 {
		est = 1
	}
	res, err := d.sqlDB.Exec(`
		INSERT INTO notification_rules (config_code, name, to_user, to_party, to_tag, is_all, estimated_count, api_code, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, configCode, p.Name, p.ToUser, p.ToParty, p.ToTag, p.IsAll, est, p.APICode, en)
	if err != nil {
		return nil, err
	}
	lastID, _ := res.LastInsertId()
	return &RuleRow{
		ID:             int(lastID),
		ConfigCode:     configCode,
		Name:           p.Name,
		ToUser:         p.ToUser,
		ToParty:        p.ToParty,
		ToTag:          p.ToTag,
		IsAll:          p.IsAll,
		EstimatedCount: est,
		APICode:        p.APICode,
		Enabled:        en,
	}, nil
}

func (d *Database) GetNotificationRulesByConfigCode(configCode string) ([]*RuleRow, error) {
	var list []*RuleRow
	err := d.withLock(func() error {
		var e error
		list, e = d.getNotificationRulesByConfigCodeLocked(configCode)
		return e
	})
	return list, err
}

func (d *Database) getNotificationRulesByConfigCodeLocked(configCode string) ([]*RuleRow, error) {
	rows, err := d.sqlDB.Query(`
		SELECT `+selectRuleColumns+`
		FROM notification_rules
		WHERE lower(config_code) = lower(?)
		ORDER BY id DESC
	`, configCode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]*RuleRow, 0)
	for rows.Next() {
		r, err := scanRuleRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (d *Database) GetNotificationRuleByAPICode(apiCode string) (*RuleWithConfigRow, error) {
	var out *RuleWithConfigRow
	err := d.withLock(func() error {
		row := d.sqlDB.QueryRow(`
			SELECT r.id, r.config_code, r.name, r.to_user, r.to_party, r.to_tag, r.is_all, r.estimated_count, r.api_code, r.enabled, r.created_at, r.updated_at,
			       c.corp_id, c.corp_secret, c.agent_id, c.callback_configured, c.is_completed,
			       c.notify_key_hash, c.enabled AS config_enabled, c.code_send_enabled, c.name AS config_name, c.version AS config_version
			FROM notification_rules r
			JOIN configurations c ON lower(r.config_code) = lower(c.code)
			WHERE lower(r.api_code) = lower(?)
		`, apiCode)

		var r RuleWithConfigRow
		var isAll, estCount, ruleEnabled, cbCfg, isComp, cfgEnabled, codeSend, cfgVer sql.NullInt64
		var toParty, toTag, createdAt, updatedAt, corpID, corpSecret, agentID, notifyKeyHash, cfgName sql.NullString

		err := row.Scan(
			&r.ID, &r.ConfigCode, &r.Name, &r.ToUser, &toParty, &toTag, &isAll, &estCount, &r.APICode, &ruleEnabled, &createdAt, &updatedAt,
			&corpID, &corpSecret, &agentID, &cbCfg, &isComp,
			&notifyKeyHash, &cfgEnabled, &codeSend, &cfgName, &cfgVer,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		r.ToParty = toParty.String
		r.ToTag = toTag.String
		r.IsAll = int(isAll.Int64)
		if estCount.Valid && estCount.Int64 > 0 {
			r.EstimatedCount = int(estCount.Int64)
		} else {
			r.EstimatedCount = 1
		}
		if ruleEnabled.Valid {
			r.Enabled = int(ruleEnabled.Int64)
		} else {
			r.Enabled = 1
		}
		r.CreatedAt = createdAt.String
		r.UpdatedAt = updatedAt.String
		r.CorpID = corpID.String
		r.CorpSecret = corpSecret.String
		r.AgentID = agentID.String
		r.CallbackConfigured = cbCfg.Int64 != 0
		r.IsCompleted = isComp.Int64 != 0
		r.NotifyKeyHash = notifyKeyHash.String
		if cfgEnabled.Valid {
			r.ConfigEnabled = int(cfgEnabled.Int64)
		} else {
			r.ConfigEnabled = 1
		}
		if codeSend.Valid {
			r.CodeSendEnabled = int(codeSend.Int64)
		} else {
			r.CodeSendEnabled = 1
		}
		r.ConfigName = cfgName.String
		if cfgVer.Valid {
			r.ConfigVersion = int(cfgVer.Int64)
		} else {
			r.ConfigVersion = 1
		}
		out = &r
		return nil
	})
	return out, err
}

func (d *Database) GetNotificationRuleByID(id int) (*RuleRow, error) {
	var out *RuleRow
	err := d.withLock(func() error {
		var e error
		out, e = d.getNotificationRuleByIDLocked(id)
		return e
	})
	return out, err
}

func (d *Database) getNotificationRuleByIDLocked(id int) (*RuleRow, error) {
	row := d.sqlDB.QueryRow(`
		SELECT `+selectRuleColumns+`
		FROM notification_rules
		WHERE id = ?
	`, id)
	return scanRuleRow(row)
}

func (d *Database) updateNotificationRuleLocked(id int, name, toUser string, apiCode *string) (int, error) {
	return d.updateNotificationRuleFullLocked(id, RuleWriteParams{
		Name:           name,
		ToUser:         toUser,
		EstimatedCount: 1,
	}, apiCode)
}

func (d *Database) updateNotificationRuleFullLocked(id int, p RuleWriteParams, apiCode *string) (int, error) {
	est := p.EstimatedCount
	if est <= 0 {
		est = 1
	}
	var res sql.Result
	var err error
	if apiCode != nil && *apiCode != "" {
		res, err = d.sqlDB.Exec(`
			UPDATE notification_rules
			SET name = ?, to_user = ?, to_party = ?, to_tag = ?, is_all = ?, estimated_count = ?, api_code = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, p.Name, p.ToUser, p.ToParty, p.ToTag, p.IsAll, est, *apiCode, id)
	} else {
		res, err = d.sqlDB.Exec(`
			UPDATE notification_rules
			SET name = ?, to_user = ?, to_party = ?, to_tag = ?, is_all = ?, estimated_count = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, p.Name, p.ToUser, p.ToParty, p.ToTag, p.IsAll, est, id)
	}
	if err != nil {
		return 0, err
	}
	changes, _ := res.RowsAffected()
	return int(changes), nil
}

func (d *Database) setNotificationRuleEnabledLocked(id int, enabled bool) (int, error) {
	en := 0
	if enabled {
		en = 1
	}
	res, err := d.sqlDB.Exec(`
		UPDATE notification_rules
		SET enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, en, id)
	if err != nil {
		return 0, err
	}
	changes, _ := res.RowsAffected()
	return int(changes), nil
}

func (d *Database) deleteNotificationRuleLocked(id int) (bool, error) {
	res, err := d.sqlDB.Exec("DELETE FROM notification_rules WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	changes, _ := res.RowsAffected()
	return changes > 0, nil
}

func (d *Database) updateNotificationRuleAPICodeLocked(id int, newAPICode string) (int, error) {
	res, err := d.sqlDB.Exec(`
		UPDATE notification_rules
		SET api_code = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, newAPICode, id)
	if err != nil {
		return 0, err
	}
	changes, _ := res.RowsAffected()
	return int(changes), nil
}

func (d *Database) RecordRetiredNotifyCode(code, ownerType, ownerRef string) error {
	return d.withLock(func() error {
		return d.recordRetiredNotifyCodeLocked(code, ownerType, ownerRef)
	})
}

func (d *Database) recordRetiredNotifyCodeLocked(code, ownerType, ownerRef string) error {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return nil
	}
	if ownerType == "" {
		ownerType = "rule"
	}
	_, err := d.sqlDB.Exec(`
		INSERT OR IGNORE INTO retired_notify_codes (code, owner_type, owner_ref, retired_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`, trimmed, ownerType, ownerRef)
	return err
}

func (d *Database) IsRetiredNotifyCode(code string) (bool, error) {
	var retired bool
	err := d.withLock(func() error {
		var e error
		retired, e = d.isRetiredNotifyCodeLocked(code)
		return e
	})
	return retired, err
}

func (d *Database) isRetiredNotifyCodeLocked(code string) (bool, error) {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return false, nil
	}
	var one int
	err := d.sqlDB.QueryRow("SELECT 1 FROM retired_notify_codes WHERE lower(code) = lower(?) LIMIT 1", trimmed).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (d *Database) CheckNotifyCodeAvailability(code string, excludeRuleID *int) (bool, string, error) {
	var available bool
	var reason string
	err := d.withLock(func() error {
		var e error
		available, reason, e = d.checkNotifyCodeAvailabilityLocked(code, excludeRuleID)
		return e
	})
	return available, reason, err
}

func (d *Database) checkNotifyCodeAvailabilityLocked(code string, excludeRuleID *int) (bool, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if normalized == "" {
		return false, "invalid", nil
	}

	var one int
	err := d.sqlDB.QueryRow("SELECT 1 FROM configurations WHERE lower(code) = ? LIMIT 1", normalized).Scan(&one)
	if err == nil {
		return false, "conflicts_with_app_code", nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}

	var ruleID int
	err = d.sqlDB.QueryRow("SELECT id FROM notification_rules WHERE lower(api_code) = ? LIMIT 1", normalized).Scan(&ruleID)
	if err == nil {
		if excludeRuleID == nil || ruleID != *excludeRuleID {
			return false, "already_in_use", nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}

	var ownerType, ownerRef string
	err = d.sqlDB.QueryRow("SELECT owner_type, owner_ref FROM retired_notify_codes WHERE lower(code) = ? LIMIT 1", normalized).Scan(&ownerType, &ownerRef)
	if err == nil {
		if excludeRuleID != nil && ownerType == "rule" {
			idStr := strconv.Itoa(*excludeRuleID)
			if ownerRef == idStr || strings.HasSuffix(ownerRef, ":"+idStr) {
				return true, "ok", nil
			}
		}
		return false, "retired", nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, "", err
	}
	return true, "ok", nil
}

func (d *Database) CreateRuleWithVersionCheck(configCode string, expectedVersion int, name, toUser, apiCode string, enabled int) (*RuleVersionResult, error) {
	return d.CreateRuleFullWithVersionCheck(configCode, expectedVersion, RuleWriteParams{
		Name:           name,
		ToUser:         toUser,
		EstimatedCount: 1,
		APICode:        apiCode,
		Enabled:        enabled,
	})
}

func (d *Database) CreateRuleFullWithVersionCheck(configCode string, expectedVersion int, p RuleWriteParams) (*RuleVersionResult, error) {
	var out *RuleVersionResult
	err := d.WithTransaction(func() error {
		bump, err := d.bumpConfigurationVersionLocked(configCode, expectedVersion)
		if err != nil {
			return err
		}
		if bump.Outcome != "updated" {
			out = &RuleVersionResult{Outcome: bump.Outcome}
			return nil
		}
		cfg, err := d.getConfigurationByCodeLocked(configCode)
		if err != nil {
			return err
		}
		canonicalCode := configCode
		if cfg != nil {
			canonicalCode = cfg.Code
		}
		rule, err := d.createNotificationRuleFullLocked(canonicalCode, p)
		if err != nil {
			return err
		}
		out = &RuleVersionResult{
			Outcome:    "created",
			NewVersion: bump.NewVersion,
			ConfigCode: canonicalCode,
			Rule:       rule,
		}
		return nil
	})
	return out, err
}

func (d *Database) UpdateRuleWithVersionCheck(ruleID int, expectedVersion int, name, toUser string, apiCode *string) (*RuleVersionResult, error) {
	return d.UpdateRuleFullWithVersionCheck(ruleID, expectedVersion, RuleWriteParams{
		Name:           name,
		ToUser:         toUser,
		EstimatedCount: 1,
	}, apiCode)
}

func (d *Database) UpdateRuleFullWithVersionCheck(ruleID int, expectedVersion int, p RuleWriteParams, apiCode *string) (*RuleVersionResult, error) {
	var out *RuleVersionResult
	err := d.WithTransaction(func() error {
		existing, err := d.getNotificationRuleByIDLocked(ruleID)
		if err != nil {
			return err
		}
		if existing == nil {
			out = &RuleVersionResult{Outcome: "rule_not_found"}
			return nil
		}

		bump, err := d.bumpConfigurationVersionLocked(existing.ConfigCode, expectedVersion)
		if err != nil {
			return err
		}
		if bump.Outcome != "updated" {
			out = &RuleVersionResult{Outcome: bump.Outcome}
			return nil
		}

		var nextAPICode string
		if apiCode != nil && strings.TrimSpace(*apiCode) != "" {
			nextAPICode = strings.TrimSpace(*apiCode)
		} else {
			nextAPICode = existing.APICode
		}
		apiCodeChanged := strings.ToLower(nextAPICode) != strings.ToLower(existing.APICode)

		_, err = d.updateNotificationRuleFullLocked(ruleID, p, &nextAPICode)
		if err != nil {
			return err
		}
		if apiCodeChanged {
			if err := d.recordRetiredNotifyCodeLocked(existing.APICode, "rule", fmt.Sprintf("%s:%d", existing.ConfigCode, ruleID)); err != nil {
				return err
			}
		}

		est := p.EstimatedCount
		if est <= 0 {
			est = 1
		}
		out = &RuleVersionResult{
			Outcome:    "updated",
			NewVersion: bump.NewVersion,
			ConfigCode: existing.ConfigCode,
			OldAPICode: existing.APICode,
			Rule: &RuleRow{
				ID:             ruleID,
				ConfigCode:     existing.ConfigCode,
				Name:           p.Name,
				ToUser:         p.ToUser,
				ToParty:        p.ToParty,
				ToTag:          p.ToTag,
				IsAll:          p.IsAll,
				EstimatedCount: est,
				APICode:        nextAPICode,
				Enabled:        existing.Enabled,
			},
		}
		return nil
	})
	return out, err
}

func (d *Database) DeleteRuleWithVersionCheck(ruleID int, expectedVersion int) (*RuleVersionResult, error) {
	var out *RuleVersionResult
	err := d.WithTransaction(func() error {
		existing, err := d.getNotificationRuleByIDLocked(ruleID)
		if err != nil {
			return err
		}
		if existing == nil {
			out = &RuleVersionResult{Outcome: "rule_not_found"}
			return nil
		}

		bump, err := d.bumpConfigurationVersionLocked(existing.ConfigCode, expectedVersion)
		if err != nil {
			return err
		}
		if bump.Outcome != "updated" {
			out = &RuleVersionResult{Outcome: bump.Outcome}
			return nil
		}

		if err := d.recordRetiredNotifyCodeLocked(existing.APICode, "rule", fmt.Sprintf("%s:%d", existing.ConfigCode, ruleID)); err != nil {
			return err
		}
		if _, err := d.deleteNotificationRuleLocked(ruleID); err != nil {
			return err
		}

		out = &RuleVersionResult{
			Outcome:    "deleted",
			NewVersion: bump.NewVersion,
			ConfigCode: existing.ConfigCode,
			OldAPICode: existing.APICode,
		}
		return nil
	})
	return out, err
}

func (d *Database) RegenerateRuleWithVersionCheck(ruleID int, expectedVersion int, newAPICode string) (*RuleVersionResult, error) {
	var out *RuleVersionResult
	err := d.WithTransaction(func() error {
		existing, err := d.getNotificationRuleByIDLocked(ruleID)
		if err != nil {
			return err
		}
		if existing == nil {
			out = &RuleVersionResult{Outcome: "rule_not_found"}
			return nil
		}

		bump, err := d.bumpConfigurationVersionLocked(existing.ConfigCode, expectedVersion)
		if err != nil {
			return err
		}
		if bump.Outcome != "updated" {
			out = &RuleVersionResult{Outcome: bump.Outcome}
			return nil
		}

		if _, err := d.updateNotificationRuleAPICodeLocked(ruleID, newAPICode); err != nil {
			return err
		}
		if strings.ToLower(newAPICode) != strings.ToLower(existing.APICode) {
			if err := d.recordRetiredNotifyCodeLocked(existing.APICode, "rule", fmt.Sprintf("%s:%d", existing.ConfigCode, ruleID)); err != nil {
				return err
			}
		}

		out = &RuleVersionResult{
			Outcome:    "regenerated",
			NewVersion: bump.NewVersion,
			ConfigCode: existing.ConfigCode,
			OldAPICode: existing.APICode,
		}
		return nil
	})
	return out, err
}

func (d *Database) SetRuleEnabledWithVersionCheck(ruleID int, expectedVersion int, enabled bool) (*RuleVersionResult, error) {
	var out *RuleVersionResult
	err := d.WithTransaction(func() error {
		existing, err := d.getNotificationRuleByIDLocked(ruleID)
		if err != nil {
			return err
		}
		if existing == nil {
			out = &RuleVersionResult{Outcome: "rule_not_found"}
			return nil
		}

		bump, err := d.bumpConfigurationVersionLocked(existing.ConfigCode, expectedVersion)
		if err != nil {
			return err
		}
		if bump.Outcome != "updated" {
			out = &RuleVersionResult{Outcome: bump.Outcome}
			return nil
		}

		if _, err := d.setNotificationRuleEnabledLocked(ruleID, enabled); err != nil {
			return err
		}

		enInt := 0
		if enabled {
			enInt = 1
		}
		out = &RuleVersionResult{
			Outcome:    "updated",
			NewVersion: bump.NewVersion,
			ConfigCode: existing.ConfigCode,
			Rule: &RuleRow{
				ID:         existing.ID,
				ConfigCode: existing.ConfigCode,
				Name:       existing.Name,
				ToUser:     existing.ToUser,
				APICode:    existing.APICode,
				Enabled:    enInt,
			},
		}
		return nil
	})
	return out, err
}
