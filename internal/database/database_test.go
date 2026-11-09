package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"qywx-notifier-plus/internal/crypto"
)

func TestDatabaseTransactionsAndIdentityConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db := New(dbPath)
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init failed: %v", err)
	}
	defer db.Close()

	cryptoSvc, err := crypto.NewService("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("crypto.NewService failed: %v", err)
	}

	// 1. P0-05: 20 rounds of concurrent CreateConfigurationAtomic with same (corp_id, agent_id)
	for round := 0; round < 20; round++ {
		corpPlain := fmt.Sprintf("ww-corp-%d", round)
		agentPlain := "1000010"

		encCorpA, _ := cryptoSvc.Encrypt(corpPlain)
		encSecA, _ := cryptoSvc.Encrypt("secA")
		encTokA, _ := cryptoSvc.Encrypt("tokA123456789012")
		encAesA, _ := cryptoSvc.Encrypt("1234567890123456789012345678901234567890123")

		encCorpB, _ := cryptoSvc.Encrypt(corpPlain)
		encSecB, _ := cryptoSvc.Encrypt("secB")
		encTokB, _ := cryptoSvc.Encrypt("tokB123456789012")
		encAesB, _ := cryptoSvc.Encrypt("1234567890123456789012345678901234567890123")

		var wg sync.WaitGroup
		wg.Add(2)
		var errA, errB error

		go func() {
			defer wg.Done()
			_, errA = db.CreateConfigurationAtomic(CreateConfigParams{
				Code:            fmt.Sprintf("code-a-%d", round),
				PlainCorpID:     corpPlain,
				PlainAgentID:    agentPlain,
				CorpID:          encCorpA,
				CorpSecret:      encSecA,
				AgentID:         agentPlain,
				ToUser:          "@all",
				Token:           encTokA,
				AESKey:          encAesA,
				IsCompleted:     true,
				Name:            "App A",
				Enabled:         1,
				CodeSendEnabled: 1,
			}, cryptoSvc.Decrypt)
		}()

		go func() {
			defer wg.Done()
			_, errB = db.CreateConfigurationAtomic(CreateConfigParams{
				Code:            fmt.Sprintf("code-b-%d", round),
				PlainCorpID:     corpPlain,
				PlainAgentID:    agentPlain,
				CorpID:          encCorpB,
				CorpSecret:      encSecB,
				AgentID:         agentPlain,
				ToUser:          "@all",
				Token:           encTokB,
				AESKey:          encAesB,
				IsCompleted:     true,
				Name:            "App B",
				Enabled:         1,
				CodeSendEnabled: 1,
			}, cryptoSvc.Decrypt)
		}()

		wg.Wait()
		if (errA == nil && errB == nil) || (errA != nil && errB != nil) {
			t.Fatalf("round %d: expected exactly 1 success and 1 identity_conflict, got errA=%v errB=%v", round, errA, errB)
		}
	}

	// 2. BUG-02: CreateDraftCallbackAtomic detects notify_code_conflict against retired or existing codes
	_ = db.RecordRetiredNotifyCode("retired-draft-code", "app", "retired-draft-code")
	_, draftErr := db.CreateDraftCallbackAtomic(DraftCallbackParams{
		Code:            "RETIRED-DRAFT-CODE",
		Token:           "tok",
		AESKey:          "aes",
		Name:            "Draft",
		Enabled:         1,
		CodeSendEnabled: 1,
	})
	var dbErr *DBError
	if !errors.As(draftErr, &dbErr) || dbErr.CreateCause != "notify_code_conflict" {
		t.Fatalf("BUG-02 regression: expected CreateCause=notify_code_conflict, got %v", draftErr)
	}

	// 3. P0-03: CreateRuleWithVersionCheck atomicity (if rule insert fails due to conflict, version must NOT increment)
	cfg, err := db.GetConfigurationByCode("code-a-0")
	if err != nil {
		t.Fatalf("GetConfigurationByCode failed: %v", err)
	}
	if cfg == nil {
		cfg, _ = db.GetConfigurationByCode("code-b-0")
	}
	initialVer := cfg.Version

	// Try creating a rule whose api_code conflicts with the app's own code -> trigger aborts -> version stays initialVer
	_, ruleErr := db.CreateRuleWithVersionCheck(cfg.Code, initialVer, "BadRule", "zhangsan", cfg.Code, 1)
	if ruleErr == nil {
		t.Fatal("expected rule creation with conflicting api_code to fail")
	}
	cfgAfter, _ := db.GetConfigurationByCode(cfg.Code)
	if cfgAfter.Version != initialVer {
		t.Fatalf("expected version to rollback to %d on rule insert failure, got %d", initialVer, cfgAfter.Version)
	}
}
