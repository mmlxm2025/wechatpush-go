package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"qywx-notifier-plus/internal/auth"
	"qywx-notifier-plus/internal/config"
	"qywx-notifier-plus/internal/crypto"
	"qywx-notifier-plus/internal/database"
	"qywx-notifier-plus/internal/server"
	"qywx-notifier-plus/internal/service"
	"qywx-notifier-plus/internal/wechat"
)

func main() {
	_ = config.LoadDotEnv(".env")
	cfg := config.FromEnv()

	errs, warnings := config.ValidateRuntime(cfg)
	for _, w := range warnings {
		log.Printf("⚠️ 安全提示: %s", w)
	}
	if len(errs) > 0 && cfg.SkipStartupValidation && cfg.NodeEnv != "production" {
		// SKIP_STARTUP_VALIDATION=1：仅本地开发使用，生产环境不生效。
		for _, e := range errs {
			log.Printf("?? 已跳过启动校验（SKIP_STARTUP_VALIDATION=1）: %s", e)
		}
		errs = nil
	}
	if len(errs) > 0 {
		log.Println("❌ 启动失败：运行环境安全配置校验未通过：")
		for _, e := range errs {
			log.Printf("   - %s", e)
		}
		os.Exit(1)
	}

	cryptoSvc, err := crypto.NewService(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("❌ 初始化加密服务失败: %v", err)
	}

	db := database.New(cfg.DBPath)
	wxSvc := wechat.NewService(cfg.WechatAPIBase, cfg.WechatHTTPTimeoutMs, cfg.WechatMaxResponseBytes)
	wxSvc.SetMaxRequestBytes(cfg.WechatMaxRequestBytes)
	notifier := service.NewNotifier(cfg, db, cryptoSvc, wxSvc)
	if err := notifier.Init(); err != nil {
		log.Fatalf("❌ 初始化通知服务失败: %v", err)
	}

	authSvc := auth.NewService(cfg.AdminUsername, cfg.AdminPassword)
	srv := server.NewServer(cfg, notifier, authSvc)
	srv.StartBackgroundCleanup(5 * time.Minute)

	addr := fmt.Sprintf(":%d", cfg.Port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("🚀 企业微信通知系统已启动")
		log.Printf("📱 访问地址: http://localhost:%d", cfg.Port)
		log.Printf("📖 API文档: http://localhost:%d/api-docs.html", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("❌ HTTP 服务异常退出: %v", err)
	case sig := <-sigCh:
		log.Printf("⏳ 收到 %v 信号，开始优雅停机（排空窗口 %dms）...", sig, cfg.ShutdownTimeoutMs)
	}

	srv.SetShuttingDown(true)
	srv.StopBackgroundCleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeoutMs)*time.Millisecond)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("⚠️ HTTP 连接排空超时或异常: %v", err)
	} else {
		log.Println("✅ HTTP 连接已全部排空")
	}

	if err := db.Close(); err != nil {
		log.Printf("⚠️ 关闭数据库连接失败: %v", err)
	}
	log.Println("👋 服务已安全退出")
}
