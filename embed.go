package assets

import "embed"

// PublicFS 内嵌前端静态资源目录 public/，支持单二进制独立部署。
//
//go:embed public public/components public/vendor
var PublicFS embed.FS
