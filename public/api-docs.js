// API 文档页图标初始化（SEC-011：从 api-docs.html 内联脚本外置）
document.addEventListener('DOMContentLoaded', function () {
    if (window.lucide) lucide.createIcons();
});
