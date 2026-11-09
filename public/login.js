// 登录页交互脚本（从 login.html 内联脚本外置，SEC-011 避免 CSP 拦截内联脚本）
document.addEventListener('DOMContentLoaded', function () {
    if (window.lucide) lucide.createIcons();

    const loginForm = document.getElementById('loginForm');
    const loginError = document.getElementById('login-error');
    const errorMessage = document.getElementById('error-message');

    // SEC-002：清除历史遗留的 localStorage token，统一改用 HttpOnly Cookie 会话。
    try { localStorage.removeItem('authToken'); } catch (e) {}

    loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const username = loginForm.username.value.trim();
        const password = loginForm.password.value;

        if (!username || !password) {
            showError('请输入用户名和密码');
            return;
        }

        const submitBtn = loginForm.querySelector('button[type=submit]');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="loading loading-spinner"></span> 登录中...';

        try {
            // SEC-002：不再把 token 写入 localStorage 或 URL；凭证只由 HttpOnly Cookie 携带。
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (!res.ok) {
                throw new Error(data.error || '登录失败');
            }

            // 登录成功，Cookie 已由服务端下发，跳转到安全返回地址或首页。
            // 多应用（二次复验 P2-01）：安全消费 ?next=，只接受同源路径，禁止外部 URL 注入。
            const next = safeReturnPath();
            window.location.href = next || '/';
        } catch (err) {
            showError(err.message);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i data-lucide="log-in" class="w-5 h-5"></i> 登录';
            if (window.lucide) lucide.createIcons();
        }
    });

    function showError(message) {
        errorMessage.textContent = message;
        loginError.classList.remove('hidden');
    }

    // 多应用（第三轮复验 P1-02）：安全消费 ?next= 返回地址。
    // 内部协议统一为同源相对路径（http.js safeRedirectToLogin 已改为生产相对路径）。
    // 为兼容旧书签中残留的绝对 URL，只在 url.origin === window.location.origin 时
    // 降级为相对路径；其他情况严格拒绝，避免开放重定向。
    // 拒绝：外部 URL、协议相对 URL（//）、脚本协议（javascript:/data:）。
    function safeReturnPath() {
        try {
            const params = new URLSearchParams(window.location.search);
            const next = params.get('next');
            if (!next) return null;
            // 兼容旧绝对 URL：同源时降级为 pathname+search+hash。
            if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(next) || next.startsWith('//')) {
                try {
                    const url = new URL(next, window.location.origin);
                    if (url.origin === window.location.origin) {
                        return url.pathname + url.search + url.hash;
                    }
                } catch (_e) { /* 无效 URL，拒绝 */ }
                return null;
            }
            // 相对路径：必须以单个 / 开头，拒绝 // 与协议。
            if (next.startsWith('/') && !next.startsWith('//') && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(next)) {
                return next;
            }
            return null;
        } catch (_e) {
            return null;
        }
    }

    // 已登录则直接进入返回地址或首页（Cookie 自动携带）
    async function checkAuth() {
        try {
            const res = await fetch('/api/auth-status', { credentials: 'same-origin' });
            const data = await res.json();
            if (data.loggedIn) {
                const next = safeReturnPath();
                window.location.href = next || '/';
            }
        } catch (err) {
            // 忽略，停留在登录页
        }
    }

    checkAuth();
});
