/*
 * 多应用管理（2026-07-04 §7.5）：统一 HTTP 客户端封装。
 *
 * 职责：
 *   - 同源 Cookie 请求（credentials: 'same-origin'），不读写 localStorage/sessionStorage 凭证。
 *   - 应用聚合写操作自动携带 If-Match 版本头。
 *   - 解析稳定业务错误码（body.code），前端禁止匹配中文错误文案（§6.9）。
 *   - 401 AUTH_REQUIRED 只记录同源路径作为安全返回地址后跳转 /login（禁止接受外部 URL）。
 *   - 重复提交保护：请求期间禁用触发按钮，避免双击产生重复请求（§5.2）。
 *
 * 暴露命名空间 window.AppHttp，不使用模块打包器（§7.5 无构建系统）。
 */
(function () {
    'use strict';

    const AppHttp = {};

    /**
     * 发起 JSON 请求并解析响应。
     * @param {string} method HTTP 方法
     * @param {string} path 同源路径
     * @param {object} [opts]
     * @param {object} [opts.body] 请求体（JSON 序列化）
     * @param {number} [opts.version] 应用聚合版本，存在则附加 If-Match 头
     * @param {HTMLElement} [opts.button] 触发按钮，请求期间禁用
     * @param {boolean} [opts.raw] 为 true 时返回原始 Response（用于非 JSON 响应）
     * @returns {Promise<{ok, status, data, code, error, details, version}>}
     */
    AppHttp.request = async function request(method, path, opts = {}) {
        const headers = { 'Accept': 'application/json' };
        // null/undefined 均视为无 body：不带 Content-Type，也不发送 "null" 字面量。
        // 原因：express.json 默认 strict=true，只接受 object/array；JSON.stringify(null)="null"
        // 会被 body parser 判为非法 JSON（400 INVALID_INPUT）。
        const hasBody = opts.body !== undefined && opts.body !== null;
        if (hasBody) headers['Content-Type'] = 'application/json';

        // If-Match 版本前置条件（§6.4 配置并发控制）。
        if (opts.version !== undefined && opts.version !== null) {
            headers['If-Match'] = String(opts.version);
        }

        const button = opts.button;
        const originalDisabled = button ? button.disabled : null;
        const originalHtml = button ? button.innerHTML : null;
        if (button) {
            button.disabled = true;
        }

        let res;
        try {
            res = await fetch(path, {
                method,
                headers,
                credentials: 'same-origin',
                body: hasBody ? JSON.stringify(opts.body) : undefined
            });
        } catch (networkErr) {
            return {
                ok: false,
                status: 0,
                code: 'NETWORK_ERROR',
                error: '网络请求失败，请检查连接后重试',
                details: null,
                networkError: true
            };
        } finally {
            if (button) {
                // 交由调用方按结果决定是否重新启用，这里先恢复可点击避免卡死。
                button.disabled = originalDisabled;
            }
        }

        if (opts.raw) {
            return { ok: res.ok, status: res.status, response: res };
        }

        let data = null;
        const text = await res.text();
        if (text) {
            try { data = JSON.parse(text); } catch (_e) { data = null; }
        }

        const result = {
            ok: res.ok,
            status: res.status,
            data: res.ok ? data : null,
            // 错误体统一为 { error, code?, details? }（§6.9）。
            error: data && data.error ? data.error : null,
            code: data && data.code ? data.code : null,
            details: data && data.details ? data.details : null,
            // 服务端返回的新版本（更新/切换/删除返回 version 或 app_version）。
            version: data && (data.version || data.app_version) || null
        };

        // 401 会话失效：只记录同源路径作为返回地址，跳转登录。
        if (res.status === 401 || (result.code === 'AUTH_REQUIRED')) {
            safeRedirectToLogin();
        }

        return result;
    };

    AppHttp.get = (path, opts) => AppHttp.request('GET', path, opts);
    AppHttp.post = (path, body, opts) => AppHttp.request('POST', path, { ...opts, body });
    AppHttp.put = (path, body, opts) => AppHttp.request('PUT', path, { ...opts, body });
    AppHttp.del = (path, opts) => AppHttp.request('DELETE', path, opts);

    /**
     * 判断错误是否为版本冲突（前端保留输入、提示刷新）。
     */
    AppHttp.isVersionConflict = function isVersionConflict(result) {
        return result && (result.code === 'APP_VERSION_CONFLICT' || result.status === 409
            && result.details && result.details.version !== undefined);
    };

    // 多应用（第三轮复验 P1-02）：安全跳转登录。
    // next 内部协议统一为同源相对路径（pathname + search + hash），
    // 与 login.js safeReturnPath 的消费契约一致（只接受相对路径）。
    // 旧实现把 origin 拼入 next 写成绝对 URL，被 login 拒绝后总是落到首页。
    function safeRedirectToLogin() {
        try {
            const here = window.location.pathname + window.location.search + window.location.hash;
            window.location.href = '/login?next=' + encodeURIComponent(here);
        } catch (_e) {
            window.location.href = '/login';
        }
    }

    window.AppHttp = AppHttp;
})();
