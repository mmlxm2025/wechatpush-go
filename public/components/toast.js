/*
 * 多应用管理（2026-07-04 §7.5）：统一 Toast 组件。
 *
 * 设计：
 *   - 全局单例容器，aria-live="polite"，屏幕阅读器可读（§7.5 可访问性）。
 *   - 消息文本通过 textContent 注入，避免不可信内容注入（§3 动态内容禁止 innerHTML）。
 *   - 不依赖 GSAP，纯 CSS 过渡，尊重 prefers-reduced-motion。
 *
 * 用法：AppToast.show('保存成功', { type: 'success' }); AppToast.show('失败', { type: 'error' });
 */
(function () {
    'use strict';

    let containerEl = null;

    function ensureContainer() {
        if (containerEl && document.body.contains(containerEl)) return containerEl;
        containerEl = document.createElement('div');
        containerEl.className = 'app-toast-container';
        containerEl.setAttribute('role', 'status');
        containerEl.setAttribute('aria-live', 'polite');
        document.body.appendChild(containerEl);
        return containerEl;
    }

    const TYPE_ICONS = {
        success: 'circle-check-big',
        error: 'circle-alert',
        warn: 'triangle-alert',
        info: 'info'
    };

    function show(message, opts = {}) {
        const type = TYPE_ICONS[opts.type] ? opts.type : 'info';
        const container = ensureContainer();

        const toast = document.createElement('div');
        toast.className = 'app-toast app-toast--' + type;

        if (window.lucide) {
            const icon = document.createElement('i');
            icon.setAttribute('data-lucide', TYPE_ICONS[type]);
            icon.className = 'icon-sm flex-shrink-0';
            icon.setAttribute('aria-hidden', 'true');
            toast.appendChild(icon);
        }

        // 消息文本一律 textContent，禁止 innerHTML（安全）。
        const text = document.createElement('span');
        text.textContent = message;
        toast.appendChild(text);

        container.appendChild(toast);
        if (window.lucide) lucide.createIcons();

        // 入场（ease-out 减速进入）。
        requestAnimationFrame(() => {
            toast.classList.add('app-toast--visible');
        });

        const duration = opts.duration || 3000;
        setTimeout(() => {
            // 退出：更快（150ms < 进入 220ms），向上淡出（§7 exit-faster-than-enter）。
            toast.classList.remove('app-toast--visible');
            toast.classList.add('app-toast--exit');
            setTimeout(() => {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 160);
        }, duration);
    }

    window.AppToast = { show };
})();
