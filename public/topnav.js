/*
 * 多应用管理（2026-07-04 §7.5）：统一顶部导航。
 *
 * 各管理页面复用，避免复制导航逻辑。当前页通过 aria-current="page" 标识（§7.5）。
 * 动态内容用 createElement，无不可信 innerHTML。
 *
 * 用法：在页面 body 顶部放置 <div id="app-topnav" data-active="overview"></div>，
 *      然后引入本脚本，DOMContentLoaded 后自动渲染。
 *      data-active 取值：overview | rules | docs。
 */
(function () {
    'use strict';

    const LINKS = [
        { key: 'overview', href: '/', label: '应用总览', icon: 'layout-grid' },
        { key: 'rules', href: '/rules', label: '接收规则', icon: 'route' },
        { key: 'docs', href: '/api-docs.html', label: 'API 文档', icon: 'book-open' }
    ];

    function render(mount) {
        const active = mount.getAttribute('data-active') || 'overview';

        const nav = document.createElement('nav');
        nav.className = 'app-topnav w-full max-w-5xl mx-auto flex items-center justify-between flex-wrap gap-2 sm:gap-3';
        nav.setAttribute('aria-label', '主导航');

        // 品牌区。
        const brand = document.createElement('a');
        brand.href = '/';
        brand.className = 'app-type-section flex items-center gap-2 min-w-0 text-primary font-bold hover:opacity-80 transition-opacity';
        const brandIcon = document.createElement('i');
        brandIcon.setAttribute('data-lucide', 'bell-ring');
        brandIcon.className = 'icon-lg flex-shrink-0';
        brandIcon.setAttribute('aria-hidden', 'true');
        brand.appendChild(brandIcon);
        const brandText = document.createElement('span');
        brandText.className = 'app-topnav-brand-text';
        brandText.textContent = '企业微信通知服务';
        brand.appendChild(brandText);
        nav.appendChild(brand);

        // 链接组。
        const linkGroup = document.createElement('div');
        linkGroup.className = 'flex items-center gap-1 flex-wrap';
        LINKS.forEach(link => {
            const a = document.createElement('a');
            a.href = link.href;
            // app-nav-link 提供底部指示条（aria-current 时显示）；统一图标尺寸令牌。
            a.className = 'app-nav-link btn btn-sm btn-ghost gap-1 sm:gap-1.5';
            if (link.key === active) {
                a.setAttribute('aria-current', 'page');
                a.classList.add('btn-active');
            }
            const icon = document.createElement('i');
            icon.setAttribute('data-lucide', link.icon);
            icon.className = 'icon-sm';
            icon.setAttribute('aria-hidden', 'true');
            a.appendChild(icon);
            const label = document.createElement('span');
            // 窄屏仅图标 + aria-label；sm 及以上显示文案，减少导航换行。
            label.className = 'hidden sm:inline';
            label.textContent = link.label;
            a.setAttribute('aria-label', link.label);
            a.title = link.label;
            a.appendChild(label);
            linkGroup.appendChild(a);
        });

        // 登出（§9 destructive-nav-separation：与导航项之间加分隔，视觉隔离危险操作）。
        const divider = document.createElement('span');
        divider.className = 'w-px h-5 bg-base-300 mx-1 hidden sm:inline-block';
        divider.setAttribute('aria-hidden', 'true');
        linkGroup.appendChild(divider);

        const logoutBtn = document.createElement('button');
        logoutBtn.type = 'button';
        logoutBtn.className = 'btn btn-sm btn-outline btn-error gap-1 sm:gap-1.5';
        logoutBtn.setAttribute('aria-label', '登出');
        logoutBtn.title = '登出';
        const logoutIcon = document.createElement('i');
        logoutIcon.setAttribute('data-lucide', 'log-out');
        logoutIcon.className = 'icon-sm';
        logoutIcon.setAttribute('aria-hidden', 'true');
        logoutBtn.appendChild(logoutIcon);
        const logoutLabel = document.createElement('span');
        logoutLabel.className = 'hidden sm:inline';
        logoutLabel.textContent = '登出';
        logoutBtn.appendChild(logoutLabel);
        logoutBtn.addEventListener('click', async () => {
            logoutBtn.disabled = true;
            try {
                await fetch('/api/logout', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (_e) { /* 即便失败也跳登录 */ }
            window.location.href = '/login';
        });
        linkGroup.appendChild(logoutBtn);

        nav.appendChild(linkGroup);
        mount.appendChild(nav);
        if (window.lucide) lucide.createIcons();
    }

    function init() {
        const mount = document.getElementById('app-topnav');
        if (mount && !mount.dataset.rendered) {
            render(mount);
            mount.dataset.rendered = '1';
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
