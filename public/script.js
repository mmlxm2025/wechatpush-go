/*
 * 多应用管理（2026-07-04 §7.2）：应用总览页交互脚本。
 *
 * 重构自旧版首页的两步创建+查找结构，统一为只读总览 + 行内总开关 + 删除影响预览。
 * 创建流程迁移到 /new（向导，阶段5）；编辑迁移到 /edit（阶段6）。
 *
 * 关键约束（设计文档）：
 *   - 只渲染服务端 lifecycle/capabilities/warnings，不自行推导状态（§4.5）。
 *   - toggle 请求期间锁定，不做无法回滚的纯乐观更新（§7.2）。
 *   - 删除前预览关联规则，使用 AppModal 而非 window.confirm（§7.3）。
 *   - 版本冲突保留状态、提示刷新；APP_NOT_FOUND 移除失效行（§7.2）。
 *   - 同源 Cookie 请求，不读写 localStorage/sessionStorage 凭证（§3）。
 *   - 动态文本一律 textContent / createElement，不解析不可信 innerHTML。
 */

document.addEventListener('DOMContentLoaded', function () {
    // SEC-002：清除历史遗留 token；会话统一由 HttpOnly Cookie 携带。
    try { localStorage.removeItem('authToken'); } catch (_e) {}

    const http = window.AppHttp;
    const toast = window.AppToast;
    const modal = window.AppModal;

    const els = {
        loading: document.getElementById('loading-state'),
        empty: document.getElementById('empty-state'),
        error: document.getElementById('error-state'),
        errorMessage: document.getElementById('error-message'),
        retry: document.getElementById('retry-btn'),
        list: document.getElementById('app-list')
    };

    // 当前页面持有的应用版本映射（code -> version），供 toggle/delete 作为 If-Match。
    const versionCache = new Map();

    checkAuth().then(isAuth => { if (isAuth) bootstrap(); });

    function redirectToLogin() {
        try {
            const here = window.location.pathname + window.location.search + window.location.hash;
            window.location.href = '/login?next=' + encodeURIComponent(here);
        } catch (_e) {
            window.location.href = '/login';
        }
    }

    async function checkAuth() {
        try {
            const res = await fetch('/api/auth-status', { credentials: 'same-origin' });
            const data = await res.json();
            if (!data.loggedIn) { redirectToLogin(); return false; }
            return true;
        } catch (_e) {
            redirectToLogin();
            return false;
        }
    }

    function bootstrap() {
        if (window.lucide) lucide.createIcons();
        els.retry.addEventListener('click', loadApps);
        loadApps();
    }

    // ─── 加载与状态切换 ───────────────────────────────────────────────

    function showState(name) {
        els.loading.classList.toggle('hidden', name !== 'loading');
        els.empty.classList.toggle('hidden', name !== 'empty');
        els.error.classList.toggle('hidden', name !== 'error');
        els.list.classList.toggle('hidden', name !== 'list');
    }

    async function loadApps() {
        showState('loading');
        const res = await http.get('/api/configurations');
        if (!res.ok) {
            els.errorMessage.textContent = res.error || '加载应用列表失败';
            showState('error');
            return;
        }
        const apps = (res.data && res.data.configurations) || [];
        if (apps.length === 0) {
            showState('empty');
            if (window.lucide) lucide.createIcons();
            return;
        }
        renderApps(apps);
        showState('list');
        if (window.lucide) lucide.createIcons();
    }

    // ─── 渲染：按 corpid 分组 ─────────────────────────────────────────

    function maskCorpid(corpid) {
        if (!corpid) return '—';
        const s = String(corpid);
        if (s.length <= 8) return s[0] + '…' + s[s.length - 1];
        return s.slice(0, 4) + '…' + s.slice(-4);
    }

    function renderApps(apps) {
        // 缓存版本。
        apps.forEach(a => versionCache.set(a.code, a.version));

        // 按 corpid 分组（完整 corpid 作键，标题只显示脱敏值）。
        const groups = new Map();
        apps.forEach(a => {
            if (!groups.has(a.corpid)) groups.set(a.corpid, []);
            groups.get(a.corpid).push(a);
        });

        els.list.innerHTML = '';
        for (const [corpid, group] of groups) {
            els.list.appendChild(renderGroup(corpid, group));
        }

        // 新建成功返回的高亮（§7.2 ?highlight=<code>，仅一次会话）。
        const highlight = new URLSearchParams(window.location.search).get('highlight');
        if (highlight) {
            const row = els.list.querySelector('[data-code="' + cssEscape(highlight) + '"]');
            if (row) row.classList.add('app-row-highlight');
            // 清掉 query，避免刷新重复高亮。
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    function renderGroup(corpid, group) {
        const section = document.createElement('section');
        section.className = 'glass-card p-3 sm:p-4 space-y-3';

        const header = document.createElement('div');
        header.className = 'flex items-center gap-2 mb-1 flex-wrap';
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'building-2');
        icon.className = 'icon-md text-base-content/60 flex-shrink-0';
        const title = document.createElement('h2');
        title.className = 'app-type-section';
        // 标题只显示脱敏值（§7.2），完整 corpid 不进入 DOM 文本。
        title.textContent = '企业 ' + maskCorpid(corpid);
        const count = document.createElement('span');
        count.className = 'badge badge-ghost';
        count.textContent = group.length + ' 个应用';
        header.appendChild(icon);
        header.appendChild(title);
        header.appendChild(count);
        section.appendChild(header);

        group.forEach(app => section.appendChild(renderAppRow(app)));
        return section;
    }

    // ─── 渲染：单个应用行 ─────────────────────────────────────────────

    const LIFECYCLE = {
        draft: { label: '待完善', badge: 'app-badge--draft', icon: 'alert-triangle' },
        active: { label: '运行中', badge: 'app-badge--active', icon: 'circle-check-big' },
        paused: { label: '已暂停', badge: 'app-badge--paused', icon: 'circle-pause' }
    };

    function renderAppRow(app) {
        const row = document.createElement('article');
        // card-hover 提供统一 hover 抬升过渡（styles.css），配合 8dp 圆角令牌。
        row.className = 'card-hover border border-base-200 rounded-lg p-3 sm:p-4 bg-base-100/60 min-w-0';
        row.setAttribute('data-code', app.code);

        // 第一行：描述 + 状态徽标。
        const top = document.createElement('div');
        top.className = 'flex items-start justify-between gap-2 sm:gap-3 flex-wrap';

        const titleBlock = document.createElement('div');
        titleBlock.className = 'flex-1 min-w-0';
        const desc = document.createElement('div');
        desc.className = 'font-semibold text-base truncate';
        desc.textContent = app.description || '未命名应用';
        const meta = document.createElement('div');
        meta.className = 'app-type-caption text-base-content/60 mt-1 flex items-center flex-wrap gap-x-1 gap-y-0.5 break-words';
        // meta 信息用 · 分隔，更紧凑（§6 whitespace-balance）。
        const metaParts = [
            'AgentID：' + (app.agentid ? app.agentid : '待填写'),
            '默认接收人：' + (app.recipient_count || 0),
            '规则：' + (app.enabled_rule_count || 0) + '/' + (app.rule_count || 0),
            '创建：' + (app.created_at || '-')
        ];
        meta.textContent = metaParts.join(' · ');
        titleBlock.appendChild(desc);
        titleBlock.appendChild(meta);

        top.appendChild(titleBlock);

        // 状态徽标区（主状态 + 重复告警，不混用、不只靠颜色）。
        const statusBlock = document.createElement('div');
        statusBlock.className = 'flex items-center gap-2 flex-wrap flex-shrink-0';
        statusBlock.appendChild(renderStatusBadge(app.lifecycle_status));
        if (Array.isArray(app.warnings) && app.warnings.includes('duplicate_identity')) {
            const dup = document.createElement('span');
            dup.className = 'app-warn-duplicate';
            const dupIcon = document.createElement('i');
            dupIcon.setAttribute('data-lucide', 'copy-x');
            dupIcon.className = 'icon-xs';
            dup.appendChild(dupIcon);
            dup.appendChild(document.createTextNode('重复应用'));
            statusBlock.appendChild(dup);
        }
        top.appendChild(statusBlock);
        row.appendChild(top);

        // 通道摘要（§7.2）：应用 Code 开关 + 规则启用数/总数；暂停时注明总开关暂停中。
        const channel = document.createElement('div');
        channel.className = 'app-type-caption mt-2 sm:mt-3 text-base-content/70 flex items-center gap-2 sm:gap-3 flex-wrap';
        const codeSend = document.createElement('span');
        codeSend.textContent = '应用 Code 发送：' + (app.code_send_enabled ? '开启' : '关闭');
        channel.appendChild(codeSend);
        if (app.lifecycle_status === 'paused') {
            const pausedNote = document.createElement('span');
            pausedNote.className = 'text-error font-medium';
            pausedNote.textContent = '（总开关暂停中）';
            channel.appendChild(pausedNote);
        }
        row.appendChild(channel);

        // 操作行：总开关 + 编辑/规则/安全（按 capabilities 显示）。
        // §4 primary-action：编辑为主操作（btn-primary），次要操作 btn-ghost；
        // 删除右移隔离（§8 destructive-emphasis）；窄屏由 .app-row-actions 网格布局接管。
        const actions = document.createElement('div');
        actions.className = 'app-row-actions mt-2 sm:mt-3';
        const toggle = renderMasterToggle(app);
        toggle.classList.add('app-row-toggle');
        actions.appendChild(toggle);
        appendCapabilityAction(actions, app, {
            cond: app.lifecycle_status === 'draft',
            href: '/new?code=' + encodeURIComponent(app.code),
            label: '继续配置', icon: 'arrow-right', variant: 'primary'
        });
        appendCapabilityAction(actions, app, {
            cond: app.capabilities && app.capabilities.can_edit,
            href: '/edit?code=' + encodeURIComponent(app.code),
            label: '编辑', icon: 'pencil', variant: 'primary'
        });
        appendCapabilityAction(actions, app, {
            cond: app.capabilities && app.capabilities.can_manage_rules,
            href: '/rules?code=' + encodeURIComponent(app.code),
            label: '规则', icon: 'route', variant: 'ghost'
        });
        appendCapabilityAction(actions, app, {
            cond: app.capabilities && app.capabilities.can_manage_security,
            href: '/edit?code=' + encodeURIComponent(app.code) + '&tab=security',
            label: '安全设置', icon: 'shield-check', variant: 'ghost'
        });
        if (app.capabilities && app.capabilities.can_delete) {
            const delBtn = document.createElement('button');
            delBtn.type = 'button';
            // sm:ml-auto 宽屏把删除推到行尾；窄屏由 .app-row-delete 占满整行。
            delBtn.className = 'app-row-delete btn btn-sm btn-ghost btn-error gap-1.5 sm:ml-auto';
            const delIcon = document.createElement('i');
            delIcon.setAttribute('data-lucide', 'trash-2');
            delIcon.className = 'icon-sm';
            delBtn.appendChild(delIcon);
            delBtn.appendChild(document.createTextNode('删除'));
            delBtn.addEventListener('click', () => onDelete(app, delBtn));
            actions.appendChild(delBtn);
        }
        row.appendChild(actions);

        return row;
    }

    function renderStatusBadge(lifecycle) {
        const cfg = LIFECYCLE[lifecycle] || LIFECYCLE.draft;
        const badge = document.createElement('span');
        badge.className = 'app-badge ' + cfg.badge;
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', cfg.icon);
        icon.className = 'icon-xs';
        badge.appendChild(icon);
        badge.appendChild(document.createTextNode(cfg.label));
        return badge;
    }

    // 总开关 toggle：发送启用/暂停切换。请求期间锁定，失败恢复原状态（§7.2）。
    // 多应用（二次复验 P1-04）：文案统一为“发送已启用 / 发送已暂停”，不暗示应用不可管理。
    // renderToggleState 统一更新 checkbox + label + ARIA，避免失败时只回滚 checkbox 而文字脱节。
    function renderToggleState(cb, label, checked) {
        cb.checked = checked;
        label.textContent = checked ? '发送已启用' : '发送已暂停';
        cb.setAttribute('aria-label', checked ? '暂停应用发送' : '启用应用发送');
    }

    function renderMasterToggle(app) {
        const wrap = document.createElement('label');
        wrap.className = 'flex items-center gap-2 cursor-pointer';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'toggle toggle-sm toggle-primary';
        const label = document.createElement('span');
        label.className = 'app-type-caption text-base-content/70';
        // 初始状态。
        renderToggleState(cb, label, app.lifecycle_status === 'active');
        // 辅助说明：暂停只阻止发送，不影响编辑/规则/安全设置（P1-04 术语收口）。
        wrap.title = '暂停只阻止发送，不影响编辑、规则和安全设置';
        // 草稿不能切换（capabilities.can_toggle=false）。
        if (!app.capabilities || !app.capabilities.can_toggle) {
            cb.disabled = true;
            wrap.title = '应用尚未完成配置，不能切换';
        }
        // 切换时即时更新为目标状态（不等重新加载）；失败时由 onToggle 统一回滚。
        cb.addEventListener('change', () => {
            renderToggleState(cb, label, cb.checked);
            onToggle(app, cb, label);
        });
        wrap.appendChild(cb);
        wrap.appendChild(label);
        return wrap;
    }

    function appendCapabilityAction(container, app, action) {
        if (!action.cond) return;
        const a = document.createElement('a');
        a.href = action.href;
        // variant：primary（主操作，btn-primary）/ ghost（次要，btn-ghost）/ outline（默认）。
        const variant = action.variant === 'primary' ? 'btn-primary'
            : action.variant === 'ghost' ? 'btn-ghost'
            : 'btn-outline';
        a.className = 'btn btn-sm ' + variant + ' gap-1.5';
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', action.icon);
        icon.className = 'icon-sm';
        a.appendChild(icon);
        a.appendChild(document.createTextNode(action.label));
        container.appendChild(a);
    }

    // ─── 总开关切换 ──────────────────────────────────────────────────

    // 多应用（二次复验 P1-04）：onToggle 接收 label，失败时通过 renderToggleState
    // 同时回滚 checkbox + label + ARIA，避免网络错误后“勾选+已停用”或“未勾选+启用”脱节。
    async function onToggle(app, cb, label) {
        // 修复反转 bug：change 事件在浏览器切换 cb.checked 之后触发，
        // 因此 cb.checked 已是“目标状态”，target 应直接取 cb.checked。
        // 旧代码用 original=cb.checked、target=!original，等于把目标取反，
        // 导致点击关闭时反而发送 enabled:true（“已恢复发送”反复弹出）。
        const target = cb.checked;        // 切换后的目标状态
        const beforeToggle = !target;     // 切换前的原状态（失败时回滚用）
        cb.disabled = true;
        const version = versionCache.get(app.code);
        const res = await http.put(
            '/api/configuration/' + encodeURIComponent(app.code) + '/app-enabled',
            { enabled: target },
            { version, button: null }
        );
        cb.disabled = false;
        if (res.ok) {
            // 用服务端返回的新版本更新本地，避免下一次用过期版本。
            if (res.version) versionCache.set(app.code, res.version);
            toast.show(target ? '已启用发送' : '已暂停发送', { type: target ? 'success' : 'warn' });
            // 重新加载以刷新 lifecycle 与通道摘要（暂停仍显示子开关原值）。
            loadApps();
        } else {
            // 失败恢复原状态：同时回滚 checkbox + label + ARIA（P1-04）。
            renderToggleState(cb, label, beforeToggle);
            if (res.code === 'APP_VERSION_CONFLICT') {
                toast.show('应用已在其他页面更新，正在刷新', { type: 'warn' });
                loadApps();
            } else if (res.code === 'APP_NOT_FOUND') {
                toast.show('应用不存在或已删除', { type: 'error' });
                loadApps();
            } else {
                toast.show(res.error || '切换失败', { type: 'error' });
            }
        }
    }

    // ─── 删除：影响预览 + 模态确认（§7.3） ───────────────────────────

    async function onDelete(app, btn) {
        btn.disabled = true;
        // 取关联规则用于影响预览（删除前看清规则和失效地址）。
        const rulesRes = await http.get('/api/configuration/' + encodeURIComponent(app.code) + '/rules');
        btn.disabled = false;
        // 预览失败不得当成「0 条规则」继续删：会误导确认文案却仍级联删除全部规则。
        if (!rulesRes.ok) {
            toast.show(rulesRes.error || '无法加载规则列表，删除已取消', { type: 'error' });
            return;
        }
        const rules = (rulesRes.data && rulesRes.data.rules) || [];

        const body = document.createElement('div');
        body.className = 'space-y-2 text-sm';

        const summary = document.createElement('p');
        summary.textContent = '应用「' + (app.description || '未命名应用') + '」（AgentID ' + (app.agentid || '待填写') + '）';
        body.appendChild(summary);

        const rulesNote = document.createElement('p');
        rulesNote.textContent = '将删除 ' + rules.length + ' 条规则：' + (rules.length === 0
            ? '（无）'
            : rules.map(r => r.name || r.api_code).join('、'));
        body.appendChild(rulesNote);

        const impact = document.createElement('p');
        impact.className = 'text-error';
        impact.textContent = '配置 Code、规则 API、回调 URL 都将失效；正在发送的请求可能完成，删除后新请求将返回 404。';
        body.appendChild(impact);

        modal.confirm({
            title: '删除应用',
            body,
            confirmText: '确认删除',
            confirmType: 'danger',
            onConfirm: async () => {
                const version = versionCache.get(app.code);
                const res = await http.del(
                    '/api/configuration/' + encodeURIComponent(app.code),
                    { version }
                );
                if (res.ok) {
                    toast.show('已删除应用（含 ' + (res.data.rules_deleted || 0) + ' 条规则）', { type: 'success' });
                    loadApps();
                    return true;
                }
                if (res.code === 'APP_VERSION_CONFLICT') {
                    toast.show('应用已变化，请重新确认后删除', { type: 'warn' });
                    loadApps();
                    return false;
                }
                if (res.code === 'APP_NOT_FOUND') {
                    toast.show('应用已不存在', { type: 'warn' });
                    loadApps();
                    return true;
                }
                toast.show(res.error || '删除失败', { type: 'error' });
                return false; // 保留模态供重试
            }
        });
    }

    // ─── 工具 ────────────────────────────────────────────────────────

    // 简易 CSS.escape polyfill：用于属性选择器中的 code。
    function cssEscape(value) {
        const s = String(value);
        return s.replace(/["\\\]]/g, '\\$&');
    }
});
