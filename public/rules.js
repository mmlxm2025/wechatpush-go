/*
 * 接收规则页脚本。
 *
 * 多应用（P1-02 §3.6）：迁移到共享基础设施。
 *   - 使用 window.AppHttp（统一 401 处理、错误码、版本头），不再定义本地 requestJson / 裸 fetch。
 *   - 使用 window.AppModal 取代 window.confirm（规则重生成 / 删除等危险操作）。
 *   - 使用 window.AppToast 取代本地 setStatus 风格（保留 setStatus 兼容）。
 *   - 配置级安全设置（Code 发送开关 / 通知密钥）唯一在编辑页管理，本页不再渲染第二套控件。
 * 多应用（P0-03）：规则写操作携带版本（If-Match），成功采用服务端 app_version，不本地 +1。
 * 多应用（R-P1-02）：版本冲突保留完整规则表单（名称/接收范围/估算人数）后重新确认。
 * 多应用（R-P1-06）：跨应用快速切换用代次守卫丢弃过期异步响应，避免成员/规则倒灌。
 */
document.addEventListener('DOMContentLoaded', function () {
    const http = window.AppHttp;
    const toast = window.AppToast;
    const modal = window.AppModal;
    const H = window.FrontendHelpers;
    // 多应用（二次复验 P1-03）：规则、成员使用独立请求守卫，
    // 避免并发的成员刷新让规则刷新被判为过期，反之亦然。
    // 应用切换时统一推进两个守卫，使所有旧请求失效。
    const rulesGuard = H.createRequestGuard();
    const membersGuard = H.createRequestGuard();

    // SEC-002：会话由 HttpOnly Cookie 携带；清除历史遗留 token 与 URL token。
    try { localStorage.removeItem('authToken'); } catch (e) {}
    const query = new URLSearchParams(window.location.search);
    if (query.get('token')) {
        window.history.replaceState({}, document.title, window.location.pathname + (query.get('code') ? '?code=' + encodeURIComponent(query.get('code')) : ''));
    }

    const configCodeInput = document.getElementById('config-code');
    const loadBtn = document.getElementById('load-btn');
    const statusNode = document.getElementById('status');
    const workspace = document.getElementById('workspace');
    const ruleForm = document.getElementById('rule-form');
    const formTitle = document.getElementById('form-title');
    const ruleIdInput = document.getElementById('rule-id');
    const ruleNameInput = document.getElementById('rule-name');
    const ruleApiCodeInput = document.getElementById('rule-api-code');
    const ruleApiCodeStatus = document.getElementById('rule-api-code-status');
    const ruleApiCodeRandomBtn = document.getElementById('rule-api-code-random');
    const ruleAllInput = document.getElementById('rule-all');
    const customScope = document.getElementById('custom-scope');
    const memberFilter = document.getElementById('member-filter');
    const memberList = document.getElementById('member-list');
    const refreshMembersBtn = document.getElementById('refresh-members-btn');
    const orphanSection = document.getElementById('orphan-section');
    const orphanList = document.getElementById('orphan-list');
    const topartyInput = document.getElementById('rule-toparty');
    const totagInput = document.getElementById('rule-totag');
    const estimatedCountInput = document.getElementById('estimated-count');
    const formError = document.getElementById('form-error');
    const rulesList = document.getElementById('rules-list');
    const resetFormBtn = document.getElementById('reset-form-btn');
    const reloadRulesBtn = document.getElementById('reload-rules-btn');

    let currentCode = query.get('code') || '';
    let currentAppVersion = null; // 多应用（P0-03）：采用服务端 app_version，不本地 +1。
    let configurations = [];
    let rules = [];
    let members = [];
    let selectedUsers = new Set();
    let selectedOrphans = new Set();
    // 接收规则 API 自定义编号（规范 §9.4）：编辑开始时的原始编号，用于改号确认。
    let originalApiCode = '';
    // 可用性预检使用独立请求代次，不复用 rulesGuard/membersGuard，避免相互取消（规范 §9.4）。
    const apiCodeRequestGuard = H.createRequestGuard();
    // 可用性预检防抖计时器。
    let apiCodeDebounceTimer = null;
    const API_CODE_CHECK_DELAY_MS = 300;

    function refreshIcons() {
        if (window.lucide) window.lucide.createIcons();
    }

    function clear(node) {
        while (node.firstChild) node.removeChild(node.firstChild);
    }

    function icon(name, size = 'icon-sm') {
        const node = document.createElement('i');
        node.setAttribute('data-lucide', name);
        node.className = size;
        return node;
    }

    function textButton(label, iconName, className) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = className;
        button.appendChild(icon(iconName));
        button.appendChild(document.createTextNode(label));
        return button;
    }

    function normalizeList(value) {
        const list = Array.isArray(value) ? value : String(value || '').split(/[|,，;；\s]+/);
        return [...new Set(list.map(item => String(item).trim()).filter(Boolean))];
    }

    function setStatus(message, type = 'info') {
        // 兼容旧渲染：以 toast 为主，status 节点用于内联提示。
        clear(statusNode);
        if (!message) return;
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} py-2`;
        const span = document.createElement('span');
        span.textContent = message;
        alert.appendChild(span);
        statusNode.appendChild(alert);
    }

    function setFormError(message) {
        clear(formError);
        if (!message) {
            formError.classList.add('hidden');
            return;
        }
        formError.classList.remove('hidden');
        const span = document.createElement('span');
        span.textContent = message;
        formError.appendChild(span);
    }

    // 接收规则 API 自定义编号（规范 §9）：编号输入状态与可用性预检。
    // 本地格式校验与后端一致（镜像 src/core/notify-code.js 的规则）。
    function isValidLocalApiCode(value) {
        const normalized = String(value == null ? '' : value).trim().toLowerCase();
        if (normalized.length < 3 || normalized.length > 64) return false;
        return /^[a-z0-9][a-z0-9_-]*[a-z0-9]$/.test(normalized);
    }

    function setApiCodeStatus(message, type) {
        clear(ruleApiCodeStatus);
        if (!message) {
            ruleApiCodeStatus.classList.add('hidden');
            ruleApiCodeStatus.removeAttribute('role');
            return;
        }
        ruleApiCodeStatus.classList.remove('hidden');
        // 格式错误用 role=alert（立即通告），可用性结果用 role=status（礼貌通告）。
        ruleApiCodeStatus.setAttribute('role', type === 'error' ? 'alert' : 'status');
        ruleApiCodeStatus.className = `text-xs mt-1 text-${type === 'error' ? 'error' : (type === 'success' ? 'success' : 'base-content/60')}`;
        const span = document.createElement('span');
        span.textContent = message;
        ruleApiCodeStatus.appendChild(span);
    }

    function clearApiCodeState() {
        originalApiCode = '';
        if (apiCodeDebounceTimer) {
            clearTimeout(apiCodeDebounceTimer);
            apiCodeDebounceTimer = null;
        }
        setApiCodeStatus('');
    }

    // 可用性预检（规范 §9.2/§9.3）：输入停顿 ~300ms 后查询，旧响应用独立代次丢弃。
    async function checkApiCodeAvailability() {
        const raw = ruleApiCodeInput.value.trim();
        if (!raw) {
            setApiCodeStatus('');
            return;
        }
        if (!isValidLocalApiCode(raw)) {
            setApiCodeStatus('编号格式不合法（3～64 位小写字母/数字/-/_，首尾为字母或数字）', 'error');
            return;
        }
        const gen = apiCodeRequestGuard.next();
        const params = new URLSearchParams({ api_code: raw });
        if (ruleIdInput.value) params.set('rule_id', ruleIdInput.value);
        const res = await http.get(`/api/rule-api-codes/availability?${params.toString()}`);
        // 旧响应丢弃：当前代次已变（用户继续输入或切换应用）。
        if (!apiCodeRequestGuard.isCurrent(gen)) return;
        if (!res.ok) {
            // 网络错误或格式错误：格式错误由后端返回时不覆盖用户输入，仅提示。
            if (res.code === 'RULE_API_CODE_INVALID') {
                setApiCodeStatus('编号格式不合法', 'error');
            }
            return;
        }
        if (res.data.available) {
            setApiCodeStatus('编号可用', 'success');
        } else if (res.data.reason === 'configuration') {
            setApiCodeStatus('该编号与应用 Code 冲突，请更换', 'error');
        } else if (res.data.reason === 'retired') {
            setApiCodeStatus('该编号已被保留，不能使用', 'error');
        } else {
            setApiCodeStatus('该编号已被占用，请更换', 'error');
        }
    }

    function scheduleApiCodeCheck() {
        if (apiCodeDebounceTimer) clearTimeout(apiCodeDebounceTimer);
        apiCodeDebounceTimer = setTimeout(() => {
            apiCodeDebounceTimer = null;
            checkApiCodeAvailability();
        }, API_CODE_CHECK_DELAY_MS);
    }

    // 客户端生成随机编号（与后端 generateNotifyCode 一致：crypto.randomUUID）。
    // 用于“随机”按钮：新建时一键填入随机 UUID；编辑时清空后重新随机。
    function generateRandomApiCode() {
        return crypto.randomUUID();
    }

    // “随机”按钮：填入随机编号并立即校验可用性。
    // 用户反馈：编辑态清空不会自动生成，改为显式点击“随机”生成。
    function fillRandomApiCode() {
        const code = generateRandomApiCode();
        ruleApiCodeInput.value = code;
        setApiCodeStatus('');
        setFormError('');
        // 推进代次使任何在途的旧可用性响应失效，然后立即校验新编号。
        apiCodeRequestGuard.next();
        checkApiCodeAvailability();
        ruleApiCodeInput.focus();
    }

    // 多应用（P0-03）：版本冲突统一处理——刷新列表并提示重新确认，不本地猜版本。
    // 多应用（R-P1-02）：版本冲突——快照当前规则表单输入，刷新最新数据后恢复，
    // 让用户对比最新规则列表与自己的改动后再次确认（不直接清空表单）。
    // 多应用（二次复验 P1-03）：conflictCode 绑定发起写时的 currentCode；
    // 只有 currentCode === conflictCode 且最新规则成功返回时才恢复表单，
    // 避免冲突快照被恢复到已切换后的新应用。
    async function handleRuleWriteConflict(res, conflictCode) {
        if (!http.isVersionConflict(res)) return false;
        // 若用户已切换到其他应用，丢弃本次冲突恢复（表单属于旧应用）。
        if (conflictCode && currentCode !== conflictCode) return false;
        // 快照当前表单（含名称/接收范围/估算人数/全体开关/api_code）。
        const snap = H.snapshotRuleForm(getPayload());
        // 规范 §9.5：补充 rule_id 与 original_api_code，确保冲突恢复后能重新计算改号确认。
        snap.rule_id = ruleIdInput.value ? String(ruleIdInput.value) : '';
        snap.original_api_code = originalApiCode;
        toast.show('应用已在其他页面更新，正在刷新', { type: 'warn' });
        // 只刷新规则数据，不重置编辑器表单（loadRules 会 resetForm）。
        const data = await refreshRulesData();
        // 刷新失败或应用已切换：不恢复表单。
        if (!data || (conflictCode && currentCode !== conflictCode)) return true;
        // 恢复用户输入，提示重新确认。
        restoreFormFromSnapshot(snap);
        setFormError('应用已被其他页面更新，请核对最新规则后再次保存');
        return true;
    }

    // 从快照恢复规则表单（直接操作 DOM 输入元素）。
    // 规范 §9.5：快照必须包含 api_code / rule_id / original_api_code，
    // 避免版本冲突刷新后只恢复名称/接收范围却丢掉用户输入的编号。
    function restoreFormFromSnapshot(snap) {
        ruleNameInput.value = snap.name || '';
        ruleApiCodeInput.value = snap.api_code || '';
        if (snap.original_api_code !== undefined) {
            originalApiCode = String(snap.original_api_code || '').toLowerCase();
        }
        if (snap.rule_id !== undefined) {
            ruleIdInput.value = snap.rule_id ? String(snap.rule_id) : '';
        }
        ruleAllInput.checked = !!snap.is_all;
        topartyInput.value = snap.toparty || '';
        totagInput.value = snap.totag || '';
        estimatedCountInput.value = String(snap.estimated_count || 1);
        selectedUsers = new Set(Array.isArray(snap.touser) ? snap.touser : []);
        toggleScopeMode();
        renderMembers();
        renderOrphans();
    }

    function configOptionText(config) {
        const description = config.description ? ` - ${config.description}` : '';
        const status = config.completed ? '' : '（未完成）';
        return `${config.code}${description}${status}`;
    }

    function renderConfigOptions() {
        clear(configCodeInput);
        if (configurations.length === 0) {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = '暂无可用配置';
            configCodeInput.appendChild(option);
            configCodeInput.disabled = true;
            loadBtn.disabled = true;
            return;
        }

        configCodeInput.disabled = false;
        loadBtn.disabled = false;
        configurations.forEach(config => {
            const option = document.createElement('option');
            option.value = config.code;
            option.textContent = configOptionText(config);
            option.disabled = !config.completed;
            configCodeInput.appendChild(option);
        });
    }

    // 多应用（§7.4）：当前应用上下文与状态横幅。安全设置入口指向编辑页（单一编辑位置）。
    function renderAppContext(configSummary) {
        const section = document.getElementById('app-context');
        const nameEl = document.getElementById('app-context-name');
        const agentidEl = document.getElementById('app-context-agentid');
        const statusEl = document.getElementById('app-context-status');
        const warnEl = document.getElementById('app-context-warn');
        const editLink = document.getElementById('app-context-edit-security');
        if (!section || !configSummary) {
            if (section) section.classList.add('hidden');
            return;
        }
        section.classList.remove('hidden');
        nameEl.textContent = configSummary.description || '未命名应用';
        agentidEl.textContent = 'AgentID ' + (configSummary.agentid || '—');
        // 多应用（P2-01 / R-P1-03）：严格读取服务端 lifecycle_status，
        // 缺失时显示“未知/需刷新”，不把协议缺失解释为运行中。
        const lifecycle = configSummary.lifecycle_status;
        const map = {
            draft: { label: '待完善', cls: 'app-badge--draft' },
            active: { label: '运行中', cls: 'app-badge--active' },
            paused: { label: '已暂停', cls: 'app-badge--paused' }
        };
        const cfg = map[lifecycle] || { label: '未知', cls: 'app-badge--draft' };
        statusEl.textContent = cfg.label;
        statusEl.className = 'app-badge ' + cfg.cls;
        // 多应用（R-P1-03）：消费服务端 warnings（含 duplicate_identity）。
        const warnings = Array.isArray(configSummary.warnings) ? configSummary.warnings : [];
        if (lifecycle === 'paused') {
            warnEl.textContent = '总开关暂停中：发送被拦截，规则管理仍可使用。';
            warnEl.classList.remove('hidden');
        } else if (warnings.includes('duplicate_identity')) {
            warnEl.textContent = '该应用与其他应用存在重复身份（同企业同 AgentID），建议治理。';
            warnEl.classList.remove('hidden');
        } else {
            warnEl.classList.add('hidden');
        }
        editLink.href = '/edit?code=' + encodeURIComponent(currentCode) + '&tab=security';
    }

    async function loadConfigurations() {
        const res = await http.get('/api/configurations');
        if (!res.ok) {
            workspace.classList.add('hidden');
            setStatus(res.error || '加载配置失败', 'error');
            return;
        }
        configurations = Array.isArray(res.data && res.data.configurations) ? res.data.configurations : [];
        renderConfigOptions();

        const completed = configurations.filter(config => config.completed);
        if (completed.length === 0) {
            workspace.classList.add('hidden');
            setStatus(configurations.length === 0 ? '暂无配置，请先返回首页创建配置' : '暂无已完成配置，请先完成第二步配置', 'warning');
            return;
        }

        const requested = completed.find(config => config.code === currentCode);
        currentCode = requested ? requested.code : completed[0].code;
        configCodeInput.value = currentCode;
        await loadRules();
        refreshIcons();
    }

    // 多应用（R-P1-06 / 二次复验 P1-03）：刷新规则数据，但不重置编辑器表单。
    // 这样规则写 409 后调用 refreshRulesData() 不会丢失用户正在编辑的输入。
    // 使用独立的 rulesGuard，避免与成员刷新互相误判过期。
    async function refreshRulesData() {
        const gen = rulesGuard.next();
        const code = currentCode;
        const res = await http.get(`/api/configuration/${encodeURIComponent(code)}/rules`);
        // 丢弃过期响应（用户已切换到其他应用）。
        if (code !== currentCode || !rulesGuard.isCurrent(gen)) return null;
        if (!res.ok) {
            workspace.classList.add('hidden');
            setStatus(res.error || '加载规则失败', 'error');
            return null;
        }
        const data = res.data || {};
        rules = Array.isArray(data.rules) ? data.rules : [];
        // 多应用（P0-03）：保存服务端聚合版本，规则写操作携带此版本。
        currentAppVersion = (data.config && Number(data.config.version)) || null;
        workspace.classList.remove('hidden');
        renderRules();
        renderAppContext(data.config);
        return data;
    }

    async function loadRules() {
        currentCode = configCodeInput.value.trim();
        if (!currentCode) {
            setStatus('请输入配置 Code', 'warning');
            return;
        }

        loadBtn.disabled = true;
        setStatus('');
        // 多应用（R-P1-06 / 二次复验 P1-03）：切换应用时立即清空上一个应用的成员/编辑态，
        // 并统一推进守卫使所有旧请求失效。currentAppVersion 置空直到新响应成功。
        // 规范 §9.4：可用性预检使用独立守卫，切换应用时一并推进，旧应用的可用性响应被丢弃。
        rulesGuard.next();
        membersGuard.next();
        apiCodeRequestGuard.next();
        members = [];
        selectedUsers = new Set();
        selectedOrphans = new Set();
        currentAppVersion = null;
        // 切换应用立即清空/禁用旧规则操作区，避免用户操作旧行。
        clear(rulesList);
        workspace.classList.add('hidden');
        resetForm();
        try {
            const data = await refreshRulesData();
            if (data) {
                await loadMembers(false);
            }
        } finally {
            loadBtn.disabled = false;
            refreshIcons();
        }
    }

    async function loadMembers(refresh) {
        if (!currentCode) return;
        refreshMembersBtn.disabled = true;
        // 多应用（二次复验 P1-03）：使用独立的 membersGuard。
        const gen = membersGuard.next();
        const code = currentCode;
        try {
            const suffix = refresh ? '?refresh=1' : '';
            const res = await http.get(`/api/configuration/${encodeURIComponent(code)}/users${suffix}`);
            // 丢弃过期响应（用户已切换到其他应用）。
            if (code !== currentCode || !membersGuard.isCurrent(gen)) return;
            if (!res.ok) {
                // 加载失败显示空状态，不保留上一个应用的成员。
                members = [];
                renderMembers();
                setStatus(res.error || '加载成员失败', 'error');
                return;
            }
            const data = res.data || {};
            members = Array.isArray(data.users) ? data.users.filter(user => user && user.userid) : [];
            if (data.warning) {
                setStatus(data.warning, 'warning');
            }
            renderMembers();
        } finally {
            // 多应用（二次复验 P1-03）：只能由当前请求恢复按钮，旧请求不得提前解锁。
            if (membersGuard.isCurrent(gen)) {
                refreshMembersBtn.disabled = false;
            }
            refreshIcons();
        }
    }

    function resetForm() {
        ruleIdInput.value = '';
        ruleNameInput.value = '';
        ruleApiCodeInput.value = '';
        ruleAllInput.checked = false;
        topartyInput.value = '';
        totagInput.value = '';
        estimatedCountInput.value = '1';
        selectedUsers = new Set();
        selectedOrphans = new Set();
        formTitle.textContent = '新建规则';
        setFormError('');
        clearApiCodeState();
        toggleScopeMode();
        renderMembers();
        renderOrphans();
    }

    function editRule(rule) {
        ruleIdInput.value = String(rule.id);
        ruleNameInput.value = rule.name || '';
        ruleApiCodeInput.value = rule.api_code || '';
        // 规范 §9.4：编辑开始时记录原始编号，用于保存前判断是否需要改号确认。
        originalApiCode = String(rule.api_code || '').toLowerCase();
        ruleAllInput.checked = rule.is_all === true;
        topartyInput.value = normalizeList(rule.toparty).join('|');
        totagInput.value = normalizeList(rule.totag).join('|');
        estimatedCountInput.value = String(rule.estimated_count || 1);
        selectedUsers = new Set(normalizeList(rule.touser));
        const visible = new Set(members.map(user => String(user.userid)));
        selectedOrphans = new Set([...selectedUsers].filter(userid => !visible.has(userid)));
        formTitle.textContent = '编辑规则';
        setFormError('');
        setApiCodeStatus('');
        toggleScopeMode();
        renderMembers();
        renderOrphans();
    }

    function toggleScopeMode() {
        customScope.classList.toggle('hidden', ruleAllInput.checked);
    }

    function visibleMembers() {
        const keyword = memberFilter.value.trim().toLowerCase();
        return members.filter(user => {
            const userid = String(user.userid || '').toLowerCase();
            const name = String(user.displayName || user.name || user.userid || '').toLowerCase();
            return !keyword || userid.includes(keyword) || name.includes(keyword);
        });
    }

    function renderMembers() {
        clear(memberList);
        const list = visibleMembers();
        if (ruleAllInput.checked) return;

        if (list.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'text-sm text-base-content/60 text-center py-3';
            empty.textContent = members.length === 0 ? '暂无成员' : '无匹配成员';
            memberList.appendChild(empty);
            return;
        }

        list.forEach(user => {
            const userid = String(user.userid);
            const label = document.createElement('label');
            label.className = 'flex items-center gap-2 rounded-md border border-base-200 p-2 hover:bg-base-200/60';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'checkbox checkbox-sm';
            checkbox.value = userid;
            checkbox.checked = selectedUsers.has(userid);
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) selectedUsers.add(userid);
                else selectedUsers.delete(userid);
                updateEstimateFromExplicitUsers();
            });

            const textWrap = document.createElement('span');
            textWrap.className = 'min-w-0';
            const name = document.createElement('span');
            name.className = 'block truncate';
            name.textContent = user.displayName || user.name || userid;
            const id = document.createElement('span');
            id.className = 'block truncate text-xs text-base-content/50 font-mono';
            id.textContent = userid;
            textWrap.appendChild(name);
            textWrap.appendChild(id);

            label.appendChild(checkbox);
            label.appendChild(textWrap);
            memberList.appendChild(label);
        });
    }

    function renderOrphans() {
        clear(orphanList);
        const orphans = [...selectedOrphans];
        orphanSection.classList.toggle('hidden', orphans.length === 0 || ruleAllInput.checked);
        orphans.forEach(userid => {
            const label = document.createElement('label');
            label.className = 'flex items-center gap-2 rounded-md border border-error bg-error/10 p-2 text-error';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'checkbox checkbox-xs';
            checkbox.value = userid;
            checkbox.checked = true;
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    selectedOrphans.add(userid);
                    selectedUsers.add(userid);
                } else {
                    selectedOrphans.delete(userid);
                    selectedUsers.delete(userid);
                }
                updateEstimateFromExplicitUsers();
            });

            const text = document.createElement('span');
            text.className = 'font-mono text-xs';
            text.textContent = userid;
            const reason = document.createElement('span');
            reason.className = 'text-xs font-medium';
            reason.textContent = '成员不可见或成员已删除';

            label.appendChild(checkbox);
            label.appendChild(text);
            label.appendChild(reason);
            orphanList.appendChild(label);
        });
    }

    function updateEstimateFromExplicitUsers() {
        const toparty = normalizeList(topartyInput.value);
        const totag = normalizeList(totagInput.value);
        if (!ruleAllInput.checked && toparty.length === 0 && totag.length === 0) {
            estimatedCountInput.value = String(Math.max(1, selectedUsers.size));
        }
    }

    function getPayload() {
        const isAll = ruleAllInput.checked;
        const visibleSelected = Array.from(memberList.querySelectorAll('input[type=checkbox]:checked'))
            .map(checkbox => checkbox.value);
        const hiddenVisibleUserids = [...selectedUsers].filter(userid => {
            return !visibleMembers().some(user => String(user.userid) === userid)
                && !selectedOrphans.has(userid);
        });
        const touser = isAll
            ? []
            : [...new Set([...visibleSelected, ...hiddenVisibleUserids, ...selectedOrphans])];
        const apiCodeRaw = ruleApiCodeInput.value.trim();
        const payload = {
            name: ruleNameInput.value.trim(),
            is_all: isAll,
            touser,
            toparty: topartyInput.value,
            totag: totagInput.value,
            estimated_count: Number(estimatedCountInput.value) || 1
        };
        // 规范 §9.5：对外字段统一 api_code。创建时空值从 payload 删除（语义更清楚）。
        if (apiCodeRaw) {
            payload.api_code = apiCodeRaw;
        }
        return payload;
    }

    async function saveRule(event) {
        event.preventDefault();
        setFormError('');
        const payload = getPayload();
        if (!payload.name) {
            setFormError('规则名称不能为空');
            return;
        }
        if (!payload.is_all && payload.touser.length === 0 && normalizeList(payload.toparty).length === 0 && normalizeList(payload.totag).length === 0) {
            setFormError('请至少配置一个接收范围');
            return;
        }

        const id = ruleIdInput.value;
        // 多应用（P0-03）：所有规则写操作携带当前聚合版本（If-Match via AppHttp）。
        const opts = { version: currentAppVersion, button: event.submitter || document.getElementById('save-rule-btn') };
        // 多应用（二次复验 P1-03）：捕获发起写时的 currentCode，冲突恢复绑定原 code。
        const writeCode = currentCode;

        // 实际提交逻辑：封装为函数，便于改号确认走 onConfirm 回调（与 regenerate/delete 一致）。
        // 返回 true=成功可关模态；false=失败保留模态（冲突/校验错误）。
        const submit = async () => {
            let res;
            if (id) {
                res = await http.put(`/api/rules/${encodeURIComponent(id)}`, payload, opts);
            } else {
                // 必须用发起时捕获的 writeCode：改号确认弹窗期间若用户切换了应用，
                // 用 currentCode 会把规则写到错误应用；opts.version 也是 writeCode 对应版本。
                res = await http.post(`/api/configuration/${encodeURIComponent(writeCode)}/rules`, payload, opts);
            }
            if (res.ok) {
                // 多应用（第三轮复验 P1-05）：写成功响应归属检查——
                // 若写发起时的应用已不是当前应用（用户切换到 B），不修改 B 的状态。
                if (writeCode && currentCode !== writeCode) {
                    toast.show('应用已切换，规则写入已在原应用完成', { type: 'info' });
                    return true;
                }
                // 采用服务端返回的 app_version，不本地 +1。
                if (res.version) currentAppVersion = res.version;
                // 规范 §9.7：改号成功提示新地址生效、旧地址失效。
                const apiChanged = res.data && res.data.api_code_changed === true;
                if (apiChanged) {
                    toast.show('规则已更新，新 API 地址已生效；旧地址已失效。', { type: 'success' });
                } else {
                    toast.show(id ? '规则已更新' : '规则已创建', { type: 'success' });
                }
                resetForm();
                await loadRules();
                return true;
            }
            // 接收规则 API 自定义编号（规范 §9.6）：编号格式错误聚焦输入框；编号冲突保留表单。
            // 不按 res.error 中文文案判断，按 res.code 分支。
            if (res.code === 'RULE_API_CODE_INVALID') {
                setApiCodeStatus('编号格式不合法（3～64 位小写字母/数字/-/_，首尾为字母或数字）', 'error');
                ruleApiCodeInput.focus();
                return false;
            }
            if (res.code === 'RULE_API_CODE_CONFLICT') {
                const scope = res.details && res.details.conflict_scope;
                const hint = scope === 'configuration'
                    ? '该编号与应用 Code 冲突，请更换'
                    : (scope === 'retired' ? '该编号已被保留，不能使用' : '该编号已占用或已被保留，请更换');
                setApiCodeStatus(hint, 'error');
                ruleApiCodeInput.focus();
                return false;
            }
            // 版本冲突：刷新列表后让用户重新确认（绑定原 code，避免跨应用恢复）。
            if (await handleRuleWriteConflict(res, writeCode)) return false;
            setFormError(res.error || '保存失败');
            return false;
        };

        // 接收规则 API 自定义编号（规范 §9.3）：编辑态修改编号前确认旧地址立即失效。
        // 使用 onConfirm 回调（与 regenerate/delete 一致），失败返回 false 保留模态。
        if (id && payload.api_code !== undefined) {
            const nextNormalized = String(payload.api_code).trim().toLowerCase();
            if (nextNormalized !== originalApiCode) {
                modal.confirm({
                    title: '修改 API 编号',
                    body: `修改 API 编号后，旧地址 /api/notify/${originalApiCode} 将立即失效。\n请确认调用方会改用 /api/notify/${nextNormalized}。`,
                    confirmText: '确认修改',
                    confirmType: 'warning',
                    onConfirm: async () => submit()
                });
                return;
            }
        }

        await submit();
    }

    function scopeText(rule) {
        if (rule.is_all) return '全体人员';
        const parts = [];
        const users = normalizeList(rule.touser);
        const parties = normalizeList(rule.toparty);
        const tags = normalizeList(rule.totag);
        if (users.length) parts.push(`成员 ${users.length}`);
        if (parties.length) parts.push(`部门 ${parties.join('|')}`);
        if (tags.length) parts.push(`标签 ${tags.join('|')}`);
        return parts.join(' / ') || '未配置';
    }

    function renderRules() {
        clear(rulesList);
        if (rules.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'app-type-lead text-base-content/60 py-8 text-center';
            empty.textContent = '暂无规则';
            rulesList.appendChild(empty);
            return;
        }

        // 卡片列表：PC/移动端统一可读，避免宽表横向溢出（mobile-first 响应式）。
        const list = document.createElement('div');
        list.className = 'space-y-3';
        list.setAttribute('role', 'list');

        rules.forEach(rule => {
            const card = document.createElement('article');
            card.className = 'app-rule-card card-hover';
            card.setAttribute('role', 'listitem');

            const head = document.createElement('div');
            head.className = 'app-rule-card__head';

            const title = document.createElement('h3');
            title.className = 'app-rule-card__title';
            title.textContent = rule.name || '未命名规则';
            head.appendChild(title);

            // 启停开关：禁用的规则其 API 发送返回 403，但规则保留。
            const enabledLabel = document.createElement('label');
            enabledLabel.className = 'cursor-pointer flex items-center gap-2 flex-shrink-0';
            const enabledToggle = document.createElement('input');
            enabledToggle.type = 'checkbox';
            enabledToggle.className = 'toggle toggle-sm toggle-success';
            enabledToggle.checked = rule.enabled !== false;
            const enabledText = document.createElement('span');
            enabledText.className = 'app-type-caption text-base-content/70';
            const updateToggleA11y = (checked) => {
                const action = checked ? '禁用' : '启用';
                const label = `${action}规则：${rule.name || '未命名规则'}`;
                enabledToggle.title = label;
                enabledToggle.setAttribute('aria-label', label);
                enabledText.textContent = checked ? '已启用' : '已禁用';
            };
            updateToggleA11y(enabledToggle.checked);
            enabledToggle.addEventListener('change', async () => {
                const next = enabledToggle.checked;
                // 多应用（二次复验 P1-03）：请求期间禁用 toggle，避免快速双击并发提交同一版本。
                enabledToggle.disabled = true;
                // 多应用（P0-03）：规则启停携带版本。
                const writeCode = currentCode;
                const res = await http.put(
                    `/api/rules/${encodeURIComponent(rule.id)}/enabled`,
                    { enabled: next },
                    { version: currentAppVersion }
                );
                enabledToggle.disabled = false;
                if (res.ok) {
                    // 多应用（第三轮复验 P1-05）：启停成功响应归属检查——
                    // 若用户已切换到其他应用，不得把旧应用的返回版本写入当前应用。
                    if (writeCode && currentCode !== writeCode) {
                        toast.show('应用已切换，规则启停已在原应用完成', { type: 'info' });
                        return;
                    }
                    if (res.version) currentAppVersion = res.version;
                    updateToggleA11y(next);
                    toast.show(next ? `规则「${rule.name}」已启用` : `规则「${rule.name}」已禁用，其 API 将拒绝发送`, { type: next ? 'success' : 'warn' });
                } else {
                    enabledToggle.checked = !next; // 回滚
                    updateToggleA11y(enabledToggle.checked);
                    if (await handleRuleWriteConflict(res, writeCode)) return;
                    toast.show(res.error || '切换规则开关失败', { type: 'error' });
                }
            });
            enabledLabel.appendChild(enabledToggle);
            enabledLabel.appendChild(enabledText);
            head.appendChild(enabledLabel);
            card.appendChild(head);

            const meta = document.createElement('dl');
            meta.className = 'app-rule-card__meta';

            const scopeDt = document.createElement('dt');
            scopeDt.textContent = '范围';
            const scopeDd = document.createElement('dd');
            scopeDd.textContent = scopeText(rule);
            meta.appendChild(scopeDt);
            meta.appendChild(scopeDd);

            const apiDt = document.createElement('dt');
            apiDt.textContent = 'API';
            const apiDd = document.createElement('dd');
            const apiCode = document.createElement('code');
            apiCode.className = 'font-mono text-xs sm:text-sm break-all';
            apiCode.textContent = rule.apiUrl || `/api/notify/${rule.api_code}`;
            apiDd.appendChild(apiCode);
            meta.appendChild(apiDt);
            meta.appendChild(apiDd);
            card.appendChild(meta);

            const actions = document.createElement('div');
            actions.className = 'app-rule-card__actions';

            const editBtn = textButton('编辑', 'pencil', 'btn btn-xs btn-outline');
            editBtn.addEventListener('click', () => editRule(rule));
            actions.appendChild(editBtn);

            const copyBtn = textButton('复制', 'copy', 'btn btn-xs btn-outline');
            copyBtn.addEventListener('click', () => {
                // 规范 §9.7：复制按钮优先使用服务端返回的 rule.apiUrl；fallback 拼接时对路径段编码。
                const apiUrl = window.location.origin + (rule.apiUrl || `/api/notify/${encodeURIComponent(rule.api_code)}`);
                navigator.clipboard.writeText(apiUrl);
                toast.show('API 已复制', { type: 'success' });
            });
            actions.appendChild(copyBtn);

            // 多应用（P1-02）：危险操作用 AppModal 确认，不再用 window.confirm。
            const regenBtn = textButton('重生成', 'refresh-cw', 'btn btn-xs btn-warning');
            regenBtn.addEventListener('click', () => {
                modal.confirm({
                    title: '重新生成规则 API',
                    body: '重新生成后旧地址会立即失效，调用方需更新为新地址。旧编号会被保留，不能分配给其他规则。是否继续？',
                    confirmText: '重新生成',
                    confirmType: 'warning',
                    onConfirm: async () => {
                        const writeCode = currentCode;
                        // 无业务 body：传 undefined（勿传 null）。null 会被 stringify 成 "null"，
                        // express.json(strict) 会判为非法 JSON →「请求体不是合法的 JSON」。
                        const res = await http.post(
                            `/api/rules/${encodeURIComponent(rule.id)}/regenerate`,
                            undefined,
                            { version: currentAppVersion }
                        );
                        if (res.ok) {
                            // 多应用（第三轮复验 P1-05）：重生成成功响应归属检查。
                            if (writeCode && currentCode !== writeCode) {
                                toast.show('应用已切换，规则 API 重生成已在原应用完成', { type: 'info' });
                                return true;
                            }
                            if (res.version) currentAppVersion = res.version;
                            toast.show('规则 API 已重新生成', { type: 'success' });
                            await loadRules();
                            return true;
                        }
                        if (await handleRuleWriteConflict(res, writeCode)) return true;
                        toast.show(res.error || '重新生成失败', { type: 'error' });
                        return false;
                    }
                });
            });
            actions.appendChild(regenBtn);

            const deleteBtn = textButton('删除', 'trash-2', 'btn btn-xs btn-error');
            deleteBtn.addEventListener('click', () => {
                modal.confirm({
                    title: '删除规则',
                    body: `确定删除规则「${rule.name}」吗？此操作不可撤销。`,
                    confirmText: '删除',
                    confirmType: 'danger',
                    onConfirm: async () => {
                        const writeCode = currentCode;
                        const res = await http.del(
                            `/api/rules/${encodeURIComponent(rule.id)}`,
                            { version: currentAppVersion }
                        );
                        if (res.ok) {
                            // 多应用（第三轮复验 P1-05）：删除成功响应归属检查。
                            if (writeCode && currentCode !== writeCode) {
                                toast.show('应用已切换，规则删除已在原应用完成', { type: 'info' });
                                return true;
                            }
                            if (res.version) currentAppVersion = res.version;
                            toast.show('规则已删除', { type: 'warn' });
                            await loadRules();
                            return true;
                        }
                        if (await handleRuleWriteConflict(res, writeCode)) return true;
                        toast.show(res.error || '删除失败', { type: 'error' });
                        return false;
                    }
                });
            });
            actions.appendChild(deleteBtn);

            card.appendChild(actions);
            list.appendChild(card);
        });

        rulesList.appendChild(list);
        refreshIcons();
    }

    loadBtn.addEventListener('click', loadRules);
    configCodeInput.addEventListener('change', loadRules);
    reloadRulesBtn.addEventListener('click', loadRules);
    resetFormBtn.addEventListener('click', resetForm);
    refreshMembersBtn.addEventListener('click', () => loadMembers(true));
    memberFilter.addEventListener('input', renderMembers);
    ruleAllInput.addEventListener('change', () => {
        toggleScopeMode();
        renderMembers();
        renderOrphans();
    });
    topartyInput.addEventListener('input', updateEstimateFromExplicitUsers);
    totagInput.addEventListener('input', updateEstimateFromExplicitUsers);
    // 接收规则 API 自定义编号（规范 §9.2）：输入时防抖触发可用性预检。
    // 切换应用/新建/保存成功时通过 resetForm/clearApiCodeState 清空提示与代次。
    ruleApiCodeInput.addEventListener('input', () => {
        // 每次输入推进代次，使任何在途的旧可用性响应失效。
        apiCodeRequestGuard.next();
        scheduleApiCodeCheck();
    });
    // “随机”按钮：新建/编辑时一键填入随机编号（编辑态清空后用此重新生成）。
    ruleApiCodeRandomBtn.addEventListener('click', fillRandomApiCode);
    ruleForm.addEventListener('submit', saveRule);

    // 多应用（§6.8）：会话守卫。AppHttp 在 401 时已自动跳转登录，这里仅做首屏检查。
    // 未登录时保留 ?code= 等路径到 login?next=，避免深链丢失。
    (async () => {
        try {
            const res = await fetch('/api/auth-status', { credentials: 'same-origin' });
            const data = await res.json();
            if (!data.loggedIn) {
                const here = window.location.pathname + window.location.search + window.location.hash;
                window.location.href = '/login?next=' + encodeURIComponent(here);
                return;
            }
        } catch (_e) {
            const here = window.location.pathname + window.location.search + window.location.hash;
            window.location.href = '/login?next=' + encodeURIComponent(here);
            return;
        }
        refreshIcons();
        await loadConfigurations();
    })();
});
