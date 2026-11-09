/*
 * 多应用管理（2026-07-04 §7.4）：应用编辑页脚本。
 *
 * 五个分区：基本信息 / 企业凭证 / 回调配置 / 默认接收人 / 安全设置。
 * 关键约束：
 *   - Payload 只含用户实际修改的字段（touched-field），空 secret/token/aeskey 不发送。
 *   - 所有写请求携带当前版本（If-Match）；版本冲突保留输入、提示刷新（§6.4）。
 *   - paused 仍可编辑（§4.3）；草稿不可编辑（由总览控制 capabilities）。
 *   - corpid 只读（CORPID_IMMUTABLE）；修改 CorpSecret/AgentID 提示会重新验证凭证。
 *   - 敏感输入不回填、不落存储；动态文本用 textContent。
 */
document.addEventListener('DOMContentLoaded', function () {
    const http = window.AppHttp;
    const toast = window.AppToast;
    const modal = window.AppModal;
    // 多应用（第三轮复验 P1-01）：H 在顶层与 http/toast/modal 同级声明，
    // refreshSummary 等独立函数才能引用。原实现仅在 APP_VERSION_CONFLICT 分支内声明，
    // 导致保存成功/缺版本/安全冲突/密钥冲突刷新时抛 ReferenceError: H is not defined。
    const H = window.FrontendHelpers;

    let appCode = null;
    let version = null;
    let original = null;           // 服务端返回的初始详情，用于 diff touched-field
    let picker = null;
    let currentMembers = [];       // { users, current, orphan }

    const els = {
        loading: document.getElementById('loading-state'),
        error: document.getElementById('error-state'),
        errorMessage: document.getElementById('error-message'),
        form: document.getElementById('edit-form'),
        pausedBanner: document.getElementById('paused-banner'),
        duplicateBanner: document.getElementById('duplicate-banner'),
        description: document.getElementById('f-description'),
        agentid: document.getElementById('f-agentid'),
        corpid: document.getElementById('f-corpid'),
        corpsecret: document.getElementById('f-corpsecret'),
        callbackEnabled: document.getElementById('f-callback-enabled'),
        callbackToken: document.getElementById('f-callback-token'),
        aeskey: document.getElementById('f-aeskey'),
        callbackUrlDisplay: document.getElementById('callback-url-display'),
        recipientMount: document.getElementById('recipient-picker-mount'),
        refreshMembersBtn: document.getElementById('refresh-members-btn'),
        codeSendToggle: document.getElementById('f-code-send-enabled'),
        codeSendStatus: document.getElementById('code-send-status'),
        notifyKeyStatus: document.getElementById('notify-key-status'),
        enableNotifyKeyBtn: document.getElementById('enable-notify-key-btn'),
        rotateNotifyKeyBtn: document.getElementById('rotate-notify-key-btn'),
        revokeNotifyKeyBtn: document.getElementById('revoke-notify-key-btn'),
        notifyKeyOnetime: document.getElementById('notify-key-onetime'),
        saveBtn: document.getElementById('save-btn')
    };

    // 成员列表请求代次守卫：防止慢速 refresh 覆盖保存/409 恢复后的 picker 选中态。
    const membersGuard = H.createRequestGuard();

    checkAuth().then(isAuth => { if (isAuth) bootstrap(); });

    function redirectToLogin() {
        // 与 AppHttp.safeRedirectToLogin 契约一致：保留同源相对路径供 login ?next= 消费。
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
        } catch (_e) { redirectToLogin(); return false; }
    }

    function bootstrap() {
        if (window.lucide) lucide.createIcons();
        appCode = new URLSearchParams(window.location.search).get('code');
        if (!appCode) {
            showError('缺少应用 code 参数');
            return;
        }
        // 总览「安全设置」链到 ?tab=security：滚动到安全分区。
        if (new URLSearchParams(window.location.search).get('tab') === 'security') {
            const sec = document.getElementById('security-section');
            if (sec) setTimeout(() => sec.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
        }
        els.saveBtn.addEventListener('click', onSave);
        els.refreshMembersBtn.addEventListener('click', () => loadMembers(true));
        els.codeSendToggle.addEventListener('change', onCodeSendToggle);
        els.enableNotifyKeyBtn.addEventListener('click', () => onNotifyKey('enable'));
        els.rotateNotifyKeyBtn.addEventListener('click', () => onNotifyKey('rotate'));
        els.revokeNotifyKeyBtn.addEventListener('click', () => onNotifyKey('revoke'));
        loadApp();
    }

    function showState(name) {
        els.loading.classList.toggle('hidden', name !== 'loading');
        els.error.classList.toggle('hidden', name !== 'error');
        els.form.classList.toggle('hidden', name !== 'form');
    }
    function showError(msg) { els.errorMessage.textContent = msg || '加载失败'; showState('error'); }

    // ─── 加载应用详情 + 成员 ──────────────────────────────────────────

    async function loadApp() {
        showState('loading');
        const res = await http.get('/api/configuration/' + encodeURIComponent(appCode));
        if (!res.ok || !res.data) {
            showError(res.error || '应用不存在或已删除');
            return;
        }
        if (!res.data.capabilities || !res.data.capabilities.can_edit) {
            // 草稿不能编辑（应走向导继续配置）。
            showError('该应用不可编辑（草稿请在新建向导中继续配置）');
            return;
        }
        original = res.data;
        version = res.data.version;
        document.getElementById('app-code').value = appCode;
        document.getElementById('app-version').value = version;
        renderApp(res.data);
        showState('form');
        if (window.lucide) lucide.createIcons();
        // 多应用（二次复验 P0-02）：await loadMembers，保证 picker 基于最新服务端成员建立，
        // 避免成员请求晚返回覆盖冲突恢复时已 setValue 的接收人。
        await loadMembers(false);
    }

    function renderApp(d) {
        // 暂停横幅。
        els.pausedBanner.classList.toggle('hidden', d.lifecycle_status !== 'paused');
        // 重复身份告警。
        const isDup = Array.isArray(d.warnings) && d.warnings.includes('duplicate_identity');
        els.duplicateBanner.classList.toggle('hidden', !isDup);

        els.description.value = d.description || '';
        els.agentid.value = d.agentid || '';
        els.corpid.value = d.corpid || '';
        // 敏感项不回填。
        els.corpsecret.value = '';
        els.callbackToken.value = '';
        els.aeskey.value = '';
        els.callbackEnabled.checked = !!d.callback_enabled;
        // 关闭回调后必须清空展示，否则会残留上一次的 URL 造成“仍开启”的错觉。
        if (d.callbackUrl) {
            els.callbackUrlDisplay.textContent = '回调 URL：' + window.location.origin + d.callbackUrl;
        } else if (els.callbackUrlDisplay) {
            els.callbackUrlDisplay.textContent = '';
        }
        // 安全设置初始显示（实际开关切换走独立接口 + 版本锁）。
        renderCodeSendPanel(d.code_send_enabled);
        renderNotifyKeyPanel(d.notify_key_enabled);
    }

    async function loadMembers(refresh) {
        const generation = membersGuard.next();
        const url = '/api/configuration/' + encodeURIComponent(appCode) + '/users' + (refresh ? '?refresh=1' : '');
        const res = await http.get(url);
        // 过期响应一律丢弃，避免慢速 refresh 覆盖保存/409 后已 setValue 的 picker。
        if (!membersGuard.isCurrent(generation)) return;
        if (!res.ok) {
            toast.show(res.error || '获取成员列表失败', { type: 'warn' });
            return;
        }
        currentMembers = res.data;
        renderPicker();
    }

    function renderPicker() {
        els.recipientMount.innerHTML = '';
        picker = window.AppRecipientPicker.create(els.recipientMount, {
            mode: 'member',
            users: currentMembers.users || [],
            current: currentMembers.current || [],
            orphan: currentMembers.orphan || []
        });
    }

    // ─── 保存：touched-field payload + If-Match ─────────────────────

    function buildPayload() {
        const payload = {};
        // 描述：与原值不同才发送。
        if (els.description.value.trim() !== (original.description || '')) {
            payload.description = els.description.value.trim();
        }
        // AgentID：变化才发送（且需正整数）。
        const agentidNum = Number(els.agentid.value);
        if (Number.isInteger(agentidNum) && agentidNum > 0 && agentidNum !== original.agentid) {
            payload.agentid = agentidNum;
        } else if (els.agentid.value !== '' && !(Number.isInteger(agentidNum) && agentidNum > 0)) {
            return { error: 'AgentID 必须为正整数' };
        }
        // CorpSecret：非空才发送（空表示不变）。
        if (els.corpsecret.value) {
            payload.corpsecret = els.corpsecret.value;
        }
        // 回调开关：变化才发送。
        const cbEnabledNew = els.callbackEnabled.checked ? 1 : 0;
        const cbEnabledOrig = original.callback_enabled ? 1 : 0;
        if (cbEnabledNew !== cbEnabledOrig) {
            payload.callback_enabled = els.callbackEnabled.checked;
        }
        // 回调 Token：非空才发送。
        if (els.callbackToken.value) {
            payload.callback_token = els.callbackToken.value;
        }
        // AESKey：非空才发送。
        if (els.aeskey.value) {
            payload.encoding_aes_key = els.aeskey.value;
        }
        // 默认接收人：与原值不同才发送。
        if (picker) {
            const newTouser = picker.getValue().touser;
            const origSorted = [...(original.touser || [])].sort().join('|');
            const newSorted = [...newTouser].sort().join('|');
            if (newSorted !== origSorted) {
                if (newTouser.length === 0) return { error: '请至少选择一个接收成员' };
                payload.touser = newTouser;
            }
        }
        return { payload };
    }

    async function onSave() {
        const built = buildPayload();
        if (built.error) { toast.show(built.error, { type: 'error' }); return; }
        const payload = built.payload;
        if (Object.keys(payload).length === 0) {
            toast.show('没有需要保存的修改', { type: 'info' });
            return;
        }
        const hasCredentialChange = payload.corpsecret || payload.agentid;
        const res = await http.put(
            '/api/configuration/' + encodeURIComponent(appCode),
            payload,
            { version, button: els.saveBtn }
        );
        if (res.ok) {
            if (res.version) version = res.version;
            document.getElementById('app-version').value = version;
            // 用服务端响应整体刷新摘要（不能只改本地表单值）。
            toast.show('保存成功' + (hasCredentialChange ? '（已重新验证凭证）' : ''), { type: 'success' });
            // 清空敏感输入。
            els.corpsecret.value = '';
            els.callbackToken.value = '';
            els.aeskey.value = '';
            await refreshSummary();
            return;
        }
        if (res.code === 'APP_VERSION_CONFLICT') {
            // 多应用（R-P1-06）：版本冲突——保留用户输入。
            // 快照非敏感输入（描述/AgentID/回调开关/默认接收成员），加载最新摘要后重新应用。
            // 敏感输入（CorpSecret/Token/AESKey）不复制、不持久化，需重新输入。
            // 用 FrontendHelpers.snapshotEditForm 统一快照逻辑（含空描述按属性存在恢复）。
            // 多应用（第三轮复验 P1-01）：H 已在 DOMContentLoaded 顶层声明，此处不再重复。
            const snapshot = H.snapshotEditForm({
                description: els.description.value,
                agentid: els.agentid.value,
                callbackEnabled: els.callbackEnabled.checked,
                touser: picker ? picker.getValue().touser : []
            });
            modal.confirm({
                title: '应用已在其他页面更新',
                body: '已加载最新版本并保留你的非敏感输入（CorpSecret/Token/AESKey 因安全原因需重新输入）。请核对差异后再次保存。',
                confirmText: '加载最新值',
                onConfirm: async () => {
                    await loadApp();
                    // 重新应用用户在冲突前的非敏感改动（按属性存在恢复，允许空描述）。
                    if (Object.prototype.hasOwnProperty.call(snapshot, 'description')) {
                        els.description.value = snapshot.description;
                    }
                    if (Object.prototype.hasOwnProperty.call(snapshot, 'agentid')) {
                        els.agentid.value = snapshot.agentid;
                    }
                    if (Object.prototype.hasOwnProperty.call(snapshot, 'callbackEnabled')) {
                        els.callbackEnabled.checked = !!snapshot.callbackEnabled;
                    }
                    // 多应用（二次复验 P0-02）：默认接收成员必须实际写回 picker（setValue），
                    // 而非丢弃。loadApp 已 await loadMembers 完成，picker 基线为服务端最新值；
                    // 这里用 computeEditRefreshPlan 计算冲突恢复态，并 setValue 写回用户快照。
                    // 不可见成员作为 orphan 显示，不丢弃。敏感字段已由 loadApp 清空。
                    if (picker && Object.prototype.hasOwnProperty.call(snapshot, 'touser')) {
                        const plan = H.computeEditRefreshPlan({
                            serverTouser: original.touser,
                            snapshotTouser: snapshot.touser,
                            conflict: true,
                            visibleUserids: (currentMembers.users || []).map(u => u.userid)
                        });
                        picker.setValue(plan.pickerCurrent, { orphan: plan.pickerOrphan });
                    }
                    return true;
                }
            });
            return;
        }
        if (res.code === 'CORPID_IMMUTABLE') {
            toast.show('企业 CorpID 不可修改，请新建应用', { type: 'error' });
            return;
        }
        if (res.code === 'APP_IDENTITY_CONFLICT') {
            toast.show('该 AgentID 已绑定到其他应用', { type: 'error' });
            return;
        }
        if (res.code === 'WECHAT_CREDENTIAL_INVALID') {
            toast.show('企业微信凭证无效，请检查 CorpSecret 与 AgentID', { type: 'error' });
            return;
        }
        if (res.code === 'APP_VERSION_REQUIRED') {
            toast.show('缺少版本，正在刷新', { type: 'warn' });
            await refreshSummary();
            return;
        }
        toast.show(res.error || '保存失败', { type: 'error' });
    }

    // 多应用（二次复验 P0-02）：refreshSummary 不再用陈旧 currentMembers.current 重建 picker。
    // 成功保存后 picker 必须以服务端最新 touser 为基线，否则下一次保存其他字段会
    // 把旧接收人静默回退（P0-02 核心 bug）。await loadMembers 保证 picker 基线正确。
    //
    // 多应用（第三轮复验 P2-4）：安全分区（Code 开关/通知密钥）冲突刷新时，
    // 通过 securityOnly=true 只刷新版本与安全分区，不清空主编辑表单（描述/AgentID/接收人）。
    async function refreshSummary(securityOnly) {
        const res = await http.get('/api/configuration/' + encodeURIComponent(appCode));
        if (res.ok && res.data) {
            original = res.data;
            version = res.data.version;
            document.getElementById('app-version').value = version;
            if (securityOnly) {
                // 仅刷新安全分区状态与暂停/重复横幅，不动主表单输入。
                els.pausedBanner.classList.toggle('hidden', res.data.lifecycle_status !== 'paused');
                const isDup = Array.isArray(res.data.warnings) && res.data.warnings.includes('duplicate_identity');
                els.duplicateBanner.classList.toggle('hidden', !isDup);
                renderCodeSendPanel(res.data.code_send_enabled);
                renderNotifyKeyPanel(res.data.notify_key_enabled);
                return;
            }
            renderApp(res.data);
            // 重新拉取成员，让 picker 的 current 由最新配置计算（而非陈旧缓存）。
            await loadMembers(false);
            // picker 已在 loadMembers → renderPicker 中以最新服务端 touser 重建。
            if (picker) {
                const plan = H.computeEditRefreshPlan({
                    serverTouser: original.touser,
                    conflict: false,
                    visibleUserids: (currentMembers.users || []).map(u => u.userid)
                });
                picker.setValue(plan.pickerCurrent, { orphan: plan.pickerOrphan });
            }
        }
    }

    // ─── 安全设置：Code 发送开关（独立接口 + 版本锁） ────────────────

    function renderCodeSendPanel(enabled) {
        els.codeSendToggle.checked = enabled !== false;
        els.codeSendStatus.textContent = enabled !== false ? '已开启' : '已关闭';
    }

    async function onCodeSendToggle() {
        const next = els.codeSendToggle.checked;
        const res = await http.put(
            '/api/configuration/' + encodeURIComponent(appCode) + '/code-send',
            { enabled: next },
            { version }
        );
        if (res.ok) {
            if (res.version) version = res.version;
            // 多应用（P1-06）：成功后同步 original 中的对应状态，避免后续失败回滚显示错误状态。
            document.getElementById('app-version').value = version;
            if (original) original.code_send_enabled = next;
            renderCodeSendPanel(next);
            toast.show(next ? '已开启 Code 发送' : '已关闭 Code 发送', { type: next ? 'success' : 'warn' });
        } else {
            // 恢复原状态（用同步后的 original，反映最新已知状态）。
            renderCodeSendPanel(original && original.code_send_enabled);
            // 多应用（第三轮 P2-4）：安全分区冲突只刷新安全分区，不清空主表单草稿。
            if (res.code === 'APP_VERSION_CONFLICT') { toast.show('版本过期，正在刷新', { type: 'warn' }); await refreshSummary(true); }
            else { toast.show(res.error || '切换失败', { type: 'error' }); }
        }
    }

    // ─── 安全设置：通知密钥（启用/轮换/撤销，独立接口 + 版本锁） ────

    function renderNotifyKeyPanel(enabled) {
        const enabledBool = !!enabled;
        els.notifyKeyStatus.textContent = enabledBool ? '已启用' : '未启用';
        els.enableNotifyKeyBtn.classList.toggle('hidden', enabledBool);
        els.rotateNotifyKeyBtn.classList.toggle('hidden', !enabledBool);
        els.revokeNotifyKeyBtn.classList.toggle('hidden', !enabledBool);
        els.notifyKeyOnetime.classList.add('hidden');
        els.notifyKeyOnetime.innerHTML = '';
    }

    async function onNotifyKey(action) {
        // 启用与轮换都生成新 key，仅语义不同；撤销清空。
        const confirmMap = {
            enable: { title: '启用通知密钥', body: '将生成新的 X-Notify-Key，仅显示一次。', confirmText: '启用' },
            rotate: { title: '轮换通知密钥', body: '旧密钥立即失效，新密钥仅显示一次。', confirmText: '轮换', danger: true },
            revoke: { title: '撤销通知密钥', body: '撤销后该应用不再要求 X-Notify-Key。确定继续？', confirmText: '撤销', danger: true }
        };
        const cfg = confirmMap[action];
        modal.confirm({
            title: cfg.title,
            body: cfg.body,
            confirmText: cfg.confirmText,
            confirmType: cfg.danger ? 'danger' : 'primary',
            onConfirm: async () => {
                let res;
                if (action === 'revoke') {
                    res = await http.del('/api/configuration/' + encodeURIComponent(appCode) + '/notify-key', { version });
                } else {
                    res = await http.post('/api/configuration/' + encodeURIComponent(appCode) + '/notify-key', {}, { version });
                }
                if (res.ok) {
                    if (res.version) version = res.version;
                    document.getElementById('app-version').value = version;
                    if (original) original.notify_key_enabled = (action !== 'revoke');
                    if (action === 'revoke') {
                        renderNotifyKeyPanel(false);
                        toast.show('已撤销通知密钥', { type: 'warn' });
                    } else {
                        renderNotifyKeyPanel(true);
                        showNotifyKeyOnetime(res.data.notify_key);
                        toast.show('已生成新通知密钥，请妥善保存', { type: 'success' });
                    }
                    return true;
                }
                // 多应用（第三轮 P2-4）：安全分区冲突只刷新安全分区，不清空主表单草稿。
                if (res.code === 'APP_VERSION_CONFLICT') { toast.show('版本过期，正在刷新', { type: 'warn' }); await refreshSummary(true); }
                else { toast.show(res.error || '操作失败', { type: 'error' }); }
                return false;
            }
        });
    }

    function showNotifyKeyOnetime(plainKey) {
        els.notifyKeyOnetime.classList.remove('hidden');
        els.notifyKeyOnetime.innerHTML = '';
        const box = document.createElement('div');
        box.className = 'alert alert-warning flex flex-col items-start gap-1';
        const lab = document.createElement('div');
        lab.className = 'font-medium text-sm';
        lab.textContent = '通知密钥（仅显示一次，请立即复制保存）';
        const val = document.createElement('div');
        val.className = 'font-mono text-xs break-all';
        val.textContent = plainKey;
        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'btn btn-xs btn-ghost gap-1';
        const cIcon = document.createElement('i');
        cIcon.setAttribute('data-lucide', 'copy');
        cIcon.className = 'h-3 w-3';
        copyBtn.appendChild(cIcon);
        copyBtn.appendChild(document.createTextNode(' 复制'));
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(plainKey).then(() => toast.show('已复制', { type: 'success' }));
        });
        box.appendChild(lab);
        box.appendChild(val);
        box.appendChild(copyBtn);
        els.notifyKeyOnetime.appendChild(box);
        if (window.lucide) lucide.createIcons();
    }
});
