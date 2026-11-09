/*
 * 多应用管理（2026-07-04 §5.4）：新建应用四步向导。
 *
 * 四步：
 *   1. 企业与回调 → POST /api/generate-callback（生成草稿 + 回调 URL）
 *   2. 应用信息与凭证 → POST /api/validate（验证凭证，不写库）
 *   3. 默认接收成员 → AppRecipientPicker（member 模式，仅成员）
 *   4. 确认与完成 → POST /api/complete-config（身份判重 + 写库）
 *
 * sessionStorage 白名单（§5.4，敏感项不落存储）：
 *   draft_code, version, step, corpid, agentid, description, selectedUserIDs
 *   CorpSecret / 回调 Token / EncodingAESKey 刷新后需重新输入。
 *
 * 稳定错误码：
 *   APP_DRAFT_EXISTS / APP_ALREADY_COMPLETED / APP_IDENTITY_CONFLICT /
 *   WECHAT_CREDENTIAL_INVALID / WECHAT_UNAVAILABLE。
 */
document.addEventListener('DOMContentLoaded', function () {
    const http = window.AppHttp;
    const toast = window.AppToast;
    const modal = window.AppModal;

    // 内存草稿状态（敏感项不持久化）。
    const draft = { code: null, version: null, corpid: null };
    // 凭证（仅在内存，不落 sessionStorage）。
    const cred = { corpsecret: '', agentid: null, validated: false };
    // 验证返回的成员列表（供 picker 使用）。
    let availableUsers = [];
    let selectedUsers = [];
    let picker = null;

    const STORE_KEY = 'wizard_state_v1';
    const ALLOWED_STORE_KEYS = new Set(['draft_code', 'version', 'step', 'corpid', 'agentid', 'description', 'selectedUserIDs']);

    const els = {
        steps: [1, 2, 3, 4].reduce((acc, n) => { acc[n] = document.getElementById('step' + n); return acc; }, {}),
        indicators: [1, 2, 3, 4].reduce((acc, n) => { acc[n] = document.getElementById('step-indicator-' + n); return acc; }, {}),
        callbackForm: document.getElementById('callbackForm'),
        callbackResult: document.getElementById('callbackResult'),
        configForm: document.getElementById('configForm'),
        validateBtn: document.getElementById('validateBtn'),
        recipientMount: document.getElementById('recipient-picker-mount'),
        summary: document.getElementById('summary'),
        result: document.getElementById('result'),
        completeBtn: document.getElementById('complete-btn')
    };

    checkAuth().then(isAuth => { if (isAuth) init(); });

    async function checkAuth() {
        try {
            const res = await fetch('/api/auth-status', { credentials: 'same-origin' });
            const data = await res.json();
            if (!data.loggedIn) {
                const here = window.location.pathname + window.location.search + window.location.hash;
                window.location.href = '/login?next=' + encodeURIComponent(here);
                return false;
            }
            return true;
        } catch (_e) {
            const here = window.location.pathname + window.location.search + window.location.hash;
            window.location.href = '/login?next=' + encodeURIComponent(here);
            return false;
        }
    }

    // ─── sessionStorage 白名单持久化 ──────────────────────────────────

    function saveState() {
        const safe = {
            draft_code: draft.code,
            version: draft.version,
            corpid: draft.corpid,
            agentid: cred.agentid,
            description: els.configForm ? els.configForm['description'].value.trim() : '',
            selectedUserIDs: selectedUsers
        };
        // 只写入白名单字段（敏感项一律不存）。
        const filtered = {};
        for (const k of ALLOWED_STORE_KEYS) filtered[k] = safe[k];
        try { sessionStorage.setItem(STORE_KEY, JSON.stringify(filtered)); } catch (_e) {}
    }

    function loadState() {
        try {
            const raw = sessionStorage.getItem(STORE_KEY);
            if (!raw) return null;
            const obj = JSON.parse(raw);
            const filtered = {};
            for (const k of ALLOWED_STORE_KEYS) if (k in obj) filtered[k] = obj[k];
            return filtered;
        } catch (_e) { return null; }
    }

    function clearState() { try { sessionStorage.removeItem(STORE_KEY); } catch (_e) {} }

    function init() {
        if (window.lucide) lucide.createIcons();

        bindNavigation();
        els.callbackForm.addEventListener('submit', onGenerateCallback);
        els.validateBtn.addEventListener('click', onValidate);
        els.completeBtn.addEventListener('click', onComplete);

        // 恢复入口：/new?code=<draft-code>（只恢复非敏感状态）。
        const restoreCode = new URLSearchParams(window.location.search).get('code');
        if (restoreCode) {
            tryRestoreDraft(restoreCode);
            return;
        }
        // 无 ?code 但 sessionStorage 有草稿 → 询问是否继续。
        const saved = loadState();
        if (saved && saved.draft_code) {
            offerResumeSaved(saved);
        }
    }

    function offerResumeSaved(saved) {
        modal.confirm({
            title: '发现未完成的草稿',
            body: '是否继续配置草稿「' + String(saved.draft_code).slice(0, 8) + '…」？继续后需重新输入回调 Token、AESKey 与 CorpSecret。',
            confirmText: '继续配置',
            onConfirm: () => {
                window.location.href = '/new?code=' + encodeURIComponent(saved.draft_code);
                return true;
            }
        });
    }

    async function tryRestoreDraft(code) {
        const res = await http.get('/api/configuration/' + encodeURIComponent(code));
        if (!res.ok || !res.data) {
            toast.show('草稿不存在，请新建', { type: 'warn' });
            clearState();
            return;
        }
        const cfg = res.data;
        if (cfg.lifecycle_status !== 'draft') {
            toast.show('该应用已完成配置，跳转编辑', { type: 'info' });
            window.location.href = '/edit?code=' + encodeURIComponent(code);
            return;
        }
        draft.code = code;
        draft.version = cfg.version;
        draft.corpid = cfg.corpid;
        els.callbackForm['corpid'].value = cfg.corpid;
        els.callbackForm['corpid'].readOnly = true;
        // 恢复 sessionStorage 白名单非敏感字段（agentid/description/selectedUserIDs）。
        // 密钥永不落存储；Token/AESKey/CorpSecret 需用户重新输入。
        const saved = loadState();
        if (saved && String(saved.draft_code || '') === String(code)) {
            if (saved.agentid !== undefined && saved.agentid !== null && els.configForm) {
                els.configForm['agentid'].value = saved.agentid;
                cred.agentid = Number(saved.agentid) || null;
            }
            if (saved.description !== undefined && saved.description !== null && els.configForm) {
                els.configForm['description'].value = saved.description;
            }
            if (Array.isArray(saved.selectedUserIDs)) {
                selectedUsers = saved.selectedUserIDs.map(String);
            }
        }
        // 直接进入第 2 步（回调 Token/AESKey 需重新输入，但 CorpID 锁定）。
        goToStep(2);
        toast.show('已恢复草稿，请填写凭证', { type: 'info' });
    }

    // ─── 步骤导航 ────────────────────────────────────────────────────

    function bindNavigation() {
        document.getElementById('back-to-1').addEventListener('click', () => goToStep(1));
        document.getElementById('back-to-2').addEventListener('click', () => goToStep(2));
        document.getElementById('to-step-4').addEventListener('click', goToConfirm);
        document.getElementById('back-to-3').addEventListener('click', () => goToStep(3));
    }

    function goToStep(n) {
        // 离开成员步前同步 picker，防止 step3→2→再验证时 selectedUsers 仍是空数组。
        if (picker && typeof picker.getValue === 'function') {
            const latest = picker.getValue().touser;
            if (Array.isArray(latest)) selectedUsers = latest;
        }
        for (let i = 1; i <= 4; i++) {
            els.steps[i].classList.toggle('hidden', i !== n);
            els.indicators[i].classList.toggle('step-primary', i <= n);
        }
        if (window.lucide) lucide.createIcons();
        const state = { step: n };
        try { sessionStorage.setItem(STORE_KEY, JSON.stringify({ ...loadState(), ...state })); } catch (_e) {}
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    // ─── 第一步：生成回调 URL ────────────────────────────────────────

    async function onGenerateCallback(e) {
        e.preventDefault();
        const form = e.currentTarget;
        const corpid = form['corpid'].value.trim();
        const callback_token = form['callback_token'].value.trim();
        const encoding_aes_key = form['encoding_aes_key'].value.trim();

        const body = { corpid, callback_token, encoding_aes_key };
        if (draft.code) { body.draft_code = draft.code; body.version = draft.version; }

        const res = await http.post('/api/generate-callback', body, { button: form.querySelector('button[type=submit]') });

        if (res.ok) {
            draft.code = res.data.code;
            draft.version = res.data.version;
            draft.corpid = corpid;
            form['corpid'].readOnly = true;
            showCallbackResult(res.data);
            saveState();
            toast.show('回调 URL 已生成', { type: 'success' });
            return;
        }
        if (res.code === 'APP_DRAFT_EXISTS' && res.details && res.details.existing_code) {
            const existing = res.details.existing_code;
            modal.confirm({
                title: '该企业已有待完善应用',
                body: '是否继续配置现有草稿？继续后需重新输入回调 Token 与 AESkey。',
                confirmText: '继续配置',
                onConfirm: () => { window.location.href = '/new?code=' + encodeURIComponent(existing); return true; }
            });
            return;
        }
        // 多应用（R-P1-03 / 二次复验 P1-02）：草稿更新版本冲突——同步最新版本，保留输入，要求重新确认。
        // 只在 APP_VERSION_CONFLICT / APP_VERSION_REQUIRED / INVALID_INPUT+details.field==='version' 时同步版本。
        // 普通 INVALID_INPUT（字段错误）直接显示服务端错误，不读取详情、不误判为版本异常。
        const isVersionIssue = res.code === 'APP_VERSION_CONFLICT'
            || res.code === 'APP_VERSION_REQUIRED'
            || (res.code === 'INVALID_INPUT' && res.details && res.details.field === 'version');
        if (isVersionIssue) {
            // 多应用（二次复验 P1-02）：APP_VERSION_REQUIRED 且尚无 draft.code 时不得请求 /configuration/null。
            if (!draft.code) {
                toast.show(res.error || '草稿状态异常，请返回总览', { type: 'warn' });
                clearState();
                return;
            }
            toast.show('草稿状态已变化，正在同步版本', { type: 'warn' });
            const detailRes = await http.get('/api/configuration/' + encodeURIComponent(draft.code));
            if (detailRes.ok && detailRes.data) {
                draft.version = detailRes.data.version;
                toast.show('已同步最新版本，请重新提交', { type: 'info' });
            } else {
                toast.show('草稿已不存在，请返回总览', { type: 'warn' });
                clearState();
            }
            return;
        }
        toast.show(res.error || '生成回调失败', { type: 'error' });
    }

    function showCallbackResult(data) {
        els.callbackResult.classList.remove('hidden');
        els.callbackResult.innerHTML = '';
        const url = window.location.origin + data.callbackUrl;
        const box = document.createElement('div');
        box.className = 'alert alert-success flex flex-col items-start gap-2';
        const title = document.createElement('div');
        title.className = 'font-medium';
        title.textContent = '回调 URL（请填入企业微信后台）';
        const codeRow = document.createElement('div');
        codeRow.className = 'text-xs break-all';
        codeRow.textContent = url;
        box.appendChild(title);
        box.appendChild(codeRow);
        appendCopyButton(box, url);
        els.callbackResult.appendChild(box);

        const nextBtn = document.createElement('button');
        nextBtn.type = 'button';
        nextBtn.className = 'btn btn-primary mt-3 gap-1';
        const nextIcon = document.createElement('i');
        nextIcon.setAttribute('data-lucide', 'arrow-right');
        nextIcon.className = 'h-4 w-4';
        nextBtn.appendChild(nextIcon);
        nextBtn.appendChild(document.createTextNode(' 下一步：填写凭证'));
        nextBtn.addEventListener('click', () => goToStep(2));
        els.callbackResult.appendChild(nextBtn);
        if (window.lucide) lucide.createIcons();
    }

    // ─── 第二步：验证凭证 ────────────────────────────────────────────

    async function onValidate() {
        const corpsecret = els.configForm['corpsecret'].value;
        const agentid = Number(els.configForm['agentid'].value);
        const description = els.configForm['description'].value.trim();
        if (!corpsecret || !Number.isInteger(agentid) || agentid <= 0) {
            toast.show('请填写 CorpSecret 和正整数 AgentID', { type: 'error' });
            return;
        }
        const res = await http.post('/api/validate',
            { corpid: draft.corpid, corpsecret, agentid },
            { button: els.validateBtn });
        if (!res.ok) {
            if (res.code === 'WECHAT_CREDENTIAL_INVALID') {
                toast.show('企业微信凭证无效或 AgentID 不匹配', { type: 'error' });
            } else if (res.code === 'WECHAT_UNAVAILABLE') {
                toast.show('企业微信暂时不可用，请稍后重试', { type: 'warn' });
            } else {
                toast.show(res.error || '验证失败', { type: 'error' });
            }
            return;
        }
        cred.corpsecret = corpsecret;
        cred.agentid = agentid;
        cred.validated = true;
        availableUsers = res.data.users || [];
        // 重新验证前若已有 picker，先同步选中，避免 step3→2→再验证时清空接收人。
        if (picker && typeof picker.getValue === 'function') {
            const latest = picker.getValue().touser;
            if (Array.isArray(latest) && latest.length > 0) selectedUsers = latest;
        }
        renderRecipientPicker();
        saveState();
        toast.show('凭证验证成功，请选择接收成员', { type: 'success' });
        goToStep(3);
    }

    function renderRecipientPicker() {
        els.recipientMount.innerHTML = '';
        picker = window.AppRecipientPicker.create(els.recipientMount, {
            mode: 'member',
            users: availableUsers,
            current: Array.isArray(selectedUsers) ? selectedUsers : []
        });
    }

    // ─── 第三步 → 第四步：确认摘要 ───────────────────────────────────

    function goToConfirm() {
        // 拉取 picker 最新选中值。
        if (picker) selectedUsers = picker.getValue().touser;
        if (selectedUsers.length === 0) {
            toast.show('请至少选择一个接收成员', { type: 'error' });
            return;
        }
        saveState();
        renderSummary();
        goToStep(4);
    }

    function renderSummary() {
        const description = els.configForm['description'].value.trim() || '未命名应用';
        const rows = [
            ['企业 CorpID', maskCorpid(draft.corpid)],
            ['应用名称/备注', description],
            ['AgentID', cred.agentid],
            ['默认接收成员', selectedUsers.length + ' 人：' + selectedUsers.join('、')]
        ];
        els.summary.innerHTML = '';
        const list = document.createElement('dl');
        list.className = 'grid grid-cols-3 gap-2';
        rows.forEach(([k, v]) => {
            const dt = document.createElement('dt');
            dt.className = 'text-base-content/60 col-span-1';
            dt.textContent = k;
            const dd = document.createElement('dd');
            dd.className = 'col-span-2 font-medium break-all';
            dd.textContent = v;
            list.appendChild(dt);
            list.appendChild(dd);
        });
        els.summary.appendChild(list);
    }

    // ─── 第四步：完成配置 ────────────────────────────────────────────

    async function onComplete() {
        const description = els.configForm['description'].value.trim();
        const res = await http.post('/api/complete-config',
            { code: draft.code, corpsecret: cred.corpsecret, agentid: cred.agentid, touser: selectedUsers, description, version: draft.version },
            { button: els.completeBtn });

        if (res.ok) {
            clearState();
            showSuccess(res.data);
            return;
        }
        // 多应用（R-P1-03 / 二次复验 P1-02）：版本冲突——读取草稿最新版本并保留输入，要求重新确认。
        if (res.code === 'APP_VERSION_CONFLICT') {
            toast.show('草稿已被其他操作更新，正在同步版本', { type: 'warn' });
            await refreshDraftVersion();
            return;
        }
        // 多应用（二次复验 P1-02）：只在版本相关错误时重新加载详情。
        // APP_VERSION_REQUIRED 或 INVALID_INPUT+details.field==='version' 视为客户端状态异常。
        // 普通 INVALID_INPUT（如 AgentID/接收人字段错误）直接显示错误，不重新加载。
        const isVersionInputError = res.code === 'APP_VERSION_REQUIRED'
            || (res.code === 'INVALID_INPUT' && res.details && res.details.field === 'version');
        if (isVersionInputError) {
            toast.show('草稿状态异常，正在重新加载', { type: 'warn' });
            await refreshDraftVersion();
            return;
        }
        if (res.code === 'APP_IDENTITY_CONFLICT' && res.details && res.details.existing_code) {
            const existing = res.details.existing_code;
            modal.confirm({
                title: 'AgentID 已被占用',
                body: '该企业下此 AgentID 已绑定到其他应用。是否打开现有应用？',
                confirmText: '打开现有应用',
                onConfirm: () => { window.location.href = '/edit?code=' + encodeURIComponent(existing); return true; }
            });
            return;
        }
        // 多应用（R-P1-03）：APP_ALREADY_COMPLETED 不能直接展示成功——
        // 需读取 details.existing_code || draft.code 的详情，仅当服务端 AgentID 与 cred.agentid 一致才进入成功页。
        if (res.code === 'APP_ALREADY_COMPLETED') {
            const existingCode = (res.details && res.details.existing_code) || draft.code;
            await handleAlreadyCompleted(existingCode);
            return;
        }
        if (res.code === 'APP_DRAFT_MISMATCH') {
            toast.show('草稿状态已变化，请刷新总览', { type: 'warn' });
            clearState();
            return;
        }
        if (res.code === 'WECHAT_CREDENTIAL_INVALID') {
            toast.show('凭证无效，请返回第二步检查', { type: 'error' });
            goToStep(2);
            return;
        }
        toast.show(res.error || '完成配置失败', { type: 'error' });
    }

    // 多应用（R-P1-03）：读取草稿最新摘要，更新 draft.version，保留当前输入。
    async function refreshDraftVersion() {
        const detailRes = await http.get('/api/configuration/' + encodeURIComponent(draft.code));
        if (detailRes.ok && detailRes.data) {
            draft.version = detailRes.data.version;
            toast.show('已同步最新版本，请重新点击完成', { type: 'info' });
        } else {
            // 草稿不存在：回到总览，不伪造成功。
            toast.show('草稿已不存在，请返回总览', { type: 'warn' });
            clearState();
        }
    }

    // 多应用（R-P1-03）：APP_ALREADY_COMPLETED 后核对实际 AgentID。
    // 仅当服务端 AgentID 与本次输入一致才进入成功页，否则停止并提示。
    async function handleAlreadyCompleted(existingCode) {
        const targetCode = existingCode || draft.code;
        const detailRes = await http.get('/api/configuration/' + encodeURIComponent(targetCode));
        if (detailRes.ok && detailRes.data) {
            const serverAgentid = Number(detailRes.data.agentid);
            if (serverAgentid === Number(cred.agentid)) {
                // 同一 AgentID：可安全展示成功。
                toast.show('应用已完成配置', { type: 'info' });
                showSuccess({ code: targetCode, apiUrl: '/api/notify/' + encodeURIComponent(targetCode) });
                return;
            }
        }
        // AgentID 不匹配或读取失败：不伪造成功，提示用户。
        toast.show('该草稿已被其他操作以不同 AgentID 完成，请返回总览核对', { type: 'warn' });
        clearState();
    }

    function showSuccess(data) {
        [1, 2, 3, 4].forEach(n => els.steps[n].classList.add('hidden'));
        els.result.innerHTML = '';
        const box = document.createElement('div');
        box.className = 'alert alert-success flex flex-col items-start gap-2';
        const title = document.createElement('div');
        title.className = 'font-medium';
        title.textContent = '应用创建成功';
        const apiUrl = window.location.origin + (data.apiUrl || ('/api/notify/' + data.code));
        box.appendChild(title);
        box.appendChild(makeCopyRow('API 地址（发送通知）', apiUrl));
        box.appendChild(makeCopyRow('应用 Code', data.code));
        els.result.appendChild(box);

        const backBtn = document.createElement('a');
        backBtn.href = '/?highlight=' + encodeURIComponent(data.code);
        backBtn.className = 'btn btn-primary mt-3 gap-1';
        const backIcon = document.createElement('i');
        backIcon.setAttribute('data-lucide', 'check');
        backIcon.className = 'h-4 w-4';
        backBtn.appendChild(backIcon);
        backBtn.appendChild(document.createTextNode(' 返回总览'));
        els.result.appendChild(backBtn);
        if (window.lucide) lucide.createIcons();
    }

    // ─── 工具 ────────────────────────────────────────────────────────

    function maskCorpid(corpid) {
        if (!corpid) return '—';
        const s = String(corpid);
        if (s.length <= 8) return s[0] + '…' + s[s.length - 1];
        return s.slice(0, 4) + '…' + s.slice(-4);
    }

    function makeCopyRow(label, value) {
        const row = document.createElement('div');
        row.className = 'text-xs w-full';
        const lab = document.createElement('div');
        lab.className = 'text-base-content/70';
        lab.textContent = label;
        const val = document.createElement('div');
        val.className = 'break-all font-mono';
        val.textContent = value;
        row.appendChild(lab);
        row.appendChild(val);
        appendCopyButton(row, value);
        return row;
    }

    function appendCopyButton(container, value) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-xs btn-ghost gap-1 mt-1';
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'copy');
        icon.className = 'h-3 w-3';
        btn.appendChild(icon);
        btn.appendChild(document.createTextNode(' 复制'));
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(value).then(
                () => toast.show('已复制', { type: 'success' }),
                () => toast.show('复制失败', { type: 'error' })
            );
        });
        container.appendChild(btn);
    }
});
