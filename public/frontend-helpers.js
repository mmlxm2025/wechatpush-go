/*
 * 前端纯逻辑辅助（多应用 R-P1-02 / R-P1-06）。
 *
 * 这些 helper 从 rules.js / edit.js 的交互流程中抽取出来，便于：
 *   - 单元测试直接验证快照/恢复与请求代次隔离逻辑（无需 DOM）；
 *   - 生产代码与测试共用同一实现，避免“测试专用副本”漂移。
 *
 * 仅包含无副作用纯函数；不访问 DOM、fetch、localStorage。
 * 本文件在浏览器中由 rules.js / edit.js 显式读取 window.FrontendHelpers；
 * 在 Node 测试中直接 require。
 */
(function (root) {
    'use strict';

    // 规则表单快照：捕获完整非敏感字段（名称/接收范围/估算人数/api_code）。
    // 规范 §9.5：api_code 属于非敏感路由标识，应随快照保留，避免版本冲突刷新后丢失用户输入。
    function snapshotRuleForm(form) {
        const snap = {
            name: form.name,
            is_all: !!form.is_all,
            touser: Array.isArray(form.touser) ? form.touser.slice() : [],
            toparty: form.toparty,
            totag: form.totag,
            estimated_count: form.estimated_count
        };
        // api_code 仅在 payload 中存在时保留（创建时空值已被 getPayload 删除）。
        if (Object.prototype.hasOwnProperty.call(form, 'api_code')) {
            snap.api_code = form.api_code;
        }
        return snap;
    }

    // 规则表单恢复：把快照写回表单对象（用于 409 后保留输入）。
    function restoreRuleForm(target, snap) {
        target.name = snap.name;
        target.is_all = !!snap.is_all;
        target.touser = Array.isArray(snap.touser) ? snap.touser.slice() : [];
        target.toparty = snap.toparty;
        target.totag = snap.totag;
        target.estimated_count = snap.estimated_count;
        if (Object.prototype.hasOwnProperty.call(snap, 'api_code')) {
            target.api_code = snap.api_code;
        }
    }

    // 编辑表单快照：捕获非敏感输入（描述/AgentID/接收成员）。
    // 敏感字段（CorpSecret/Token/AESKey）不得进入快照——按属性存在恢复，
    // 允许空描述（“主动清空”的意图需保留）。
    function snapshotEditForm(form) {
        const snap = {};
        if (Object.prototype.hasOwnProperty.call(form, 'description')) {
            snap.description = form.description; // 允许空字符串
        }
        if (Object.prototype.hasOwnProperty.call(form, 'agentid')) {
            snap.agentid = form.agentid;
        }
        if (Object.prototype.hasOwnProperty.call(form, 'callbackEnabled')) {
            snap.callbackEnabled = form.callbackEnabled;
        }
        // 默认接收成员：非敏感，应保留。
        if (Object.prototype.hasOwnProperty.call(form, 'touser')) {
            snap.touser = Array.isArray(form.touser) ? form.touser.slice() : [];
        }
        // 敏感字段故意不快照：CorpSecret / callback_token / encoding_aes_key。
        return snap;
    }

    // 请求代次守卫：用于跨应用快速切换时丢弃过期异步响应。
    // createRequestGuard() 返回 { next(), isCurrent(generation) }。
    // 每次切换应用/重新加载调用 next() 推进代次；响应回来用 isCurrent 判断是否过期。
    function createRequestGuard() {
        let current = 0;
        return {
            next() { current += 1; return current; },
            current() { return current; },
            isCurrent(generation) { return generation === current; }
        };
    }

    // 多应用（二次复验 P0-02）：编辑页 picker 刷新计划。
    //
    // 编辑页在“保存成功”或“409 冲突恢复”后需要重建 picker。设计要求：
    //   - picker 的 current 必须取服务端最新 touser（不能取陈旧 currentMembers.current），
    //     否则下一次保存其他字段会把旧接收人静默回退（P0-02 核心 bug）。
    //   - 409 冲突恢复时，叠加用户在冲突前输入的 snapshot.touser（实际写回 picker）；
    //     不可见的 userid 必须作为 orphan 显示，不丢弃。
    //
    // 入参：
    //   - serverTouser: 服务端最新配置的 touser 数组（loadApp/refreshSummary 拉到的）。
    //   - snapshotTouser: 409 冲突时用户在冲突前的接收人快照；成功保存时传 null/undefined。
    //   - conflict: 是否为冲突恢复路径。
    //   - visibleUserids: 当前可见成员 userid 集合（用于判断 orphan）。
    //
    // 返回 { pickerCurrent, pickerOrphan }：
    //   - pickerCurrent: picker.setValue / 重建时应使用的选中集合。
    //   - pickerOrphan: 其中不可见的 userid（需作为 orphan 行显示，不丢弃）。
    function computeEditRefreshPlan(opts) {
        const options = opts || {};
        const conflict = options.conflict === true;
        const visible = Array.isArray(options.visibleUserids) ? options.visibleUserids : [];
        const visibleSet = new Set(visible.map(String));
        // 冲突恢复：以用户快照为准（保留用户输入）；否则以服务端最新值为基线。
        const hasSnap = Object.prototype.hasOwnProperty.call(options, 'snapshotTouser')
            && Array.isArray(options.snapshotTouser);
        const base = (conflict && hasSnap)
            ? options.snapshotTouser.slice()
            : (Array.isArray(options.serverTouser) ? options.serverTouser.slice() : []);
        const pickerCurrent = base.slice();
        // orphan：选中但不在可见成员中的 userid，需在 picker 中作为不可见行显示。
        const pickerOrphan = pickerCurrent.filter(userid => !visibleSet.has(String(userid)));
        return { pickerCurrent, pickerOrphan };
    }

    const FrontendHelpers = {
        snapshotRuleForm,
        restoreRuleForm,
        snapshotEditForm,
        createRequestGuard,
        computeEditRefreshPlan
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = FrontendHelpers;
    }
    if (typeof root !== 'undefined') {
        root.FrontendHelpers = FrontendHelpers;
    }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
