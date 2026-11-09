/*
 * 多应用管理（2026-07-04 §7.5）：可访问的确认对话框。
 *
 * 替代 window.confirm（§7.3 删除确认禁止 window.confirm）。
 * 行为：
 *   - ESC 关闭、点击遮罩关闭。
 *   - 焦点陷阱：Tab 在对话框内循环，不外溢到背景。
 *   - 关闭后焦点归还触发元素。
 *   - 动态内容用 textContent / 安全属性，不用 innerHTML 解析不可信输入。
 *
 * 用法：
 *   AppModal.confirm({
 *     title: '删除应用', body: '将删除 N 条规则...',
 *     confirmText: '删除', confirmType: 'danger',
 *     onConfirm: async () => { ... return true; }
 *   });
 */
(function () {
    'use strict';

    let activeModal = null;
    let lastFocused = null;

    const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

    function open(opts) {
        if (activeModal) close(false);
        lastFocused = document.activeElement;

        const overlay = document.createElement('div');
        overlay.className = 'app-modal-overlay';

        const dialog = document.createElement('div');
        dialog.className = 'app-modal-dialog';
        dialog.setAttribute('role', 'dialog');
        dialog.setAttribute('aria-modal', 'true');
        if (opts.title) dialog.setAttribute('aria-label', opts.title);

        // 标题（textContent）。
        if (opts.title) {
            const h = document.createElement('h3');
            h.className = 'app-modal-title';
            h.textContent = opts.title;
            dialog.appendChild(h);
        }

        // 内容：支持字符串（textContent）或预构建 DOM 节点（用于规则列表）。
        if (opts.body !== undefined && opts.body !== null) {
            const body = document.createElement('div');
            body.className = 'app-modal-body';
            if (typeof opts.body === 'string') {
                body.textContent = opts.body;
            } else {
                body.appendChild(opts.body);
            }
            dialog.appendChild(body);
        }

        const actions = document.createElement('div');
        actions.className = 'app-modal-actions';

        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.textContent = opts.cancelText || '取消';
        cancelBtn.className = 'btn btn-ghost';
        // 多应用（二次复验 P2-05）：busy 期间禁止取消。
        cancelBtn.addEventListener('click', () => {
            if (activeModal && activeModal.busy) return;
            close(false);
        });

        const confirmBtn = document.createElement('button');
        confirmBtn.type = 'button';
        confirmBtn.textContent = opts.confirmText || '确认';
        confirmBtn.className = 'btn ' + (opts.confirmType === 'danger' ? 'btn-error' : 'btn-primary');

        actions.appendChild(cancelBtn);
        actions.appendChild(confirmBtn);
        dialog.appendChild(actions);
        overlay.appendChild(dialog);

        // 遮罩点击关闭（点击对话框本身不关闭）。
        // 多应用（二次复验 P2-05）：异步确认 busy 期间禁止 ESC/遮罩/取消关闭，
        // 避免用户误以为操作已取消（删除/轮换可能仍在后台执行）。
        overlay.addEventListener('mousedown', (e) => {
            if (e.target === overlay && !isBusy()) close(false);
        });

        // 焦点陷阱 + ESC（busy 时禁用 ESC）。
        overlay.addEventListener('keydown', handleKeydown);

        document.body.appendChild(overlay);
        document.body.classList.add('app-modal-open');
        const modalState = { overlay, dialog, confirmBtn, cancelBtn, opts, closed: false, busy: false };
        activeModal = modalState;

        // busy 标志：onConfirm 执行期间为 true，禁止任何关闭路径。
        function isBusy() { return !!(activeModal && activeModal.busy); }

        // 危险操作默认聚焦取消，降低键盘误确认风险；普通确认仍聚焦确认按钮。
        setTimeout(() => (opts.confirmType === 'danger' ? cancelBtn : confirmBtn).focus(), 0);

        confirmBtn.addEventListener('click', async () => {
            if (confirmBtn.disabled) return;
            confirmBtn.disabled = true;
            // 多应用（二次复验 P2-05）：busy 期间禁用取消按钮、ESC 与遮罩关闭。
            modalState.busy = true;
            cancelBtn.disabled = true;
            const original = confirmBtn.textContent;
            confirmBtn.textContent = '处理中…';
            let shouldClose = true;
            try {
                if (typeof opts.onConfirm === 'function') {
                    const ret = await opts.onConfirm();
                    shouldClose = ret !== false;
                }
            } catch (_e) {
                // 调用方自行处理错误（Toast）；保持模态打开供重试。
                shouldClose = false;
            } finally {
                // 必须先解除 busy 再关闭：close() 内部会因 busy 拒绝关闭，
                // 否则会出现“提示成功但模态不消失”的问题。
                modalState.busy = false;
            }
            if (shouldClose) {
                close(true);
            } else {
                // 失败/取消重试：恢复按钮可点击状态。
                confirmBtn.disabled = false;
                cancelBtn.disabled = false;
                confirmBtn.textContent = original;
            }
        });

        return new Promise((resolve) => {
            activeModal.resolve = resolve;
        });
    }

    function handleKeydown(e) {
        if (!activeModal) return;
        if (e.key === 'Escape') {
            // 多应用（二次复验 P2-05）：busy 期间禁止 ESC 关闭。
            if (activeModal.busy) { e.preventDefault(); return; }
            e.preventDefault();
            close(false);
            return;
        }
        if (e.key === 'Tab') {
            const focusable = activeModal.dialog.querySelectorAll(FOCUSABLE);
            if (focusable.length === 0) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    }

    function close(confirmed) {
        if (!activeModal || activeModal.closed) return;
        // 多应用（第三轮 P2-6）：busy 期间禁止任何关闭路径（含公开 close() 与 open() 内的先关闭）。
        if (activeModal.busy) return;
        activeModal.closed = true;
        const { overlay, resolve } = activeModal;
        document.body.classList.remove('app-modal-open');
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        const r = resolve;
        activeModal = null;
        // 焦点归还触发元素。
        if (lastFocused && typeof lastFocused.focus === 'function') {
            setTimeout(() => lastFocused.focus(), 0);
        }
        if (r) r(confirmed);
    }

    window.AppModal = {
        confirm: open,
        close
    };
})();
