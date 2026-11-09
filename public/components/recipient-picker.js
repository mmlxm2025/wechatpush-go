/*
 * 多应用管理（2026-07-04 §7.5）：统一接收范围选择器。
 *
 * 两种模式（§5.4 / §7.4）：
 *   - 'member'：仅成员 UserID（应用编辑页默认接收人用，不提供部门/标签）。
 *   - 'rule'  ：成员 + 部门 + 标签 + 全体（规则页保留部门/标签语义，不破坏现有规则）。
 *
 * 安全：
 *   - 动态文本一律 textContent / createElement，不解析不可信 innerHTML。
 *   - orphan 成员（通讯录无权限时）仍可见可编辑，沿用现有 fallback 语义。
 *
 * 用法：
 *   const picker = AppRecipientPicker.create(containerEl, {
 *     mode: 'member',
 *     users: [...], current: ['alice'], orphan: ['missing']
 *   });
 *   picker.onChange(state => { ... });
 *   const value = picker.getValue(); // { touser: [...], toparty?, totag?, is_all? }
 */
(function () {
    'use strict';

    function create(container, opts = {}) {
        const mode = opts.mode === 'rule' ? 'rule' : 'member';
        const users = Array.isArray(opts.users) ? opts.users : [];
        const current = Array.isArray(opts.current) ? opts.current.slice() : [];
        const orphan = Array.isArray(opts.orphan) ? opts.orphan.slice() : [];

        // 选中态：成员用 Set，部门/标签用数组（字符串）。
        const selectedMembers = new Set(current);
        const state = {
            touser: current.slice(),
            toparty: Array.isArray(opts.toparty) ? opts.toparty.slice() : [],
            totag: Array.isArray(opts.totag) ? opts.totag.slice() : [],
            is_all: opts.is_all === true
        };
        const listeners = [];

        container.innerHTML = '';
        container.appendChild(render());

        function notify() {
            state.touser = [...selectedMembers];
            listeners.forEach(fn => { try { fn(getValue()); } catch (_e) {} });
        }

        function getValue() {
            if (mode === 'member') {
                return { touser: [...selectedMembers] };
            }
            return {
                touser: [...selectedMembers],
                toparty: state.toparty.slice(),
                totag: state.totag.slice(),
                is_all: state.is_all
            };
        }

        function render() {
            const wrap = document.createElement('div');
            wrap.className = 'app-recipient-picker space-y-3';

            if (mode === 'rule') {
                // 全体开关（仅规则模式）。
                const allRow = document.createElement('label');
                allRow.className = 'flex items-center gap-2 cursor-pointer';
                const allCb = document.createElement('input');
                allCb.type = 'checkbox';
                allCb.className = 'checkbox checkbox-sm';
                allCb.checked = state.is_all;
                allCb.addEventListener('change', () => {
                    state.is_all = allCb.checked;
                    notify();
                });
                const allLabel = document.createElement('span');
                allLabel.textContent = '全体成员（@all）';
                allRow.appendChild(allCb);
                allRow.appendChild(allLabel);
                wrap.appendChild(allRow);
            }

            // 搜索框。
            const search = document.createElement('input');
            search.type = 'search';
            search.placeholder = '搜索成员 UserID / 姓名';
            search.className = 'input input-bordered input-sm w-full';
            search.setAttribute('aria-label', '搜索成员');
            wrap.appendChild(search);

            // 全选（member 模式 / 非 is_all）。
            const toolbar = document.createElement('div');
            toolbar.className = 'flex items-center justify-between text-xs';
            const selectAllBtn = document.createElement('button');
            selectAllBtn.type = 'button';
            selectAllBtn.className = 'btn btn-ghost btn-xs';
            selectAllBtn.textContent = '全选';
            const countLabel = document.createElement('span');
            countLabel.className = 'text-base-content/60';
            toolbar.appendChild(selectAllBtn);
            toolbar.appendChild(countLabel);
            wrap.appendChild(toolbar);

            // 成员列表。
            const list = document.createElement('div');
            list.className = 'border border-base-200 rounded-lg max-h-48 overflow-y-auto p-2';
            list.setAttribute('role', 'group');
            list.setAttribute('aria-label', '可选成员列表');
            wrap.appendChild(list);

            function renderList(filter) {
                list.innerHTML = '';
                const f = (filter || '').trim().toLowerCase();
                const shown = users.filter(u => !f
                    || String(u.userid || '').toLowerCase().includes(f)
                    || String(u.name || '').toLowerCase().includes(f));
                if (shown.length === 0) {
                    const empty = document.createElement('div');
                    empty.className = 'text-sm text-base-content/50 py-2 text-center';
                    empty.textContent = users.length === 0 ? '暂无可选成员' : '无匹配成员';
                    list.appendChild(empty);
                }
                shown.forEach(u => {
                    const row = document.createElement('label');
                    row.className = 'flex items-center gap-2 py-1 cursor-pointer hover:bg-base-200 rounded px-1';
                    const cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.className = 'checkbox checkbox-sm';
                    cb.checked = selectedMembers.has(u.userid);
                    cb.addEventListener('change', () => {
                        if (cb.checked) selectedMembers.add(u.userid);
                        else selectedMembers.delete(u.userid);
                        updateCount();
                        notify();
                    });
                    const label = document.createElement('span');
                    label.className = 'text-sm';
                    const display = u.displayName || u.name || u.userid;
                    label.textContent = display + (u.userid !== display ? ' (' + u.userid + ')' : '');
                    row.appendChild(cb);
                    row.appendChild(label);
                    list.appendChild(row);
                });

                // orphan 成员：通讯录无权限时仍显示，可取消勾选。
                orphan.forEach(userid => {
                    if (users.some(u => u.userid === userid)) return;
                    const row = document.createElement('label');
                    row.className = 'flex items-center gap-2 py-1 cursor-pointer hover:bg-base-200 rounded px-1';
                    const cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.className = 'checkbox checkbox-sm';
                    cb.checked = selectedMembers.has(userid);
                    cb.addEventListener('change', () => {
                        if (cb.checked) selectedMembers.add(userid);
                        else selectedMembers.delete(userid);
                        updateCount();
                        notify();
                    });
                    const label = document.createElement('span');
                    label.className = 'text-sm text-warning';
                    label.textContent = userid + '（通讯录不可见）';
                    row.appendChild(cb);
                    row.appendChild(label);
                    list.appendChild(row);
                });
            }

            function updateCount() {
                countLabel.textContent = '已选 ' + selectedMembers.size + ' 个成员';
            }

            selectAllBtn.addEventListener('click', () => {
                const allSelected = users.every(u => selectedMembers.has(u.userid));
                if (allSelected) {
                    users.forEach(u => selectedMembers.delete(u.userid));
                } else {
                    users.forEach(u => selectedMembers.add(u.userid));
                }
                renderList(search.value);
                updateCount();
                notify();
            });

            search.addEventListener('input', () => renderList(search.value));

            renderList('');
            updateCount();

            // 规则模式：部门/标签手动输入（保留规则页语义）。
            if (mode === 'rule') {
                const partyRow = makeListInput('部门 ID（多个用逗号分隔）', state.toparty, val => { state.toparty = val; notify(); });
                const tagRow = makeListInput('标签 ID（多个用逗号分隔）', state.totag, val => { state.totag = val; notify(); });
                wrap.appendChild(partyRow);
                wrap.appendChild(tagRow);
            }

            return wrap;
        }

        function onChange(fn) { listeners.push(fn); }

        // 多应用（二次复验 P0-02 + 第三轮 P2-5）：受控重置选中态。
        //
        // 用于编辑页“保存成功/409 冲突恢复”后把 picker 显式重置为目标选中集合，
        // 而不是依赖陈旧的 currentMembers.current 重建。不可见的 userid 作为 orphan
        // 显示，不丢弃。
        //
        // 多应用（第三轮 P2-5）：受控重置时替换 orphan 基线，不再无限累积旧 orphan。
        // 多次恢复后只保留本次 setValue 指定的 orphan，避免保留不再相关的未选项。
        //
        // @param {string[]} userids 目标选中集合
        // @param {object} [opts]
        // @param {string[]} [opts.orphan] 不可见 userid（替换 orphan 基线）
        function setValue(userids, opts) {
            const list = Array.isArray(userids) ? userids.slice() : [];
            // 替换 orphan 基线（而非追加）。
            orphan.length = 0;
            if (Array.isArray(opts && opts.orphan)) {
                opts.orphan.forEach(id => orphan.push(id));
            }
            selectedMembers.clear();
            list.forEach(id => selectedMembers.add(id));
            state.touser = [...selectedMembers];
            // 重建列表以反映新选中态与 orphan。
            container.innerHTML = '';
            container.appendChild(render());
            notify();
        }

        return { getValue, onChange, setValue };
    }

    // 构造一个逗号分隔的 ID 列表输入行（规则页部门/标签用）。
    function makeListInput(placeholder, initial, onChange) {
        const wrap = document.createElement('div');
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'input input-bordered input-sm w-full';
        input.placeholder = placeholder;
        input.value = Array.isArray(initial) ? initial.join(',') : '';
        input.addEventListener('input', () => {
            const list = input.value.split(/[,，;；\s]+/).map(s => s.trim()).filter(Boolean);
            onChange(list);
        });
        wrap.appendChild(input);
        return wrap;
    }

    window.AppRecipientPicker = { create };
})();
