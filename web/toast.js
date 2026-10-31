/*
 * 统一 Toast 提示组件（无依赖，全站共用）
 * ------------------------------------------------------------------
 * 页面内所有浮动提示统一走这里，不再使用 alert / confirm / 自定义提示条。
 *
 * 用法：
 *   Toast.success('已保存修改');
 *   Toast.error('删除失败：网络错误');
 *   Toast.warn('验证码暂不可用');
 *   Toast.info('正在解析二维码…', { duration: 0 });      // 手动关闭
 *   Toast.warn('确定删除「GitHub」？', {                  // 带操作按钮
 *       duration: 0,
 *       closable: true,
 *       action: { label: '删除', onClick: doDelete }
 *   });
 *
 * 选项：
 *   type      success | error | warn | info（也可直接调对应方法）
 *   duration  显示毫秒数，0 表示不自动消失；默认 2600（带 action 时为 0）
 *   closable  是否显示右上角关闭按钮
 *   action    { label, onClick }，在文字右侧渲染一个操作按钮
 *
 * 返回 { dismiss(), element }，可手动提前关闭。
 * 通过 CSS 变量 --toast-bottom 可调整提示距底部的距离。
 * MIT License / Copyright (c) 2026
 */
(function () {
    'use strict';

    if (window.Toast) return;

    var DEFAULT_DURATION = 2600;
    var MAX_VISIBLE = 3;
    var HOST_ID = 'toastHost';
    var STYLE_ID = 'toastStyles';

    var ICONS = {
        success: '<polyline points="20 6 9 17 4 12"></polyline>',
        error: '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>',
        warn: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>' +
              '<line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>',
        info: '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line>' +
              '<line x1="12" y1="8" x2="12.01" y2="8"></line>'
    };

    var CSS = [
        '#toastHost{position:fixed;left:0;right:0;bottom:var(--toast-bottom,32px);z-index:9999;',
        'display:flex;flex-direction:column;align-items:center;gap:10px;padding:0 16px;pointer-events:none}',

        '#toastHost .toast{pointer-events:auto;display:flex;align-items:center;gap:10px;',
        'box-sizing:border-box;max-width:min(92vw,520px);background:#1E293B;color:#F8FAFC;',
        'padding:12px 16px;border-radius:14px;font-size:14px;font-weight:500;line-height:1.45;',
        'font-family:system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;',
        'box-shadow:0 12px 32px rgba(0,0,0,.28);opacity:0;transform:translateY(14px) scale(.97);',
        'transition:opacity .2s ease,transform .2s ease;word-break:break-word}',

        '#toastHost .toast.show{opacity:1;transform:translateY(0) scale(1)}',

        '#toastHost .toast-ico{display:flex;flex-shrink:0}',
        '#toastHost .toast-ico svg{width:18px;height:18px;display:block}',
        '#toastHost .toast-success .toast-ico{color:#4ADE80}',
        '#toastHost .toast-error .toast-ico{color:#F87171}',
        '#toastHost .toast-warn .toast-ico{color:#FBBF24}',
        '#toastHost .toast-info .toast-ico{color:#60A5FA}',

        '#toastHost .toast-text{flex:1 1 auto;min-width:0}',

        '#toastHost .toast-action{flex-shrink:0;background:rgba(255,255,255,.16);color:#fff;border:none;',
        'border-radius:20px;padding:6px 14px;font-size:13px;font-weight:600;font-family:inherit;',
        'cursor:pointer;transition:background .15s}',
        '#toastHost .toast-action:hover{background:rgba(255,255,255,.3)}',

        '#toastHost .toast-close{flex-shrink:0;background:none;border:none;padding:2px;cursor:pointer;',
        'color:rgba(255,255,255,.6);display:flex;transition:color .15s}',
        '#toastHost .toast-close:hover{color:#fff}',
        '#toastHost .toast-close svg{width:16px;height:16px;display:block}',

        'body.dark-mode #toastHost .toast{background:#374151}',
        '@media (prefers-color-scheme:dark){#toastHost .toast{background:#374151}}'
    ].join('');

    function merge(base, extra) {
        var out = {}, key;
        for (key in base) {
            if (Object.prototype.hasOwnProperty.call(base, key)) out[key] = base[key];
        }
        for (key in extra) {
            if (Object.prototype.hasOwnProperty.call(extra, key)) out[key] = extra[key];
        }
        return out;
    }

    function ensureStyles() {
        if (document.getElementById(STYLE_ID)) return;
        var style = document.createElement('style');
        style.id = STYLE_ID;
        style.textContent = CSS;
        document.head.appendChild(style);
    }

    function ensureHost() {
        var host = document.getElementById(HOST_ID);
        if (host) return host;
        host = document.createElement('div');
        host.id = HOST_ID;
        host.setAttribute('role', 'status');
        host.setAttribute('aria-live', 'polite');
        document.body.appendChild(host);
        return host;
    }

    function show(message, options) {
        options = options || {};
        ensureStyles();
        var host = ensureHost();

        var type = ICONS[options.type] ? options.type : 'info';
        var hasAction = !!(options.action && options.action.label);
        var duration = options.duration === undefined
            ? (hasAction ? 0 : DEFAULT_DURATION)
            : (Number(options.duration) || 0);

        // 超出上限时先移除最早的一条，避免堆满屏幕
        while (host.children.length >= MAX_VISIBLE) {
            host.removeChild(host.firstChild);
        }

        var el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.innerHTML =
            '<span class="toast-ico">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" ' +
                    'stroke-linecap="round" stroke-linejoin="round">' + ICONS[type] + '</svg>' +
            '</span>' +
            '<span class="toast-text"></span>';
        el.querySelector('.toast-text').textContent = (message == null) ? '' : String(message);

        var timer = null;
        var closed = false;

        function dismiss() {
            if (closed) return;
            closed = true;
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
            el.classList.remove('show');
            setTimeout(function () {
                if (el.parentNode) el.parentNode.removeChild(el);
            }, 220);
        }

        if (hasAction) {
            var actionBtn = document.createElement('button');
            actionBtn.type = 'button';
            actionBtn.className = 'toast-action';
            actionBtn.textContent = options.action.label;
            actionBtn.addEventListener('click', function () {
                dismiss();
                if (typeof options.action.onClick === 'function') options.action.onClick();
            });
            el.appendChild(actionBtn);
        }

        if (options.closable) {
            var closeBtn = document.createElement('button');
            closeBtn.type = 'button';
            closeBtn.className = 'toast-close';
            closeBtn.setAttribute('aria-label', '关闭');
            closeBtn.innerHTML =
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
                    'stroke-linecap="round">' +
                    '<line x1="18" y1="6" x2="6" y2="18"></line>' +
                    '<line x1="6" y1="6" x2="18" y2="18"></line>' +
                '</svg>';
            closeBtn.addEventListener('click', dismiss);
            el.appendChild(closeBtn);
        }

        host.appendChild(el);
        if (typeof window.requestAnimationFrame === 'function') {
            window.requestAnimationFrame(function () { el.classList.add('show'); });
        } else {
            el.classList.add('show');
        }

        if (duration > 0) timer = setTimeout(dismiss, duration);

        return { dismiss: dismiss, element: el };
    }

    window.Toast = {
        show: show,
        success: function (message, options) {
            return show(message, merge({ type: 'success' }, options));
        },
        error: function (message, options) {
            return show(message, merge({ type: 'error', duration: 3600 }, options));
        },
        warn: function (message, options) {
            return show(message, merge({ type: 'warn', duration: 3200 }, options));
        },
        info: function (message, options) {
            return show(message, merge({ type: 'info' }, options));
        }
    };
})();
