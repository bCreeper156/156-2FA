/* =====================================================================
 * api.js —— 156-2FA 统一 API 客户端（前后端分离）
 *
 * 前端所有数据访问都经过本模块，页面本身不感知数据来源：
 *   - local  本地桌面服务（同源 /api/*），依赖同机会话令牌
 *   - remote 远程 API（http(s)://host:port），依赖 Bearer 访问令牌
 *
 * 配置优先级：URL 参数 > localStorage > 桌面端连接配置 > 同源
 * MIT License
 * ===================================================================== */
(function (global) {
    'use strict';

    var STORAGE_KEY = '2fa_api_config';
    var LOCAL = 'local';
    var REMOTE = 'remote';

    var state = {
        mode: LOCAL,
        remoteUrl: '',
        remoteToken: '',
        loaded: false
    };

    /* ---------------- 工具 ---------------- */

    function normalizeBase(url) {
        var text = String(url == null ? '' : url).trim().replace(/\/+$/, '');
        if (!text) return '';
        if (!/^https?:\/\//i.test(text)) text = 'http://' + text;
        return text.replace(/\/api$/i, '');
    }

    function now() {
        return (global.performance && global.performance.now) ? performance.now() : Date.now();
    }

    function readQuery() {
        var search = global.location ? global.location.search : '';
        var found = {};
        if (!search || search.length < 2) return found;
        search.slice(1).split('&').forEach(function (pair) {
            if (!pair) return;
            var index = pair.indexOf('=');
            var key = index < 0 ? pair : pair.slice(0, index);
            var value = index < 0 ? '' : pair.slice(index + 1);
            try {
                found[decodeURIComponent(key)] = decodeURIComponent(String(value).replace(/\+/g, ' '));
            } catch (e) {
                found[key] = value;
            }
        });
        return found;
    }

    function readStored() {
        try {
            var raw = global.localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            var parsed = JSON.parse(raw);
            return parsed && typeof parsed === 'object' ? parsed : null;
        } catch (e) {
            return null;
        }
    }

    function writeStored() {
        try {
            global.localStorage.setItem(STORAGE_KEY, JSON.stringify({
                mode: state.mode,
                remoteUrl: state.remoteUrl,
                remoteToken: state.remoteToken
            }));
        } catch (e) { /* 隐私模式下不可写，忽略 */ }
    }

    function desktopApi() {
        return global.pywebview && global.pywebview.api ? global.pywebview.api : null;
    }

    function current() {
        return {
            mode: state.mode,
            remoteUrl: state.remoteUrl,
            remoteToken: state.remoteToken,
            isRemote: state.mode === REMOTE
        };
    }

    /* ---------------- 配置 ---------------- */

    /** 载入配置：本地缓存立即生效，桌面端配置随后异步补齐 */
    function loadConfig() {
        var stored = readStored() || {};
        var query = readQuery();

        state.mode = stored.mode === REMOTE ? REMOTE : LOCAL;
        state.remoteUrl = normalizeBase(stored.remoteUrl);
        state.remoteToken = String(stored.remoteToken || '');
        state.loaded = true;

        // URL 参数可临时覆盖，便于用分享链接直连自部署服务
        if (query.api) {
            state.mode = REMOTE;
            state.remoteUrl = normalizeBase(query.api);
            state.remoteToken = query.apiToken ? String(query.apiToken) : state.remoteToken;
        } else if (query.mode === REMOTE || query.mode === LOCAL) {
            state.mode = query.mode;
        }

        var api = desktopApi();
        if (api && typeof api.get_connection_config === 'function') {
            return api.get_connection_config().then(function (res) {
                var config = res && res.config ? res.config : null;
                if (!config) return current();
                if (config.mode === REMOTE && config.remoteUrl) {
                    state.mode = REMOTE;
                    state.remoteUrl = normalizeBase(config.remoteUrl);
                    state.remoteToken = String(config.remoteToken || '');
                } else if (config.mode === LOCAL) {
                    state.mode = LOCAL;
                }
                writeStored();
                return current();
            }).catch(function () {
                return current();
            });
        }
        return Promise.resolve(current());
    }

    /** 保存远程连接配置（桌面端会同步写入 server.json） */
    function setConfig(options) {
        var input = options || {};
        state.mode = input.mode === REMOTE ? REMOTE : LOCAL;
        state.remoteUrl = normalizeBase(input.remoteUrl);
        state.remoteToken = String(input.remoteToken || '');
        writeStored();

        var api = desktopApi();
        if (api && typeof api.save_remote_config === 'function') {
            return api.save_remote_config(state.remoteUrl, state.remoteToken)
                .then(function () { return current(); })
                .catch(function () { return current(); });
        }
        return Promise.resolve(current());
    }

    function setMode(mode) {
        return setConfig({
            mode: mode === REMOTE ? REMOTE : LOCAL,
            remoteUrl: state.remoteUrl,
            remoteToken: state.remoteToken
        });
    }

    /* ---------------- 请求内核 ---------------- */

    function baseUrlOf(config) {
        return config && config.mode === REMOTE ? config.remoteUrl : '';
    }

    function buildUrl(path, params, config) {
        var url = baseUrlOf(config) + path;
        if (!params) return url;
        var query = Object.keys(params).map(function (key) {
            return encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
        });
        return url + (query.length ? '?' + query.join('&') : '');
    }

    function buildHeaders(config, extra) {
        var headers = {};
        if (config.mode === REMOTE && config.remoteToken) {
            headers['Authorization'] = 'Bearer ' + config.remoteToken;
        }
        if (extra) {
            Object.keys(extra).forEach(function (key) {
                headers[key] = extra[key];
            });
        }
        return headers;
    }

    function decodeError(payload, response) {
        if (payload && payload.error) return payload.error;
        if (response && response.status === 403) {
            return '没有访问权限，请检查地址与访问令牌';
        }
        if (response && response.status === 404) return '接口不存在';
        return response ? ('HTTP ' + response.status) : '网络请求失败';
    }

    /**
     * 统一请求入口
     * @param {string} path 以 /api/ 开头的路径
     * @param {object} options {method, body, params, headers, expectText, config}
     */
    function request(path, options) {
        var settings = options || {};
        var config = settings.config || current();
        var url = buildUrl(path, settings.params, config);
        var init = {
            method: settings.method || 'GET',
            headers: buildHeaders(config, settings.headers),
            cache: 'no-store'
        };
        // 跨源请求不携带 Cookie（远程模式只用 Bearer），同源则保留会话 Cookie
        init.credentials = config.mode === REMOTE ? 'omit' : 'same-origin';
        if (settings.body !== undefined && settings.body !== null) {
            init.headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(settings.body);
        }

        return fetch(url, init).then(function (response) {
            if (settings.expectText) {
                if (!response.ok) {
                    return response.json().catch(function () { return {}; }).then(function (payload) {
                        throw new Error(decodeError(payload, response));
                    });
                }
                return response.text().then(function (text) {
                    return { text: text, headers: response.headers };
                });
            }
            return response.json().catch(function () {
                throw new Error(decodeError(null, response));
            }).then(function (payload) {
                if (!response.ok || payload.ok === false) {
                    throw new Error(decodeError(payload, response));
                }
                return payload;
            });
        });
    }

    /* ---------------- 接口封装 ---------------- */

    function health(options) { return request('/api/health', options); }
    function info() { return request('/api/info'); }
    function listAccounts() { return request('/api/accounts'); }
    function addAccount(payload) { return request('/api/accounts', { method: 'POST', body: payload }); }
    function updateAccount(id, payload) { return request('/api/accounts/' + id, { method: 'PUT', body: payload }); }
    function deleteAccount(id) { return request('/api/accounts/' + id, { method: 'DELETE' }); }
    function importEntry(payload) { return request('/api/import', { method: 'POST', body: payload }); }
    function restore(payload) { return request('/api/restore', { method: 'POST', body: payload }); }
    function resetAll() { return request('/api/reset', { method: 'POST' }); }

    function exportData(format) {
        return request('/api/export', { params: { format: format || 'backup' }, expectText: true });
    }

    /** 连接测试：先用免鉴权的 /api/health 探活，再用令牌取一次真实数据 */
    function probe(options) {
        var input = options || {};
        var config = {
            mode: input.remoteUrl ? REMOTE : LOCAL,
            remoteUrl: normalizeBase(input.remoteUrl),
            remoteToken: String(input.remoteToken || '')
        };
        var api = desktopApi();
        if (api && typeof api.test_remote === 'function' && config.mode === REMOTE) {
            // 桌面端代测：不受浏览器同源策略限制，错误信息更准
            return api.test_remote(config.remoteUrl, config.remoteToken).then(function (res) {
                if (!res || !res.ok) throw new Error((res && res.error) || '连接失败');
                return { ok: true, latencyMs: res.latencyMs, info: res.info, reachable: true };
            });
        }

        var started = now();
        return request('/api/health', { config: config }).then(function (payload) {
            return request('/api/info', { config: config }).then(function (detail) {
                return {
                    ok: true,
                    latencyMs: Math.max(0, Math.round(now() - started)),
                    info: payload,
                    detail: detail,
                    reachable: true
                };
            });
        });
    }

    /** 页面关闭信号（远程模式无意义，忽略即可） */
    function bye() {
        var config = current();
        if (config.mode === REMOTE) return;
        try {
            if (global.navigator && global.navigator.sendBeacon) {
                global.navigator.sendBeacon(buildUrl('/api/bye', null, config), '');
            }
        } catch (e) { /* ignore */ }
    }

    function openApiDocs() {
        var api = desktopApi();
        if (api && typeof api.open_api_docs === 'function') {
            return api.open_api_docs();
        }
        var config = current();
        if (config.mode === REMOTE && config.remoteUrl) {
            try {
                global.open(config.remoteUrl + '/api/docs', '_blank');
                return Promise.resolve({ ok: true });
            } catch (e) {
                return Promise.reject(e);
            }
        }
        try {
            global.open('/api/docs', '_blank');
            return Promise.resolve({ ok: true });
        } catch (e) {
            return Promise.reject(new Error('无法打开接口文档'));
        }
    }

    /** 展示用连接说明，例如「远程 · 192.168.1.9:8765」 */
    function describe(config) {
        var cfg = config || current();
        if (cfg.mode === REMOTE) {
            if (!cfg.remoteUrl) return '远程 API（未配置）';
            return '远程 · ' + cfg.remoteUrl.replace(/^https?:\/\//i, '');
        }
        return '本地服务';
    }

    global.ApiClient = {
        LOCAL: LOCAL,
        REMOTE: REMOTE,
        loadConfig: loadConfig,
        setConfig: setConfig,
        setMode: setMode,
        getConfig: current,
        config: current,
        describe: describe,
        baseUrlOf: baseUrlOf,
        probe: probe,
        health: health,
        info: info,
        listAccounts: listAccounts,
        addAccount: addAccount,
        updateAccount: updateAccount,
        deleteAccount: deleteAccount,
        importEntry: importEntry,
        restore: restore,
        exportData: exportData,
        resetAll: resetAll,
        bye: bye,
        openApiDocs: openApiDocs,
        request: request
    };
})(window);
