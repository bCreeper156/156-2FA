# -*- coding: utf-8 -*-
"""
HTTP 服务模块（前后端分离后的后端）

- 纯 REST 接口：/api/* 全部返回 JSON，不再返回页面片段
- 静态前端（web/）只是**可选挂载**，可关闭后由任意静态服务器托管
- 三种调用者：
  1. 桌面端内置 WebView（Cookie / ?token= 会话令牌，受 Host + Origin 白名单保护）
  2. 同机浏览器（同上）
  3. 远程客户端 / 第三方前端（Authorization: Bearer <accessToken>，附带 CORS 支持）
- 端口与监听地址可自定义，并会按**该地址**探测可用性
MIT License
Copyright (c) 2026
"""

import hmac
import json
import mimetypes
import os
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import apiconfig
import openapi
from qr_utils import build_otpauth, decode_qr_from_data_url, parse_otpauth, parse_otpauth_text
from storage import VaultError
from totp_utils import current_counter, remaining_seconds, totp

# 无任何请求时的兜底退出时间（秒）；GUI 模式传 None 可关闭该看门狗
IDLE_TIMEOUT = 600
# 收到页面关闭信号后的延迟退出时间（秒），期间任何请求都会取消退出
BYE_GRACE = 10.0

# 会话 Cookie 名称
FRONTEND_COOKIE = "2fa_frontend"
# API 文档静态页（位于前端目录，可由任意静态服务器托管）
DOCS_PAGE = "apidocs.html"


class BindError(Exception):
    """监听地址 / 端口不可用"""
    pass


class LocalServer:
    """封装本地服务生命周期"""

    def __init__(self, vault, web_dir: str, host: str = apiconfig.DEFAULT_HOST, port=None,
                 idle_timeout=IDLE_TIMEOUT, username: str = "", serve_static: bool = True,
                 access_token: str = None, cors_origins: list = None, mode: str = apiconfig.LOCAL_MODE,
                 extra_hosts=None):
        self.vault = vault
        self.username = username or ""
        self.frontend_token = secrets.token_urlsafe(32)
        self.web_dir = os.path.abspath(web_dir) if web_dir else ""
        self.host = apiconfig.normalize_host(host) or apiconfig.DEFAULT_HOST
        # 显式端口（None 表示随机），start() 绑定失败时会给出明确提示
        self.requested_port = port
        self.port = port or apiconfig.pick_free_port(self.host)
        # idle_timeout 为 None 或 <=0 时不启用空闲自动退出
        # （pywebview 模式由窗口关闭控制生命周期）
        self.idle_timeout = idle_timeout
        self.serve_static = serve_static
        self.mode = mode if mode in (apiconfig.LOCAL_MODE, apiconfig.REMOTE_MODE) else apiconfig.LOCAL_MODE
        # 对外开放 API 的长期令牌（远程客户端使用）；为空表示禁用远程令牌
        self.access_token = (str(access_token).strip() if access_token else "") or None
        self.cors_origins = list(cors_origins) if cors_origins else ["*"]
        # 用户追加的 Host / Origin 白名单（仅 127.0.0.1 / 通配监听时生效）
        self.extra_hosts = apiconfig.normalize_extra_hosts(extra_hosts)

        self.httpd = None
        self._thread = None
        self._watchdog = None
        self._lock = threading.RLock()
        self._shutdown_timer = None
        self._stopping = False
        self.last_seen = time.time()
        # 重置程序时的关闭回调，由宿主（main.py）注册；未注册时仅重置数据
        self.on_reset = None

        self.build_access_lists()

    # ---------- 来源白名单 ----------
    def build_access_lists(self):
        """构造 Host / Origin 白名单（配置变更后可就地重新调用）

        通配地址（0.0.0.0 / ::）时枚举本机全部地址，
        否则只包含配置的地址与回环地址，兼顾自定义 IP 与 DNS Rebinding 防护。
        """
        names = [apiconfig.DEFAULT_HOST, "localhost", "::1"]
        if apiconfig.is_wildcard_host(self.host):
            # 监听全部网卡：本机所有地址都可访问
            for item in apiconfig.local_addresses():
                if item not in names:
                    names.append(item)
        elif self.host not in names:
            names.insert(0, self.host)

        hosts, origins = set(), set()
        for name in names:
            if not name:
                continue
            label = "[" + name + "]" if apiconfig.is_ipv6(name) else name
            hosts.add(name)
            hosts.add(f"{label}:{self.port}")
            origins.add(f"http://{label}:{self.port}")
        if not apiconfig.is_wildcard_host(self.host):
            origins.add(f"http://{self.host}:{self.port}")

        # 用户追加的白名单：仅当监听模式开放该通道时生效（防御历史 / 手工改坏的配置）
        if apiconfig.extra_hosts_allowed(self.host):
            try:
                entries = apiconfig.normalize_extra_hosts(self.extra_hosts)
            except ValueError:
                entries = []
            for entry in entries:
                name, port_value = apiconfig.split_extra_host(entry)
                if not name:
                    continue
                label = ("[" + name + "]" if apiconfig.is_ipv6(name) else name).lower()
                port_value = port_value or self.port
                hosts.add(label)
                hosts.add(f"{label}:{port_value}")
                # 同时放行 http / https 与「带端口 / 不带端口」两种写法：
                # 浏览器对 80 / 443 等默认端口不会在 Origin 里带端口，反代场景还会是 https
                for scheme in ("http", "https"):
                    origins.add(f"{scheme}://{label}")
                    origins.add(f"{scheme}://{label}:{port_value}")

        self.allowed_hosts = hosts
        self.allowed_origins = origins

    def access_urls(self) -> list:
        """对外可访问的地址列表（含 IPv6 方括号处理）"""
        return apiconfig.public_urls(self.host, self.port)

    # ---------- 生命周期 ----------
    def start(self):
        handler = _make_handler(self)
        bind_host = apiconfig.bind_host(self.host)
        # 显式端口需先确认未被占用：Windows 的 SO_REUSEADDR 会放行重复绑定，
        # 否则会出现「服务启动了但请求被别人接走」的假可用状态
        if self.requested_port and not apiconfig.port_available(self.host, self.port):
            raise BindError(
                f"端口 {self.port} 在 {self.host} 上已被其他程序占用，"
                f"请更换端口或留空使用随机端口"
            )
        try:
            self.httpd = ThreadingHTTPServer((bind_host, self.port), handler)
        except OSError as exc:
            raise BindError(
                f"无法监听 {self.host}:{self.port}（{exc.strerror or exc}）。"
                f"请确认该 IP 属于本机且端口未被占用。"
            ) from exc
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.requested_port = self.port
        self.build_access_lists()
        self._stopping = False
        self.last_seen = time.time()
        self._thread = threading.Thread(target=self.httpd.serve_forever, name="http-server", daemon=True)
        self._thread.start()
        self._watchdog = threading.Thread(target=self._watchdog_loop, name="watchdog", daemon=True)
        self._watchdog.start()
        return self.port

    def serve_forever(self):
        """阻塞主线程，直到服务停止"""
        if self._thread:
            self._thread.join()

    def _watchdog_loop(self):
        if not self.idle_timeout or self.idle_timeout <= 0:
            return
        while not self._stopping:
            time.sleep(2.0)
            if self._stopping:
                return
            if time.time() - self.last_seen > self.idle_timeout:
                self._do_shutdown()
                return

    def touch(self):
        """记录一次活跃请求，并取消待执行的退出定时器"""
        self.last_seen = time.time()
        with self._lock:
            if self._shutdown_timer is not None:
                self._shutdown_timer.cancel()
                self._shutdown_timer = None

    def schedule_shutdown(self, delay: float = BYE_GRACE):
        """收到页面关闭信号后，延迟退出；期间若有新请求则取消"""
        if not self.idle_timeout or self.idle_timeout <= 0:
            return
        with self._lock:
            if self._shutdown_timer is not None:
                self._shutdown_timer.cancel()
            timer = threading.Timer(delay, self._do_shutdown)
            timer.daemon = True
            self._shutdown_timer = timer
            timer.start()

    def _do_shutdown(self):
        with self._lock:
            if self._stopping:
                return
            self._stopping = True
            if self._shutdown_timer is not None:
                self._shutdown_timer.cancel()
                self._shutdown_timer = None
        try:
            if self.httpd:
                self.httpd.shutdown()
        except Exception:
            pass

    def stop(self):
        self._do_shutdown()
        try:
            if self.httpd:
                self.httpd.server_close()
        except Exception:
            pass

    # ---------- 重置程序 ----------
    def notify_reset(self, delay: float = 0.8):
        """数据已删除后，延迟调用宿主回调以关闭程序（留出时间让前端提示可见）"""
        callback = self.on_reset
        if not callable(callback):
            return

        def runner():
            try:
                time.sleep(delay)
            except Exception:
                pass
            try:
                callback()
            except Exception:
                pass

        threading.Thread(target=runner, name="reset-callback", daemon=True).start()

    # ---------- 业务数据 ----------
    def _decorate(self, account: dict) -> dict:
        period = account.get("period") or 30
        digits = account.get("digits") or 6
        algorithm = account.get("algorithm") or "SHA1"
        now = time.time()
        try:
            code = totp(account["secret"], period, digits, algorithm, now)
        except Exception:
            code = "------"
        return {
            "id": account["id"],
            "name": account.get("name", ""),
            "issuer": account.get("issuer", ""),
            "createdAt": account.get("createdAt", ""),
            "algorithm": algorithm,
            "digits": digits,
            "period": period,
            "code": code,
            "remaining": remaining_seconds(period, now),
            "counter": current_counter(period, now),
        }

    def accounts_payload(self) -> dict:
        now = time.time()
        accounts = [self._decorate(a) for a in self.vault.list_accounts()]
        accounts.sort(key=lambda a: (a.get("issuer") or "", a.get("name") or ""))
        return {
            "ok": True,
            "address": f"{apiconfig.url_host(self.host)}:{self.port}",
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "serverTime": now,
            "accounts": accounts,
        }

    def info_payload(self) -> dict:
        return {
            "ok": True,
            "service": "156-2FA",
            "version": openapi.API_VERSION,
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "address": f"{apiconfig.url_host(self.host)}:{self.port}",
            "urls": self.access_urls(),
            "documentation": "/api/docs",
            "openapi": "/api/openapi.json",
            "static": self.serve_static,
            "remoteToken": bool(self.access_token),
        }

    def health_payload(self) -> dict:
        """免鉴权健康信息，仅暴露连接测试所需的最小集合"""
        return {
            "ok": True,
            "service": "156-2FA",
            "version": openapi.API_VERSION,
            "mode": self.mode,
            "authRequired": True,
            "username": self.username,
            "serverTime": time.time(),
        }

    def openapi_payload(self) -> dict:
        return openapi.build_openapi(
            server_address=f"{apiconfig.url_host(self.host)}:{self.port}",
            extra_servers=self.access_urls(),
        )

    # ---------- 数据导出 / 导入 ----------
    def export_filename(self, ext: str) -> str:
        """生成带时间戳的导出文件名（纯 ASCII，避免下载时编码问题）"""
        return "2fa-export-" + time.strftime("%Y%m%d-%H%M%S", time.localtime()) + ext

    def export_backup_text(self) -> str:
        """导出：加密备份文件的原始内容（仍由当前用户口令保护）"""
        return self.vault.export_backup()

    def export_otpauth_text(self) -> str:
        """导出：每行一个 otpauth:// 链接的明文文本"""
        lines = [build_otpauth(a) for a in self.vault.list_accounts()]
        return ("\r\n".join(lines) + "\r\n") if lines else ""

    def import_content(self, content: str, mode: str = "merge") -> dict:
        """导入：自动识别加密备份文件或 otpauth 文本，合并或覆盖到仓库"""
        text = (content or "").strip()
        if not text:
            raise VaultError("导入内容为空")

        invalid = 0
        if text.startswith("{"):
            accounts = self.vault.parse_backup(text)
            source = "backup"
        else:
            accounts, invalid = parse_otpauth_text(text)
            source = "text"
            if not accounts:
                raise VaultError("未找到可导入的账户：既不是有效的备份文件，文本中也没有 otpauth 链接")

        result = self.vault.import_accounts(accounts, mode=mode)
        result["source"] = source
        result["invalid"] = invalid
        return result


def _make_handler(app: LocalServer):
    """根据服务实例创建请求处理器类"""

    class Handler(BaseHTTPRequestHandler):
        server_version = "Local2FA/2.0"
        protocol_version = "HTTP/1.1"

        # ---------- 日志 ----------
        def log_message(self, fmt, *args):  # 静默，避免刷屏
            pass

        # ---------- 鉴权 ----------
        def _bearer_token(self) -> str:
            header = self.headers.get("Authorization") or ""
            scheme, _, value = header.partition(" ")
            if scheme.strip().lower() != "bearer":
                return ""
            return value.strip()

        def _remote_ok(self) -> bool:
            """长期 API 令牌（远程客户端）：不受来源限制"""
            token = self._bearer_token()
            if not token or not app.access_token:
                return False
            return hmac.compare_digest(token, app.access_token)

        def _client_ok(self) -> bool:
            """来源校验：Host + Origin 白名单，远程令牌直接放行"""
            if self._remote_ok():
                return True
            # 主机名大小写不敏感（浏览器可能原样透传用户输入的域名）
            host = (self.headers.get("Host") or "").strip().lower()
            if host not in app.allowed_hosts:
                return False
            origin = (self.headers.get("Origin") or "").strip()
            if origin and origin.lower() not in app.allowed_origins:
                return False
            return True

        def _frontend_ok(self) -> bool:
            """桌面端 / 同机浏览器会话令牌：Cookie 或 URL 参数"""
            cookies = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                if "=" in part:
                    key, _, value = part.strip().partition("=")
                    cookies[key] = value
            passed = cookies.get(FRONTEND_COOKIE, "")
            for candidate in (app.frontend_token, app.access_token or ""):
                if candidate and hmac.compare_digest(passed, candidate):
                    return True
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            for value in query.get("token", []):
                for candidate in (app.frontend_token, app.access_token or ""):
                    if candidate and hmac.compare_digest(value or "", candidate):
                        return True
            return False

        def _authorized(self) -> bool:
            return self._remote_ok() or self._frontend_ok()

        # ---------- 响应工具 ----------
        def _cors_headers(self) -> dict:
            """跨域头：远程客户端使用 Bearer 令牌，不需要携带 Cookie"""
            origin = self.headers.get("Origin")
            if "*" in app.cors_origins:
                allow = "*"
            elif origin and origin in app.cors_origins:
                allow = origin
            else:
                return {}
            return {
                "Access-Control-Allow-Origin": allow,
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                "Access-Control-Max-Age": "86400",
                "Access-Control-Expose-Headers": "Content-Disposition, X-Suggested-Filename",
            }

        def _send(self, status: int, body: bytes, content_type: str = "application/octet-stream",
                  extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for key, value in self._cors_headers().items():
                self.send_header(key, value)
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_json(self, obj, status: int = 200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _send_frontend_forbidden(self):
            forbidden_html = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>403 · 2FA API</title>
<style>
:root { color-scheme: light dark; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  font-family:system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif; color:#1e293b;
  background:#f5f7fb; padding:24px; }
@media (prefers-color-scheme:dark) { body { background:#171a1f; color:#edf2f7; } }
.card { max-width:560px; width:100%; padding:32px; border-radius:20px; border:1px solid rgba(127,127,127,.25);
  background:rgba(255,255,255,.72); }
@media (prefers-color-scheme:dark) { .card { background:rgba(38,42,48,.7); } }
h1 { margin:0 0 10px; font-size:22px; }
p { margin:0 0 8px; line-height:1.8; opacity:.85; }
code { padding:2px 6px; border-radius:6px; background:rgba(127,127,127,.16); font-size:13px; }
</style>
</head>
<body>
<main class="card" role="alert">
  <h1>403 · 未授权访问</h1>
  <p>本接口需要提供访问凭据，请改用以下任一方式：</p>
  <p>· 桌面客户端同机会话（自动携带 <code>2fa_frontend</code> 令牌）；</p>
  <p>· 请求头 <code>Authorization: Bearer &lt;accessToken&gt;</code>；</p>
  <p>· 在网址后追加 <code>?token=&lt;accessToken&gt;</code>。</p>
</main>
</body>
</html>"""
            self._send(403, forbidden_html.encode("utf-8"), "text/html; charset=utf-8")

        def _prefers_json(self) -> bool:
            """判断调用方要 JSON 还是 HTML 页面

            /api/* 一律走 JSON（openapi.json 与 docs/API.md 的既定约定）；
            非浏览器客户端（curl、脚本、第三方程序）不会把 text/html 排进食谱，
            同样应拿到 JSON，而不是给浏览器看的可视化提示页。
            """
            path = urllib.parse.urlparse(self.path).path
            if path.startswith("/api/"):
                return True
            # 只有浏览器导航（Accept 带 text/html）才回落到可视化提示页
            accept = (self.headers.get("Accept") or "").lower()
            return "text/html" not in accept

        def _send_forbidden(self, error: str = "缺少或无效的访问凭据"):
            """403：API 调用方拿 JSON，浏览器直接访问时拿可视化提示页"""
            if self._prefers_json():
                self._send_json({"ok": False, "error": error}, status=403)
                return
            self._send_frontend_forbidden()

        def _read_body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except Exception:
                length = 0
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            if not raw:
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                raise ValueError("请求体不是合法的 JSON")

        # ---------- 静态资源 ----------
        def _serve_static(self, path: str):
            if not app.serve_static or not app.web_dir:
                self._send_json({"ok": False, "error": "静态资源未启用"}, status=404)
                return
            if path in ("/", ""):
                path = "/index.html"
            rel = urllib.parse.unquote(path.lstrip("/"))
            target = os.path.normpath(os.path.join(app.web_dir, rel))
            # 防目录穿越：规范化后必须仍在前端目录之内
            if os.path.commonpath([target, app.web_dir]) != app.web_dir:
                self._send_json({"ok": False, "error": "非法路径"}, status=400)
                return
            if not os.path.isfile(target):
                self._send(404, b"404 Not Found", "text/plain; charset=utf-8")
                return
            ctype, _ = mimetypes.guess_type(target)
            if ctype is None:
                ctype = "application/octet-stream"
            if target.endswith(".html"):
                ctype = "text/html; charset=utf-8"
            elif target.endswith(".js"):
                ctype = "application/javascript; charset=utf-8"
            elif target.endswith(".css"):
                ctype = "text/css; charset=utf-8"
            elif target.endswith(".woff2"):
                ctype = "font/woff2"
            elif target.endswith(".woff"):
                ctype = "font/woff"
            elif target.endswith(".ttf"):
                ctype = "font/ttf"
            with open(target, "rb") as fh:
                data = fh.read()
            extra_headers = {}
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            tokens = [app.frontend_token, app.access_token or ""]
            if any(value in tokens for value in query.get("token", []) if value):
                extra_headers["Set-Cookie"] = (
                    f"{FRONTEND_COOKIE}={app.frontend_token}; HttpOnly; SameSite=Strict; Path=/"
                )
            self._send(200, data, ctype, extra_headers)

        def _serve_docs_page(self):
            """优先返回前端目录中的文档页，缺失时回落到内置页面"""
            if app.serve_static and app.web_dir:
                target = os.path.join(app.web_dir, DOCS_PAGE)
                if os.path.isfile(target):
                    with open(target, "rb") as fh:
                        data = fh.read()
                    self._send(200, data, "text/html; charset=utf-8")
                    return
            fallback = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>API 文档 · 156-2FA</title></head>
<body style="font-family:system-ui;padding:40px;line-height:1.8">
<h1>156-2FA API 文档</h1>
<p>机器可读规范：<a href="/api/openapi.json">/api/openapi.json</a></p>
<p>未找到 <code>{DOCS_PAGE}</code>，可将前端目录挂载后重试。</p>
</body></html>"""
            self._send(200, fallback.encode("utf-8"), "text/html; charset=utf-8")

        # ---------- 路由 ----------
        def do_GET(self):
            app.touch()
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            # 健康检查与文档属于公开信息，便于外部探活与查看
            if path == "/api/health":
                self._send_json(app.health_payload())
                return
            if path == "/api/openapi.json":
                self._send_json(app.openapi_payload())
                return
            if path in ("/api/docs", "/api/docs/"):
                self._serve_docs_page()
                return

            if not self._client_ok():
                self._send_forbidden("请求来源不被允许（Host / Origin 不在白名单）")
                return
            if not self._authorized():
                self._send_forbidden("缺少或无效的访问凭据")
                return

            if path == "/api/info":
                self._send_json(app.info_payload())
                return
            if path == "/api/accounts":
                self._send_json(app.accounts_payload())
                return
            if path == "/api/export":
                self._handle_export(parsed)
                return
            self._serve_static(path)

        def do_POST(self):
            app.touch()
            if not self._client_ok():
                self._send_forbidden("请求来源不被允许（Host / Origin 不在白名单）")
                return
            if not self._authorized():
                self._send_forbidden("缺少或无效的访问凭据")
                return
            path = urllib.parse.urlparse(self.path).path

            if path == "/api/bye":
                self._send_json({"ok": True})
                app.schedule_shutdown()
                return

            if path == "/api/reset":
                self._handle_reset()
                return

            try:
                body = self._read_body()
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return

            if path == "/api/accounts":
                self._handle_add(body)
                return
            if path == "/api/import":
                self._handle_import(body)
                return
            if path == "/api/restore":
                self._handle_restore(body)
                return
            self._send_json({"ok": False, "error": "未知接口"}, status=404)

        def do_PUT(self):
            app.touch()
            if not self._client_ok():
                self._send_forbidden("请求来源不被允许（Host / Origin 不在白名单）")
                return
            if not self._authorized():
                self._send_forbidden("缺少或无效的访问凭据")
                return
            path = urllib.parse.urlparse(self.path).path
            account_id = _extract_id(path)
            if account_id is None:
                self._send_json({"ok": False, "error": "未知接口"}, status=404)
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            try:
                account = app.vault.update_account(
                    account_id,
                    name=body.get("name"),
                    issuer=body.get("issuer"),
                    secret=body.get("secret"),
                    algorithm=body.get("algorithm"),
                    digits=body.get("digits"),
                    period=body.get("period"),
                )
            except VaultError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=404)
                return
            self._send_json({"ok": True, "account": app._decorate(account)})

        def do_DELETE(self):
            app.touch()
            if not self._client_ok():
                self._send_forbidden("请求来源不被允许（Host / Origin 不在白名单）")
                return
            if not self._authorized():
                self._send_forbidden("缺少或无效的访问凭据")
                return
            path = urllib.parse.urlparse(self.path).path
            account_id = _extract_id(path)
            if account_id is None:
                self._send_json({"ok": False, "error": "未知接口"}, status=404)
                return
            ok = app.vault.delete_account(account_id)
            if not ok:
                self._send_json({"ok": False, "error": f"未找到 id={account_id}"}, status=404)
                return
            self._send_json({"ok": True})

        def do_OPTIONS(self):
            """跨域预检：仅对持有凭据或无凭据的本地请求回显允许的方法"""
            self.send_response(204)
            self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
            for key, value in self._cors_headers().items():
                self.send_header(key, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # ---------- 业务处理 ----------
        def _handle_add(self, body: dict):
            name = (body.get("name") or "").strip()
            secret = (body.get("secret") or "").strip().replace(" ", "").upper()
            issuer = (body.get("issuer") or "").strip()
            if not secret:
                self._send_json({"ok": False, "error": "缺少 secret 密钥"}, status=400)
                return
            if not name:
                name = issuer or "未命名账户"
            try:
                account = app.vault.add_account(
                    name=name,
                    secret=secret,
                    issuer=issuer,
                    algorithm=body.get("algorithm") or "SHA1",
                    digits=int(body.get("digits") or 6),
                    period=int(body.get("period") or 30),
                )
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            self._send_json({"ok": True, "account": app._decorate(account)})

        def _handle_import(self, body: dict):
            uri = (body.get("uri") or "").strip()
            image = body.get("image")
            try:
                if not uri and image:
                    decoded = decode_qr_from_data_url(image)
                    if not decoded:
                        self._send_json({"ok": False, "error": "未能识别图片中的二维码"}, status=400)
                        return
                    uri = decoded.strip()

                if not uri:
                    self._send_json({"ok": False, "error": "缺少 uri 或 image 参数"}, status=400)
                    return

                if not uri.lower().startswith("otpauth://"):
                    self._send_json({"ok": False, "error": "二维码内容不是 2FA 链接"}, status=400)
                    return

                info = parse_otpauth(uri)
                account = app.vault.add_account(
                    name=info["name"],
                    secret=info["secret"],
                    issuer=info["issuer"],
                    algorithm=info["algorithm"],
                    digits=info["digits"],
                    period=info["period"],
                )
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            except Exception as exc:
                self._send_json({"ok": False, "error": f"导入失败：{exc}"}, status=400)
                return
            self._send_json({"ok": True, "account": app._decorate(account)})

        def _handle_export(self, parsed):
            """导出：返回加密备份或 otpauth 文本，由前端决定保存方式"""
            fmt = (urllib.parse.parse_qs(parsed.query).get("format", ["backup"])[0] or "backup").lower()
            try:
                if fmt == "otpauth":
                    text = app.export_otpauth_text()
                    filename = app.export_filename(".txt")
                else:
                    text = app.export_backup_text()
                    filename = app.export_filename(".json")
            except VaultError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return

            self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8", extra_headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Suggested-Filename": filename,
            })

        def _handle_restore(self, body):
            """导入：自动识别加密备份文件或 otpauth 文本"""
            mode = (body.get("mode") or "merge").lower()
            if mode not in ("merge", "replace"):
                mode = "merge"
            try:
                result = app.import_content(body.get("content") or "", mode=mode)
            except VaultError as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            except Exception as exc:
                self._send_json({"ok": False, "error": f"导入失败：{exc}"}, status=400)
                return
            self._send_json({"ok": True, "result": result})

        def _handle_reset(self):
            """重置程序：删除所有用户数据文件，随后关闭程序"""
            try:
                app.vault.purge()
            except Exception as exc:
                self._send_json({"ok": False, "error": f"重置失败：{exc}"}, status=500)
                return
            self._send_json({"ok": True})
            app.notify_reset()

    return Handler


def _extract_id(path: str):
    """从 /api/accounts/123 中提取 id"""
    parts = [p for p in path.split("/") if p]
    if len(parts) == 3 and parts[0] == "api" and parts[1] == "accounts":
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None
