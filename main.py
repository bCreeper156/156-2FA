# -*- coding: utf-8 -*-
"""
156-2FA 主程序（前端已与后端分离）
- 多用户：本地用户表 data/users.json，口令仅以 Argon2id 哈希保存
- gui（默认）：先显示带进度条的启动窗口，初始化完成并关闭后再弹出登录/注册窗口（所有窗口默认居中），
  校验通过后解密该用户自己的加密 JSON 保险库，
  再启动本地 HTTP 服务（默认 127.0.0.1 + 随机端口，可在设置页自定义），
  并在同一个 pywebview 窗口进程中打开验证码主界面（不使用外部浏览器）
- serve：无界面服务端，解锁保险库后常驻对外提供 REST API，供本机或远程客户端连接
- 关闭主窗口 / Ctrl+C 即退出，内存中的敏感数据被清理
MIT License
Copyright (c) 2026
"""

import json
import os
import secrets
import sys
import time

import apiconfig
from apiconfig import (  # 数据根目录与连接配置统一由 apiconfig 提供
    base_dir,
    data_root,
    is_wildcard_host,
    local_addresses,
    normalize_host,
    parse_port,
    port_available,
    url_host,
)
from openapi import API_VERSION
from server import IDLE_TIMEOUT, BindError, LocalServer
from storage import Vault, VaultError
from users import UserError, UserStore

# 早期版本用于注入主密码的环境变量，现已废弃，仅在重置时清理残留
LEGACY_ENV_MASTER_PASS = "TOTP_MASTER_PASS"


def resource_path(relative_path: str) -> str:
    """获取资源绝对路径，兼容开发环境与 PyInstaller 打包"""
    base_path = getattr(sys, "_MEIPASS", None)
    if not base_path:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def frontend_url(server) -> str:
    """拼接前端访问地址：IPv6 加方括号、通配地址回落到 127.0.0.1，并附会话令牌"""
    return f"http://{url_host(server.host)}:{server.port}/?token={server.frontend_token}"


def validate_listen(host, port, check_port: bool = True):
    """校验监听 IP 与端口

    返回 (host, port)；不符合时抛出 ValueError 并给出可直接展示的原因。
    校验项：地址可解析 / 属于本机 / 端口范围合法 / 端口未被占用（可被 check_port 关闭）。
    """
    text = normalize_host(host)
    if text == "*":
        text = "0.0.0.0"
    if not apiconfig.host_resolvable(text):
        raise ValueError(f"无法解析监听地址：{text}")
    loopback = apiconfig.LOOPBACK_HOSTS
    if not is_wildcard_host(text) and text not in loopback and text not in local_addresses():
        raise ValueError(f"{text} 不是本机可用地址，请填写 127.0.0.1、0.0.0.0 或本机网卡 IP")
    value = parse_port(port)
    if check_port and value is not None and not port_available(text, value):
        raise ValueError(f"端口 {value} 在 {text} 上已被占用，请更换端口或留空使用随机端口")
    return text, value


def create_server(vault, username: str, network=None, idle_timeout=None, serve_static: bool = True):
    """按连接配置创建本地服务实例"""
    network = network or apiconfig.load_connection_config()
    return LocalServer(
        vault, resource_path("web"),
        host=network.get("host") or apiconfig.DEFAULT_HOST,
        port=network.get("port"),
        idle_timeout=idle_timeout,
        username=username,
        serve_static=serve_static,
        access_token=network.get("accessToken") or None,
        mode=network.get("mode") or apiconfig.LOCAL_MODE,
        extra_hosts=network.get("extraHosts"),
    )


def resolve_port_conflict(network: dict, requested_port) -> tuple:
    """端口冲突时的回落策略

    用户显式指定的端口被占用时不静默换端口（那会让地址与预期不符），
    交由调用方提示；仅当配置为随机端口时才重新挑选。
    """
    if requested_port is None:
        return None, None
    host = network.get("host") or apiconfig.DEFAULT_HOST
    host_ok = apiconfig.host_resolvable(host) and (
        is_wildcard_host(host) or host in local_addresses()
        or host in apiconfig.LOOPBACK_HOSTS
    )
    if host_ok and port_available(host, requested_port):
        return requested_port, None
    fallback = apiconfig.pick_free_port(host if host_ok else apiconfig.DEFAULT_HOST)
    return fallback, (
        f"配置的端口 {requested_port} 在 {host} 上不可用，本次已改用随机端口 {fallback}"
        if requested_port else None
    )


def probe_remote_api(url, token="", timeout: float = 8.0) -> dict:
    """由桌面端代为探测远程 API（桌面端不受浏览器同源策略限制，错误信息也更明确）"""
    import urllib.request

    try:
        target = apiconfig.validate_remote_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if not target:
        return {"ok": False, "error": "请填写远程 API 地址"}

    request = urllib.request.Request(target + "/api/health", headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", "Bearer " + str(token).strip())
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except Exception as exc:
        return {"ok": False, "error": f"连接失败：{exc}"}

    latency = int((time.time() - started) * 1000)
    try:
        payload = json.loads(raw)
    except ValueError:
        return {"ok": False, "error": "响应不是合法的 JSON，可能不是 156-2FA 服务"}
    if status >= 400 or payload.get("ok") is False:
        return {"ok": False, "error": payload.get("error") or f"服务返回 HTTP {status}"}
    return {"ok": True, "latencyMs": latency, "info": payload, "url": target}


def apply_listen_change(ctx: dict, on_reset, host, port, loader=None) -> dict:
    """按新的监听地址重建本地服务（端口 / IP 自定义的核心流程）

    顺序刻意设计为「先校验 → 再启动 → 最后落盘」：
    1. 目标地址必须属于本机且端口未被占用，否则保持现状并说明原因；
    2. 新服务真正监听成功后才写入配置，避免出现「配置改了但服务起不来」；
    3. 中途失败会用原地址完整回滚（含重置回调），用户不会陷入不可用状态。

    loader：可选回调，用于在令牌变化后让桌面窗口重新加载（自己带新令牌），
    避免页面还拿着旧令牌继续请求。
    """
    vault = ctx.get("vault")
    if vault is None:
        return {"ok": False, "error": "保险库尚未解锁"}

    old = ctx.get("server")
    previous = {
        "host": old.host if old is not None else apiconfig.DEFAULT_HOST,
        "port": old.requested_port if old is not None else None,
        # 真实端口用作回滚目标：原端口此刻已被本服务占用，不能按「被占用」处理
        "actual": old.port if old is not None else None,
    }

    try:
        new_host, new_port = validate_listen(host, port, check_port=False)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # 配置未变化时不重建服务：既省一次重启，也避免令牌轮换导致页面重新加载
    if old is not None and new_host == old.host and new_port == previous["port"]:
        return {"ok": True, "restarted": False, "url": frontend_url(old),
                "host": old.host, "port": old.port}

    # 端口冲突必须在服务**停下来之前**判断，这样失败时不需要回滚
    if new_port is not None and not port_available(new_host, new_port):
        return {"ok": False, "error": f"端口 {new_port} 在 {new_host} 上已被占用，"
                                      f"请更换端口或留空使用随机端口"}

    def build(host_value, port_value):
        network = apiconfig.load_connection_config()
        return LocalServer(
            vault, resource_path("web"), host=host_value, port=port_value,
            idle_timeout=None, username=ctx.get("username") or "",
            serve_static=True, access_token=network.get("accessToken") or None,
            mode=apiconfig.LOCAL_MODE, extra_hosts=network.get("extraHosts"),
        )

    if old is not None:
        try:
            old.stop()
        except Exception:
            pass
    ctx["server"] = None

    try:
        server = build(new_host, new_port)
        started_port = server.start()
    except Exception as exc:
        restored = None
        for candidate in ((previous["host"], previous["actual"]), (previous["host"], None)):
            try:
                candidate_server = build(*candidate)
                candidate_server.start()
                restored = candidate_server
                break
            except Exception:
                continue
        if restored is not None:
            restored.on_reset = on_reset
            ctx["server"] = restored
        label = f"{new_host}:{new_port or '随机端口'}"
        message = f"无法监听 {label}：{exc}"
        if restored is None:
            message += "；旧服务也未能恢复，请重启程序"
        return {"ok": False, "error": message, "rolledBack": restored is not None}

    server.on_reset = on_reset
    ctx["server"] = server
    try:
        apiconfig.save_connection_config(mode=apiconfig.LOCAL_MODE, host=new_host, port=new_port)
    except Exception:
        pass

    # 令牌已变化：让桌面窗口自己带着新令牌重新加载，避免前端与后端同时跳转竞争
    url = frontend_url(server)
    if callable(loader):
        try:
            loader(url)
        except Exception:
            pass
    return {"ok": True, "restarted": True, "url": url,
            "host": server.host, "port": started_port}


def web_storage_path() -> str:
    """pywebview 本地存储目录（仅保存主题等界面偏好）"""
    return os.path.join(data_root(), "webview")


def users_store() -> UserStore:
    """用户表（users.json 与各用户的 vaults/*.json 都位于数据根目录下）"""
    return UserStore(data_root())


def legacy_vault_path() -> str:
    """早期单用户版本的保险库文件路径（升级时尝试接管）"""
    return os.path.join(data_root(), "vault.json")


# ------------------------------------------------------------------
# 数据根目录记录（应对 TOTP_DATA_FILE 被多次修改）
# ------------------------------------------------------------------
STATE_FILE = ".2fa-state.json"


def state_file_path() -> str:
    """程序状态文件：记录使用过的数据根目录（位于程序目录，便于重置时读取）"""
    return os.path.join(base_dir(), STATE_FILE)


def _load_state() -> dict:
    """读取状态文件，异常时返回空字典"""
    try:
        with open(state_file_path(), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict):
            return doc
    except Exception:
        pass
    return {}


def _save_state(state: dict):
    """尽力写盘保存状态（失败时静默，不影响主流程）"""
    try:
        with open(state_file_path(), "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
    except Exception:
        pass


def used_data_roots() -> list:
    """历史上使用过的全部数据根目录（绝对路径，去重、保序）"""
    state = _load_state()
    roots = []
    raw = state.get("dataRoots")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item:
                abspath = os.path.abspath(item)
                if abspath not in roots:
                    roots.append(abspath)
    # 兼容更早版本记录的数据文件路径
    legacy = state.get("dataPaths")
    if isinstance(legacy, list):
        for item in legacy:
            if isinstance(item, str) and item:
                abspath = os.path.dirname(os.path.abspath(item))
                if abspath and abspath not in roots:
                    roots.append(abspath)
    return roots


def remember_data_root() -> str:
    """记录本次生效的数据根目录：始终以当前环境变量（或默认路径）为准"""
    current = os.path.abspath(data_root())
    state = _load_state()
    roots = used_data_roots()
    if current not in roots:
        roots.append(current)
    state["dataRoots"] = roots
    state["currentDataRoot"] = current
    _save_state(state)
    return current


# ------------------------------------------------------------------
# 旧版主密码环境变量清理（仅清理残留，不再读取）
# ------------------------------------------------------------------
def _broadcast_env_change():
    """通知 Windows 各进程刷新环境变量（尽力而为）"""
    try:
        import ctypes

        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            ctypes.c_wchar_p("Environment"),
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )
    except Exception:
        pass


def _strip_env_from_shell_configs(var_name: str):
    """从常见 shell 配置文件中移除导出语句（Linux / macOS，尽力而为）"""
    home = os.path.expanduser("~")
    targets = [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zshenv",
        os.path.join(".config", "fish", "config.fish"),
    ]
    for name in targets:
        path = os.path.join(home, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception:
            continue
        kept = [line for line in lines if var_name not in line]
        if len(kept) != len(lines):
            try:
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.writelines(kept)
            except Exception:
                pass


def clear_legacy_env():
    """清除早期版本注入主密码的环境变量（当前进程 + Windows 持久变量 + *nix shell 配置）"""
    try:
        os.environ.pop(LEGACY_ENV_MASTER_PASS, None)
    except Exception:
        pass

    if os.name == "nt":
        try:
            import winreg

            for hive, sub in (
                (winreg.HKEY_CURRENT_USER, "Environment"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            ):
                try:
                    with winreg.OpenKey(
                        hive, sub, 0, winreg.KEY_READ | winreg.KEY_WRITE
                    ) as key:
                        try:
                            winreg.DeleteValue(key, LEGACY_ENV_MASTER_PASS)
                        except FileNotFoundError:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        _broadcast_env_change()
        return

    _strip_env_from_shell_configs(LEGACY_ENV_MASTER_PASS)


# ------------------------------------------------------------------
# 重置与数据清理
# ------------------------------------------------------------------
RESET_MARKER = ".reset-pending"


def reset_marker_path() -> str:
    """重置标记文件（位于数据根目录），用于下次启动补齐清理"""
    return os.path.join(data_root(), RESET_MARKER)


def remove_path(path: str, attempts: int = 6, delay: float = 0.25) -> bool:
    """反复尝试删除文件或目录，返回是否已确认删除（应对文件被占用的情况）"""
    import shutil

    for index in range(attempts):
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=False)
            elif os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        if not os.path.exists(path):
            return True
        if index < attempts - 1:
            time.sleep(delay)
    return not os.path.exists(path)


def _wipe_targets(root: str) -> list:
    """某个数据根目录下需要清理的全部路径"""
    store = UserStore(root)
    targets = [
        store.users_file,
        store.users_file + ".tmp",
        store.vault_dir,
        os.path.join(root, "webview"),
        os.path.join(root, "vault.json"),          # 早期单用户保险库
        os.path.join(root, "vault.json.tmp"),
    ]
    for vault in store.all_vault_paths():
        targets.append(vault)
        targets.append(vault + ".tmp")
    return targets


def wipe_user_data() -> list:
    """删除用户表、各用户保险库与界面偏好，返回未能删除的路径列表。

    会清理当前数据根目录以及历史上使用过的**全部**数据根目录，
    确保彻底回到「未使用」状态。
    """
    roots = used_data_roots()
    current = os.path.abspath(data_root())
    if current not in roots:
        roots.append(current)

    targets = []
    for root in roots:
        targets.extend(_wipe_targets(root))

    failed = [path for path in targets if not remove_path(path)]

    # 各数据根目录若已清空则一并移除
    for root in roots:
        try:
            if os.path.isdir(root) and not os.listdir(root):
                os.rmdir(root)
        except Exception:
            pass

    # 仅当全部清理成功时才删除状态文件；否则保留以便下次启动重试
    if not failed:
        remove_path(state_file_path())
    return failed


def pending_reset_dirs() -> list:
    """可能残留重置标记的目录：当前数据根目录 + 历史数据根目录"""
    dirs = []
    for root in used_data_roots() + [os.path.abspath(data_root())]:
        if root and root not in dirs:
            dirs.append(root)
    return dirs


def pending_reset_markers() -> list:
    """所有可能出现重置标记的文件路径"""
    return [os.path.join(directory, RESET_MARKER) for directory in pending_reset_dirs()]


def has_pending_reset() -> bool:
    """是否存在待补齐的重置残留（状态文件记录或标记文件）"""
    if _load_state().get("resetPending"):
        return True
    return any(os.path.exists(marker) for marker in pending_reset_markers())


def mark_pending_reset():
    """写入重置标记，确保下次启动补齐清理（WebView2 退出时可能重建缓存目录）"""
    marker = reset_marker_path()
    try:
        parent = os.path.dirname(marker)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
    except Exception:
        pass

    state = _load_state()
    state["resetPending"] = True
    _save_state(state)


def finish_pending_reset() -> bool:
    """若上次重置留下标记，则补齐清理；返回本次启动是否处理了重置残留"""
    if not has_pending_reset():
        return False

    clear_legacy_env()
    markers = pending_reset_markers()
    directories = pending_reset_dirs()
    failed = wipe_user_data()
    if not failed:
        for marker in markers:
            remove_path(marker)
        for directory in directories:
            try:
                if os.path.isdir(directory) and not os.listdir(directory):
                    os.rmdir(directory)
            except Exception:
                pass
    return True


# ------------------------------------------------------------------
# 升级接管：早期单用户保险库 -> 当前用户的保险库
# ------------------------------------------------------------------
def adopt_legacy_vault(vault_path: str, password: str) -> bool:
    """用户还没有自己的保险库时，尝试继承早期的单文件保险库。

    仅当旧文件能用当前口令解开时才接管（旧文件由 PBKDF2 派生，Vault 可读），
    接管后立即以 Argon2id 重新加密写入用户保险库，并删除旧文件。
    """
    if os.path.exists(vault_path):
        return False
    legacy = legacy_vault_path()
    if not os.path.exists(legacy):
        return False

    old = Vault(legacy, password)
    try:
        old.load()
    except Exception:
        old.clear()
        return False

    try:
        new = Vault(vault_path, password)
        new.load()
        new.import_accounts(old.list_accounts(), mode="replace")
    except Exception:
        try:
            new.clear()
        except Exception:
            pass
        old.clear()
        return False

    new.clear()
    old.clear()
    remove_path(legacy)
    return True


# ------------------------------------------------------------------
# 窗口居中：所有窗口默认落在主屏幕正中
# ------------------------------------------------------------------
# 启动窗口尺寸（宽、高）
SPLASH_SIZE = (460, 300)
# 登录窗口 / 主窗口尺寸
LOGIN_SIZE = (440, 640)
MAIN_SIZE = (980, 800)

_screen_cache = {"ready": False, "screen": None}


def primary_screen():
    """主屏幕信息（只查询一次；取不到时返回 None，交由系统自行摆放）"""
    if not _screen_cache["ready"]:
        _screen_cache["ready"] = True
        try:
            import webview

            screens = webview.screens
            _screen_cache["screen"] = screens[0] if screens else None
        except Exception:
            _screen_cache["screen"] = None
    return _screen_cache["screen"]


def center_position(width: int, height: int) -> tuple:
    """按主屏幕尺寸算出居中坐标，用于把窗口默认放在屏幕中间"""
    screen = primary_screen()
    if screen is None:
        return None, None
    return (int(screen.x + max(0, screen.width - width) / 2),
            int(screen.y + max(0, screen.height - height) / 2))


def prefers_dark() -> bool:
    """尽力判断系统是否为深色主题（决定启动窗口底色，判断不了就按浅色处理）"""
    if os.name != "nt":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            return not winreg.QueryValueEx(key, "AppsUseLightTheme")[0]
    except Exception:
        return False


# ------------------------------------------------------------------
# 图形模式：启动窗口 -> 登录窗口 -> 主窗口（同一个 pywebview 生命周期）
# ------------------------------------------------------------------
def run_gui() -> int:
    """在 pywebview 中完成登录/注册与主界面展示，不使用外部浏览器"""
    import webview  # 惰性导入，缺少该依赖时由 run() 回退到控制台模式

    ctx = {
        "store": None,
        "vault": None,
        "server": None,
        "splash_window": None,
        "login_window": None,
        "main_window": None,
        "username": None,
        "unlocked": False,
        "reset": False,
        "boot_error": None,
    }

    def handle_reset():
        """重置程序：标记待清理数据，并销毁所有窗口退出进程"""
        ctx["reset"] = True
        mark_pending_reset()
        for key in ("main_window", "login_window", "splash_window"):
            window = ctx.get(key)
            if window is not None:
                try:
                    window.destroy()
                except Exception:
                    pass

    class MainApi:
        """主窗口原生能力：导出时保存文件、导入时选择文件、切换用户"""

        @staticmethod
        def _dialog_const(name: str):
            """兼容 pywebview 各版本的文件对话框常量"""
            value = getattr(webview, name, None)
            if value is not None:
                return value
            return getattr(webview.FileDialog, name.split("_")[0])

        def current_user(self):
            return {"ok": True, "username": ctx.get("username") or ""}

        def save_export(self, filename, content):
            """弹出系统保存对话框并写入文本"""
            window = ctx["main_window"]
            if window is None:
                return {"ok": False, "error": "主窗口不可用"}
            try:
                target = window.create_file_dialog(
                    self._dialog_const("SAVE_DIALOG"),
                    save_filename=filename or "export.txt",
                )
            except Exception as exc:
                return {"ok": False, "error": f"无法打开保存对话框：{exc}"}
            if not target:
                return {"ok": False, "cancelled": True}

            path = target if isinstance(target, str) else target[0]
            try:
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write("" if content is None else str(content))
            except Exception as exc:
                return {"ok": False, "error": f"写入文件失败：{exc}"}
            return {"ok": True, "path": path, "name": os.path.basename(path)}

        def pick_file(self):
            """弹出系统打开对话框并读取文本内容"""
            window = ctx["main_window"]
            if window is None:
                return {"ok": False, "error": "主窗口不可用"}
            try:
                picked = window.create_file_dialog(
                    self._dialog_const("OPEN_DIALOG"),
                    allow_multiple=False,
                    file_types=("数据文件 (*.json;*.txt)", "所有文件 (*.*)"),
                )
            except Exception as exc:
                return {"ok": False, "error": f"无法打开文件对话框：{exc}"}
            if not picked:
                return {"ok": False, "cancelled": True}

            path = picked[0] if isinstance(picked, (list, tuple)) else picked
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception as exc:
                return {"ok": False, "error": f"读取文件失败：{exc}"}
            return {"ok": True, "name": os.path.basename(path), "content": content}

        def get_connection_config(self):
            """前端连接配置：本地监听信息 + 远程 API 设置"""
            config = apiconfig.client_config()
            server = ctx.get("server")
            if server is not None:
                config["running"] = True
                config["host"] = server.host
                config["port"] = server.port
                config["address"] = f"{url_host(server.host)}:{server.port}"
                config["urls"] = server.access_urls()
                config["docsUrl"] = f"http://{url_host(server.host)}:{server.port}/api/docs"
            else:
                config["running"] = False
            return {"ok": True, "config": config}

        def save_network_config(self, host="", port=None):
            """修改本地监听 IP / 端口（核心流程见 apply_listen_change）"""
            def loader(url):
                window = ctx.get("main_window")
                if window is not None:
                    window.load_url(url)

            return apply_listen_change(ctx, handle_reset, host, port, loader=loader)

        def save_extra_hosts(self, hosts=None):
            """覆盖 Host / Origin 白名单，并让运行中的服务立即生效

            仅监听地址属于本机（回环 / 通配 / 本机网卡 IP）时可用，其余情况直接拒绝。
            """
            try:
                entries = apiconfig.normalize_extra_hosts(hosts)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}

            server = ctx.get("server")
            # 以「实际生效的监听地址」判权，避免页面上改了 IP 却按旧配置放行
            effective = server.host if server is not None \
                else apiconfig.load_connection_config().get("host")
            try:
                apiconfig.save_connection_config(host=effective, extra_hosts=entries)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}

            # 白名单在服务构造时展开，就地重建即可，不必重启服务（避免令牌轮换）
            if server is not None:
                server.extra_hosts = entries
                server.build_access_lists()
            return {"ok": True, "config": apiconfig.client_config(), "restarted": False}

        def save_remote_config(self, url="", token=""):
            """保存远程 API 基址与访问令牌"""
            try:
                apiconfig.save_connection_config(mode=apiconfig.REMOTE_MODE,
                                                 remote_url=url, remote_token=token)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            return {"ok": True, "config": apiconfig.client_config()}

        def set_api_mode(self, mode=""):
            """切换数据来源：本地服务 / 远程 API"""
            try:
                apiconfig.save_connection_config(mode=mode)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            return {"ok": True, "config": apiconfig.client_config()}

        def test_remote(self, url="", token=""):
            """桌面端代为探测远程 API 是否可用（不受浏览器同源策略限制）"""
            return probe_remote_api(url, token)

        def api_docs_url(self):
            """当前实例的接口文档地址"""
            server = ctx.get("server")
            if server is None:
                return {"ok": False, "error": "本地服务未运行"}
            return {"ok": True, "url": f"http://{url_host(server.host)}:{server.port}/api/docs"}

        def open_api_docs(self):
            """在默认浏览器中打开接口文档"""
            result = self.api_docs_url()
            if not result.get("ok"):
                return result
            import webbrowser

            try:
                webbrowser.open(result["url"])
            except Exception as exc:
                return {"ok": False, "error": f"无法打开浏览器：{exc}"}
            return {"ok": True}

        def reload_frontend(self):
            """用当前会话令牌重新加载首页"""
            server, window = ctx.get("server"), ctx.get("main_window")
            if server is None or window is None:
                return {"ok": False, "error": "窗口或本地服务不可用"}
            try:
                window.load_url(frontend_url(server))
            except Exception as exc:
                return {"ok": False, "error": f"刷新失败：{exc}"}
            return {"ok": True}

        def logout(self):
            """切换用户：关闭主窗口与本地服务，重新打开登录窗口"""
            server, vault = ctx.get("server"), ctx.get("vault")
            ctx["server"] = None
            ctx["vault"] = None
            ctx["username"] = None
            ctx["unlocked"] = False
            try:
                if server is not None:
                    server.stop()
            except Exception:
                pass
            try:
                if vault is not None:
                    vault.clear()
            except Exception:
                pass

            main = ctx.get("main_window")
            # 先建立新的登录窗口，再销毁主窗口，避免窗口数归零导致 GUI 循环退出
            open_login_window()
            ctx["main_window"] = None
            if main is not None:
                try:
                    main.destroy()
                except Exception:
                    pass
            return {"ok": True}

    class AuthApi:
        """登录窗口原生能力：列出用户、登录、注册"""

        def list_users(self):
            try:
                names = ctx["store"].usernames()
            except Exception:
                names = []
            return {"ok": True, "users": names, "hasUsers": bool(names)}

        def login(self, username, password):
            if ctx.get("unlocked"):
                return {"ok": True}
            password = "" if password is None else str(password)
            try:
                record = ctx["store"].verify(username, password)
            except Exception as exc:
                return {"ok": False, "message": f"登录失败：{exc}"}
            if not record:
                time.sleep(0.35)  # 轻微延时，降低暴力尝试速度
                return {"ok": False, "message": "用户名或口令错误，请重试"}
            return self._unlock(record["username"], password)

        def register(self, username, password):
            if ctx.get("unlocked"):
                return {"ok": True}
            try:
                record = ctx["store"].register(username, password)
            except UserError as exc:
                return {"ok": False, "message": str(exc)}
            except Exception as exc:
                return {"ok": False, "message": f"创建用户失败：{exc}"}
            result = self._unlock(record["username"], password)
            if not result.get("ok"):
                result["created"] = True
                result["message"] = (f"账户「{record['username']}」已创建，但进入失败："
                                     + (result.get("message") or "未知错误"))
            return result

        def cancel(self):
            try:
                ctx["login_window"].destroy()
            except Exception:
                pass
            return {"ok": True}

        # ---------- 内部 ----------
        def _unlock(self, username, password):
            """打开该用户的保险库并启动本地服务、创建主窗口"""
            try:
                vault_path = ctx["store"].vault_path(username)
            except UserError as exc:
                return {"ok": False, "message": str(exc)}

            try:
                adopt_legacy_vault(vault_path, password)
            except Exception:
                pass

            vault = Vault(vault_path, password)
            try:
                vault.load()
            except VaultError as exc:
                vault.clear()
                return {"ok": False, "message": str(exc)}

            # 端口被占用时不静默失败：改用可用端口并修正配置，保证「改了还能用」
            network = apiconfig.load_connection_config()
            if network.get("port"):
                chosen, notice = resolve_port_conflict(network, network["port"])
                if chosen != network.get("port"):
                    network["port"] = chosen
                    print(f"[提示] {notice or '端口不可用，已改用随机端口'}：{chosen}")
                    try:
                        apiconfig.save_connection_config(port=chosen)
                    except Exception:
                        pass

            try:
                server = create_server(vault, username, network, idle_timeout=None)
                server.start()
            except BindError as exc:
                vault.clear()
                return {"ok": False, "message": str(exc)}
            except Exception as exc:
                vault.clear()
                return {"ok": False, "message": f"本地服务启动失败：{exc}"}

            server.on_reset = handle_reset
            ctx["vault"] = vault
            ctx["server"] = server
            ctx["username"] = username

            url = frontend_url(server)

            # 先创建主窗口，再关闭登录窗口，避免 GUI 循环提前退出
            try:
                width, height = MAIN_SIZE
                x, y = center_position(width, height)
                ctx["main_window"] = webview.create_window(
                    title=f"2FA 动态验证码 · {username}",
                    url=url,
                    width=width,
                    height=height,
                    x=x,
                    y=y,
                    min_size=(460, 560),
                    js_api=MainApi(),
                )
            except Exception as exc:
                server.stop()
                vault.clear()
                ctx["server"] = None
                ctx["vault"] = None
                ctx["username"] = None
                return {"ok": False, "message": f"主窗口创建失败：{exc}"}

            ctx["unlocked"] = True
            login_window = ctx.get("login_window")
            ctx["login_window"] = None
            if login_window is not None:
                try:
                    login_window.destroy()
                except Exception:
                    pass

            return {"ok": True, "url": url}

    def open_login_window(hidden: bool = False):
        """创建登录窗口；hidden=True 时先建好但不显示，便于等启动窗口关闭后再露面"""
        width, height = LOGIN_SIZE
        x, y = center_position(width, height)
        ctx["login_window"] = webview.create_window(
            title="2FA 工具 · 用户登录",
            url=resource_path("web/login.html"),
            width=width,
            height=height,
            x=x,
            y=y,
            resizable=False,
            hidden=hidden,
            js_api=AuthApi(),
        )
        return ctx["login_window"]

    def create_splash_window():
        """启动窗口：无边框小窗，带加载进度条"""
        width, height = SPLASH_SIZE
        x, y = center_position(width, height)
        ctx["splash_window"] = webview.create_window(
            title="156-2FA 正在启动",
            url=resource_path("web/splash.html"),
            width=width,
            height=height,
            x=x,
            y=y,
            resizable=False,
            frameless=True,
            background_color="#1A1D21" if prefers_dark() else "#F4F7FB",
        )
        return ctx["splash_window"]

    def boot():
        """启动流程：按步骤初始化并把进度回报给启动窗口

        每一步都有最短展示时间，避免初始化太快导致进度条一闪而过。
        登录窗口先以隐藏方式建好（保证窗口数不为零，否则 GUI 循环会退出），
        等启动窗口真正关闭后再显示，做到「启动窗口关闭 → 主界面出现」的顺序。
        """
        splash = ctx.get("splash_window")

        def splash_alive():
            return splash is not None and not splash.events.closed.is_set()

        if splash is not None:
            # 等页面就绪（最多 10 秒）后再推进度；用户提前关闭启动窗口则不再继续
            deadline = time.time() + 10
            while splash_alive() and not splash.events.loaded.is_set():
                if time.time() > deadline:
                    break
                time.sleep(0.05)

        def report(percent, message):
            """推进度给启动页；页面不可用时忽略，不阻断启动"""
            if splash is None:
                return
            try:
                splash.evaluate_js("window.setProgress(%d, %s)"
                                   % (max(0, min(100, int(percent))), json.dumps(message)))
            except Exception:
                pass

        def step(percent, message, worker=None, seconds=0.24):
            """执行一步初始化，返回是否仍可继续"""
            started = time.time()
            report(percent, message)
            try:
                if worker is not None:
                    worker()
            except Exception as exc:
                ctx["boot_error"] = f"{message.rstrip('…')}失败：{exc}"
            remaining = seconds - (time.time() - started)
            if remaining > 0:
                time.sleep(remaining)
            return ctx["boot_error"] is None

        def ensure_data_dir():
            os.makedirs(data_root(), exist_ok=True)

        def load_users():
            ctx["store"] = users_store()

        def check_frontend():
            index = resource_path("web/index.html")
            if not os.path.isfile(index):
                raise FileNotFoundError(f"缺少前端文件 {index}")

        for percent, message, worker in (
            (12, "正在初始化运行环境…", ensure_data_dir),
            (34, "正在加载用户数据…", load_users),
            (56, "正在读取连接配置…", apiconfig.load_connection_config),
            (74, "正在校验界面资源…", check_frontend),
            (92, "正在打开登录窗口…", lambda: open_login_window(hidden=True)),
        ):
            if splash is not None and not splash_alive():
                ctx["boot_error"] = ctx["boot_error"] or "启动窗口已被关闭"
                break
            if not step(percent, message, worker):
                break

        if ctx["boot_error"] is None:
            report(100, "准备就绪")
            time.sleep(0.28)
        elif splash is not None:
            try:
                splash.evaluate_js("window.setError(%s)" % json.dumps(ctx["boot_error"]))
            except Exception:
                pass
            time.sleep(1.2)

        if splash is not None:
            try:
                splash.destroy()
            except Exception:
                pass
            # 等启动窗口真正关闭（事件回执）后再显示登录窗口，避免两个窗口同时出现
            deadline = time.time() + 5
            while not splash.events.closed.is_set() and time.time() < deadline:
                time.sleep(0.03)
            ctx["splash_window"] = None

        login = ctx.get("login_window")
        if login is not None and ctx["boot_error"] is None:
            # 启动窗口已关闭，此时才让登录窗口露面（失败重试一次，避免窗口存在却不可见）
            for attempt in (0, 1):
                try:
                    login.show()
                    break
                except Exception:
                    if attempt == 0:
                        time.sleep(0.2)

    try:
        create_splash_window()
    except Exception as exc:
        print(f"[错误] 无法创建启动窗口：{exc}")
        return 1

    try:
        webview.start(boot, private_mode=False, storage_path=web_storage_path())
    except KeyboardInterrupt:
        print("\n[退出] 收到中断信号。")
    finally:
        splash = ctx.get("splash_window")
        if splash is not None:
            try:
                splash.destroy()
            except Exception:
                pass
            ctx["splash_window"] = None
        if ctx["server"] is not None:
            ctx["server"].stop()
        if ctx["vault"] is not None:
            ctx["vault"].clear()
        # 重置程序时，额外清理界面偏好（主题等），确保回到最初状态。
        # WebView2 可能在本进程退出时才把缓存目录写回，故保留标记由下次启动补齐。
        if ctx["reset"]:
            wipe_user_data()

    if ctx["reset"]:
        print("[退出] 程序已重置，所有用户数据已删除。")
        return 0

    if ctx["boot_error"]:
        print(f"[错误] {ctx['boot_error']}")
        return 1

    if not ctx["unlocked"]:
        print("[退出] 未通过登录验证。")
        return 1

    print("[退出] 内存中的敏感数据已清理。")
    return 0


# ------------------------------------------------------------------
# 控制台兜底（无法创建 GUI 窗口时）
# ------------------------------------------------------------------
def console_ask_credentials(store: UserStore):
    """控制台输入用户名与口令；返回 (username, password) 或 None"""
    import getpass

    names = store.usernames()
    if names:
        print("已有用户：" + "、".join(names))

    for attempt in range(3):
        try:
            username = input("用户名：").strip()
            password = getpass.getpass("口令：")
        except Exception:
            return None
        if not username:
            print("用户名不能为空，请重试")
            continue
        if store.get(username) is None:
            print(f"用户「{username}」不存在，请重试")
            continue
        try:
            record = store.verify(username, password)
        except Exception as exc:
            print(f"[错误] {exc}")
            return None
        if record:
            return record["username"], password
        print(f"口令错误，请重试（剩余 {2 - attempt} 次）")
    return None


def console_create_user(store: UserStore):
    """控制台创建首个用户；返回 (username, password) 或 None"""
    import getpass

    print("尚未创建任何用户，请先创建一个账户。")
    for _ in range(3):
        try:
            username = input("新用户名：").strip()
            password = getpass.getpass("设置口令：")
            confirm = getpass.getpass("再次输入口令：")
        except Exception:
            return None
        if password != confirm:
            print("两次输入的口令不一致，请重试")
            continue
        try:
            record = store.register(username, password)
        except UserError as exc:
            print(f"[错误] {exc}")
            continue
        return record["username"], password
    return None


def unlock_interactive():
    """控制台交互登录并解密保险库；成功返回 (username, password, vault)"""
    store = users_store()
    if store.has_users():
        credentials = console_ask_credentials(store)
    else:
        credentials = console_create_user(store)
    if not credentials:
        return None
    username, password = credentials

    try:
        vault_path = store.vault_path(username)
    except UserError as exc:
        print(f"[错误] {exc}")
        return None
    try:
        adopt_legacy_vault(vault_path, password)
    except Exception:
        pass

    vault = Vault(vault_path, password)
    try:
        vault.load()
    except VaultError as exc:
        print(f"[错误] {exc}")
        vault.clear()
        return None
    return username, password, vault


def start_with_fallback(vault, username: str, network=None, idle_timeout=None,
                        serve_static: bool = True):
    """按连接配置启动本地服务；端口不可用时自动回落并修正配置"""
    network = network or apiconfig.load_connection_config()
    if network.get("port"):
        chosen, notice = resolve_port_conflict(network, network["port"])
        if chosen != network.get("port"):
            print(f"[提示] {notice or '端口不可用，已改用随机端口'}：{chosen}")
            network["port"] = chosen
            try:
                apiconfig.save_connection_config(port=chosen)
            except Exception:
                pass
    server = create_server(vault, username, network, idle_timeout=idle_timeout,
                           serve_static=serve_static)
    server.start()
    return server


def run_console() -> int:
    """无图形环境时的兜底流程：控制台登录 + 系统浏览器展示"""
    unlocked = unlock_interactive()
    if not unlocked:
        print("[退出] 未通过登录验证。")
        return 1
    username, password, vault = unlocked

    try:
        server = start_with_fallback(vault, username, idle_timeout=IDLE_TIMEOUT)
    except BindError as exc:
        print(f"[错误] {exc}")
        vault.clear()
        return 1
    except Exception as exc:
        print(f"[错误] 本地服务启动失败：{exc}")
        vault.clear()
        return 1

    def _console_reset():
        mark_pending_reset()
        wipe_user_data()
        server.stop()

    server.on_reset = _console_reset
    url = frontend_url(server)

    print("=" * 60)
    print(" 2FA 本地服务已启动（控制台模式）")
    print(f" 当前用户: {username}")
    print(f" 用户数据: {data_root()}")
    print(f" 服务地址: {url}")
    print(f" 接口文档: http://{url_host(server.host)}:{server.port}/api/docs")
    print(f" 可访问地址: {', '.join(server.access_urls())}")
    print(f" 关闭页面后服务会在 {IDLE_TIMEOUT} 秒空闲后自动退出，也可按 Ctrl+C 结束。")
    print(" 前端仅允许桌面应用内访问，不会自动打开浏览器。")
    print("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[退出] 收到中断信号。")
    finally:
        server.stop()
        vault.clear()
        password = None

    print("[退出] 内存中的敏感数据已清理。")
    return 0


# ------------------------------------------------------------------
# 服务端模式（headless）：对外提供 REST API，供桌面端 / 远程客户端连接
# ------------------------------------------------------------------
def run_api_server(host=None, port=None, token=None, static: bool = True,
                   extra_hosts=None) -> int:
    """无界面 API 服务：解锁保险库后常驻提供 /api/*"""
    unlocked = unlock_interactive()
    if not unlocked:
        print("[退出] 未通过登录验证。")
        return 1
    username, password, vault = unlocked

    network = apiconfig.load_connection_config()
    if host:
        network["host"] = apiconfig.normalize_host(host)
    if port:
        network["port"] = apiconfig.parse_port(port)
    access_token = (str(token).strip() if token else "") or network.get("accessToken") \
        or secrets.token_urlsafe(32)
    generated = not token and not network.get("accessToken")

    # 追加白名单仅在 127.0.0.1 / 0.0.0.0 监听时开放
    extra = None
    if extra_hosts:
        try:
            extra = apiconfig.normalize_extra_hosts(extra_hosts)
        except ValueError as exc:
            print(f"[错误] {exc}")
            vault.clear()
            return 1
    try:
        apiconfig.save_connection_config(host=network["host"], port=network["port"],
                                         access_token=access_token, extra_hosts=extra)
    except ValueError as exc:
        print(f"[错误] {exc}")
        vault.clear()
        return 1
    except Exception:
        pass

    try:
        server = LocalServer(vault, resource_path("web"), host=network["host"],
                             port=network["port"], idle_timeout=None, username=username,
                             serve_static=static, access_token=access_token,
                             cors_origins=["*"], mode=apiconfig.LOCAL_MODE,
                             extra_hosts=extra)
        started = server.start()
    except BindError as exc:
        print(f"[错误] {exc}")
        vault.clear()
        return 1
    except Exception as exc:
        print(f"[错误] 服务启动失败：{exc}")
        vault.clear()
        return 1

    def _server_reset():
        mark_pending_reset()
        wipe_user_data()
        server.stop()

    server.on_reset = _server_reset
    base = f"http://{url_host(server.host)}:{started}"

    print("=" * 64)
    print(" 156-2FA API 服务已启动（服务端模式）")
    print(f" 监听地址 : {server.host}:{started}")
    print(f" 当前用户 : {username}")
    print(f" 用户数据 : {data_root()}")
    print(f" 可访问地址: {', '.join(server.access_urls())}")
    if server.extra_hosts:
        print(f" 追加白名单: {', '.join(server.extra_hosts)}")
    else:
        print(" 追加白名单: 无" + ("（监听地址不属于本机，通道已关闭）"
                                 if not apiconfig.extra_hosts_allowed(server.host) else ""))
    print(f" 接口文档 : {base}/api/docs")
    print(f" OpenAPI  : {base}/api/openapi.json")
    if static:
        print(f" 前端页面 : {base}/?token={server.frontend_token}")
    else:
        print(" 静态资源 : 已关闭（纯 API 模式）")
    print(f" API 令牌 : {access_token}" + ("（本次随机生成并已写入 server.json）" if generated else ""))
    print(" 远程客户端：在桌面端「设置 → 连接」填写上述地址与令牌即可使用。")
    print(" 按 Ctrl+C 停止服务。")
    print("=" * 64)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[退出] 收到中断信号。")
    finally:
        server.stop()
        vault.clear()
        password = None

    print("[退出] 内存中的敏感数据已清理。")
    return 0


# ------------------------------------------------------------------
# 命令行
# ------------------------------------------------------------------
def build_argparser(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        prog="156-2FA",
        description="156-2FA 动态验证码工具：gui 桌面端（默认） / serve 无界面 API 服务端",
    )
    parser.add_argument("command", nargs="?", choices=["gui", "serve"], default="gui",
                        help="gui：桌面窗口（默认）；serve：常驻 API 服务")
    parser.add_argument("--host", dest="host", default=None,
                        help="服务端监听 IP（serve 模式，默认沿用 server.json）")
    parser.add_argument("--port", dest="port", default=None,
                        help="服务端监听端口（留空为随机端口）")
    parser.add_argument("--token", dest="token", default=None,
                        help="对外访问令牌（留空沿用配置或随机生成）")
    parser.add_argument("--no-static", dest="static", action="store_false",
                        help="serve 模式下不挂载前端静态资源（纯 API）")
    parser.add_argument("--allow-host", dest="allow_hosts", action="append", default=None,
                        help="追加 Host / Origin 白名单，可重复；仅监听地址属于本机时可用")
    parser.add_argument("--version", action="version", version=f"156-2FA API {API_VERSION}")
    return parser.parse_args(argv)


# ------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------
def run(argv=None):
    args = build_argparser(argv)

    # 0. 若上次「重置」留下残留（例如 WebView2 退出时重建的缓存目录），先补齐清理
    try:
        if finish_pending_reset():
            print("[启动] 已补齐上次重置的清理。")
    except Exception:
        pass

    # 0.1 记录本次生效的数据根目录：始终以最新环境变量为准，
    #     同时保留历史目录，供「重置」时一并清理
    try:
        remember_data_root()
    except Exception:
        pass

    # 1. 服务端模式：无需图形环境，直接常驻提供 API
    if args.command == "serve":
        return run_api_server(host=args.host, port=args.port, token=args.token, static=args.static,
                              extra_hosts=args.allow_hosts)

    # 2. 优先使用 pywebview 图形窗口；不可用时回退到控制台模式
    try:
        return run_gui()
    except Exception as exc:
        print(f"[提示] 图形窗口不可用（{exc}），改用控制台模式。")
        print("       如需桌面窗口，请先执行：pip install -r requirements.txt")
        return run_console()


if __name__ == "__main__":
    sys.exit(run())
