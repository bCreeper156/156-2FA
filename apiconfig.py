# -*- coding: utf-8 -*-
"""
连接配置模块（前后端分离）

集中管理：
- 数据根目录解析（环境变量 TOTP_DATA_FILE）
- 本地监听地址 / 端口的读写与**可用性校验**
- 远程 API 地址与访问令牌的读写
- 本机地址枚举（用于 Host 白名单与地址展示）

设计要点：
- 端口探测必须绑定**用户指定的 IP**，而不是固定 127.0.0.1，
  否则自定义 IP 时会误判端口可用性（历史 bug 之一）。
- 配置按 version 演进，向后兼容早期仅含 host / port 的 server.json。
MIT License
Copyright (c) 2026
"""

import json
import os
import random
import socket
import sys

# 数据根目录覆盖（可选）：默认 <程序目录>/data
ENV_DATA_FILE = "TOTP_DATA_FILE"
# 对外提供 API 服务的令牌（服务端侧），优先级高于配置文件
ENV_ACCESS_TOKEN = "TOTP_API_TOKEN"

DEFAULT_HOST = "127.0.0.1"
# 通配地址：监听本机全部网卡
WILDCARD_HOSTS = {"", "*", "0.0.0.0", "::"}
PORT_RANGE_START = 30000
PORT_RANGE_END = 60000

CONFIG_FILE = "server.json"
CONFIG_VERSION = 2
LOCAL_MODE = "local"
REMOTE_MODE = "remote"


def base_dir() -> str:
    """程序所在目录：打包后为 exe 同级目录，开发时为脚本目录"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def data_root() -> str:
    """用户数据根目录：默认 <程序目录>/data，可用环境变量覆盖

    环境变量指向文件时取所在目录，指向目录时直接使用。
    """
    override = os.environ.get(ENV_DATA_FILE)
    if override:
        path = os.path.abspath(override)
        if path.lower().endswith(".json"):
            return os.path.dirname(path)
        return path
    return os.path.join(base_dir(), "data")


def config_path() -> str:
    """连接配置文件路径"""
    return os.path.join(data_root(), CONFIG_FILE)


# ------------------------------------------------------------------
# 地址与端口处理
# ------------------------------------------------------------------
def normalize_host(host) -> str:
    """去掉空白与 IPv6 方括号；留空时返回默认回环地址"""
    text = "" if host is None else str(host).strip()
    if not text:
        return DEFAULT_HOST
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    return text


def is_wildcard_host(host) -> bool:
    """是否为通配监听地址（0.0.0.0 / :: / *）"""
    return normalize_host(host) in WILDCARD_HOSTS


def is_ipv6(host) -> bool:
    """是否为 IPv6 字面地址（不含方括号）"""
    text = normalize_host(host)
    if text == "*":
        return False
    return text.count(":") >= 2


def bind_host(host) -> str:
    """socket.bind 使用的地址：`*` 需还原为空字符串"""
    text = normalize_host(host)
    return "" if text == "*" else text


def url_host(host) -> str:
    """拼接 URL 使用的主机片段：通配地址回落到 127.0.0.1，IPv6 加方括号"""
    text = normalize_host(host)
    if text in WILDCARD_HOSTS or text == "*":
        return DEFAULT_HOST
    if is_ipv6(text) and not text.startswith("["):
        return "[" + text + "]"
    return text


def parse_port(port):
    """校验并转换端口；空值返回 None（表示随机端口）"""
    if port in (None, ""):
        return None
    if isinstance(port, bool):
        raise ValueError("端口必须是 1～65535 的整数，或留空表示随机端口")
    try:
        value = int(str(port).strip())
    except (TypeError, ValueError):
        raise ValueError("端口必须是 1～65535 的整数，或留空表示随机端口")
    if not (1 <= value <= 65535):
        raise ValueError("端口必须在 1～65535 之间")
    return value


def host_resolvable(host) -> bool:
    """IP 字面量或可解析的主机名都接受"""
    text = normalize_host(host)
    if text in WILDCARD_HOSTS:
        return True
    try:
        socket.getaddrinfo(text, None, type=socket.SOCK_STREAM)
        return True
    except (OSError, UnicodeError):
        return False


def pick_free_port(host=None) -> int:
    """在指定地址的端口范围内挑选空闲端口；都不通时交给系统分配"""
    target = normalize_host(host) if host else DEFAULT_HOST
    for _ in range(200):
        port = random.randint(PORT_RANGE_START, PORT_RANGE_END)
        if port_available(target, port):
            return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((DEFAULT_HOST, 0))
        return sock.getsockname()[1]


def _in_subnet(address: str, network: str, bits: int) -> bool:
    """判断 IPv4 地址是否落在指定网段"""
    import ipaddress

    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(f"{network}/{bits}", strict=False)
    except ValueError:
        return False


def local_addresses() -> list:
    """本机可用于访问的地址列表（回环 + 各网卡），用于 Host 白名单与地址展示

    过滤链路本地 IPv6（fe80::/10）等无法直连的地址，避免白名单里出现
    「看起来可用、实际连不上」的条目。
    """
    addresses = [DEFAULT_HOST, "::1"]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM):
            value = info[4][0]
            if not value:
                continue
            if value.lower().startswith("fe80:") or value.lower().startswith("169.254."):
                continue
            if value not in addresses:
                addresses.append(value)
    except OSError:
        pass
    # 通过 UDP "连接" 获取默认出口 IP（不会真正发包）
    for probe in (("192.0.2.1", 80), ("8.8.8.8", 80)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(probe)
                value = sock.getsockname()[0]
                if value and not _in_subnet(value, "169.254.0.0", 16) and value not in addresses:
                    addresses.append(value)
            break
        except OSError:
            continue
    return addresses


def port_available(host, port: int, timeout: float = 0.4) -> bool:
    """在**指定地址**上探测端口是否可用

    两步检测，缺一不可：
    1. connect_ex：只要已有服务在该端口监听即视为占用；
    2. bind：确保本机确实能绑定该地址（Windows 的 SO_REUSEADDR 会放行重复
       绑定，因此绑定阶段额外尝试 SO_EXCLUSIVEADDRUSE 兜底）。

    只做 bind 检测是不充分的 —— Windows 上 SO_REUSEADDR 允许两个 socket
    绑定同一端口，会造成「端口已被占用却启动成功、请求被别的服务劫持」。
    """
    probe = normalize_host(host)
    if probe in WILDCARD_HOSTS:
        probe = DEFAULT_HOST
    if probe == "localhost":
        probe = DEFAULT_HOST
    family = socket.AF_INET6 if is_ipv6(probe) else socket.AF_INET

    def listening() -> bool:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((probe, port)) == 0
        except OSError:
            return False

    if listening():
        return False

    has_exclusive = hasattr(socket, "SO_EXCLUSIVEADDRUSE")
    for exclusive in ((True, False) if has_exclusive else (False,)):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                if exclusive:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((probe, port))
                return True
        except OSError:
            continue
    return False


def public_urls(host, port) -> list:
    """该监听地址对外可用的访问地址列表（用于展示与 Host 白名单）"""
    candidates = []
    if is_wildcard_host(host):
        candidates = local_addresses()
    else:
        candidates = [normalize_host(host), DEFAULT_HOST]
    urls = []
    for item in candidates:
        piece = url_host(item)
        candidate = f"http://{piece}:{port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


# ------------------------------------------------------------------
# 配置读写
# ------------------------------------------------------------------
def _default_config() -> dict:
    return {
        "version": CONFIG_VERSION,
        "mode": LOCAL_MODE,
        "host": DEFAULT_HOST,
        "port": None,
        "remoteUrl": "",
        "remoteToken": "",
        "accessToken": "",
    }


def validate_remote_url(url) -> str:
    """规范化远程 API 基址：必须以 http(s):// 开头，去掉尾部的斜杠与 /api"""
    text = "" if url is None else str(url).strip().rstrip("/")
    if not text:
        return ""
    if not (text.startswith("http://") or text.startswith("https://")):
        raise ValueError("远程 API 地址必须以 http:// 或 https:// 开头")
    # 去掉尾部的 /api，统一由客户端拼接
    lowered = text.lower()
    if lowered.endswith("/api"):
        text = text[:-4]
    return text.rstrip("/")


def load_connection_config() -> dict:
    """读取连接配置；文件缺失或不完整时回落到默认值"""
    config = _default_config()
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError, TypeError):
        raw = {}

    if isinstance(raw, dict):
        mode = str(raw.get("mode") or LOCAL_MODE).strip().lower()
        config["mode"] = REMOTE_MODE if mode == REMOTE_MODE else LOCAL_MODE
        host = str(raw.get("host") or "").strip() or DEFAULT_HOST
        if not host_resolvable(host):
            host = DEFAULT_HOST
        config["host"] = host
        try:
            config["port"] = parse_port(raw.get("port"))
        except ValueError:
            config["port"] = None
        try:
            config["remoteUrl"] = validate_remote_url(raw.get("remoteUrl"))
        except ValueError:
            config["remoteUrl"] = ""
        config["remoteToken"] = str(raw.get("remoteToken") or "").strip()
        config["accessToken"] = str(raw.get("accessToken") or "").strip()

    # 环境变量优先级最高，便于服务端部署时不落盘令牌
    env_token = os.environ.get(ENV_ACCESS_TOKEN)
    if env_token:
        config["accessToken"] = env_token.strip()
    return config


def save_connection_config(mode=None, host=None, port=None,
                           remote_url=None, remote_token=None, access_token=None) -> dict:
    """局部更新并保存连接配置；返回保存后的完整配置"""
    current = load_connection_config()

    if mode is not None:
        text = str(mode).strip().lower()
        current["mode"] = REMOTE_MODE if text == REMOTE_MODE else LOCAL_MODE
    if host is not None:
        text = normalize_host(host)
        if text == "*":
            text = "0.0.0.0"
        if not host_resolvable(text):
            raise ValueError("无法解析的监听地址：" + text)
        current["host"] = text
    if port is not None or "port" not in current:
        current["port"] = parse_port(port)
    if remote_url is not None:
        current["remoteUrl"] = validate_remote_url(remote_url)
    if remote_token is not None:
        current["remoteToken"] = "" if remote_token is None else str(remote_token).strip()
    if access_token is not None and not os.environ.get(ENV_ACCESS_TOKEN):
        current["accessToken"] = "" if access_token is None else str(access_token).strip()

    current["version"] = CONFIG_VERSION
    os.makedirs(os.path.dirname(config_path()), exist_ok=True)
    with open(config_path(), "w", encoding="utf-8") as fh:
        json.dump(current, fh, ensure_ascii=False, indent=2)
    return current


def client_config() -> dict:
    """前端使用的连接配置（仅本地监听信息与远程地址，不含对外令牌）"""
    config = load_connection_config()
    return {
        "mode": config["mode"],
        "host": config["host"],
        "port": config["port"],
        "remoteUrl": config["remoteUrl"],
        "remoteToken": config["remoteToken"],
        "hasAccessToken": bool(config["accessToken"]),
    }
