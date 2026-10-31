# -*- coding: utf-8 -*-
"""
TOTP / HOTP 计算模块（纯 Python 实现，无需额外依赖）
- 支持 SHA1 / SHA256 / SHA512
- 默认 6 位验证码、30 秒周期
MIT License
Copyright (c) 2026
"""

import base64
import hashlib
import hmac
import struct
import time

# 支持的摘要算法
_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

# 默认参数
DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6
DEFAULT_ALGORITHM = "SHA1"


def normalize_secret(secret: str) -> str:
    """去除空格、补全 base32 填充、统一大写"""
    if not secret:
        return ""
    s = "".join(secret.split()).upper()
    s = s.rstrip("=")
    pad = (-len(s)) % 8
    return s + ("=" * pad)


def base32_decode(secret: str) -> bytes:
    """将 base32 密钥解码为字节"""
    normalized = normalize_secret(secret)
    if not normalized:
        raise ValueError("密钥为空")
    return base64.b32decode(normalized, casefold=True)


def hotp(secret: str, counter: int, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM) -> str:
    """计算 HOTP 验证码"""
    algo = _ALGOS.get(str(algorithm).upper(), hashlib.sha1)
    key = base32_decode(secret)
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(key, msg, algo).digest()

    # 动态截断
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = binary % (10 ** int(digits))
    return str(code).zfill(int(digits))


def totp(secret: str, period: int = DEFAULT_PERIOD, digits: int = DEFAULT_DIGITS,
         algorithm: str = DEFAULT_ALGORITHM, timestamp: float = None) -> str:
    """根据时间戳计算 TOTP 验证码"""
    if timestamp is None:
        timestamp = time.time()
    period = int(period) or DEFAULT_PERIOD
    counter = int(timestamp) // period
    return hotp(secret, counter, digits, algorithm)


def remaining_seconds(period: int = DEFAULT_PERIOD, timestamp: float = None) -> int:
    """返回当前验证码的剩余有效秒数（1 ~ period）"""
    if timestamp is None:
        timestamp = time.time()
    period = int(period) or DEFAULT_PERIOD
    remaining = period - (int(timestamp) % period)
    return remaining if remaining > 0 else period


def current_counter(period: int = DEFAULT_PERIOD, timestamp: float = None) -> int:
    """返回当前时间步计数器"""
    if timestamp is None:
        timestamp = time.time()
    period = int(period) or DEFAULT_PERIOD
    return int(timestamp) // period
