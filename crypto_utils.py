# -*- coding: utf-8 -*-
"""
加密工具模块
MIT License
Copyright (c) 2026
"""

import base64
import hashlib
import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Argon2id 密钥派生参数 ----
KDF_NAME = "argon2id"            # 写入保险库文件的算法标识
KDF_TIME_COST = 3                # 迭代轮数
KDF_MEMORY_COST = 65536          # 内存开销（KiB，即 64 MiB）
KDF_PARALLELISM = 4              # 并行度
KDF_HASH_LEN = 32                # 派生密钥长度（AES-256）

SALT_LEN = 32                    # 盐长度（字节）
IV_LEN = 12                      # AES-GCM 初始化向量长度（字节）
KEY_LEN = 32                     # AES-256 密钥长度（字节）
DATA_VERSION = 2                 # 加密数据格式版本

# ---- 旧版 PBKDF2 兼容参数（仅读取历史文件时使用）----
LEGACY_KDF_NAME = "pbkdf2-sha256"
LEGACY_PBKDF2_ITERATIONS = 200_000

# 口令哈希器：Argon2id + 随机盐，输出标准 PHC 字符串
_password_hasher = PasswordHasher(
    time_cost=KDF_TIME_COST,
    memory_cost=KDF_MEMORY_COST,
    parallelism=KDF_PARALLELISM,
    hash_len=KDF_HASH_LEN,
    salt_len=SALT_LEN,
    type=Type.ID,
)


class CryptoError(Exception):
    """加解密相关错误（密码错误或数据损坏）"""
    pass


# ------------------------------------------------------------------
# 密钥派生（保险库加密用）
# ------------------------------------------------------------------
def kdf_params(**overrides) -> dict:
    """当前使用的 Argon2id 参数；写入文件以便将来平滑升级参数"""
    params = {
        "timeCost": KDF_TIME_COST,
        "memoryCost": KDF_MEMORY_COST,
        "parallelism": KDF_PARALLELISM,
        "hashLen": KDF_HASH_LEN,
    }
    for key, value in (overrides or {}).items():
        if value:
            params[key] = value
    return params


def derive_key(password: str, salt: bytes, params: dict = None) -> bytes:
    """使用 Argon2id 从用户口令和盐派生 32 字节密钥"""
    if not isinstance(password, str):
        raise CryptoError("口令类型错误")
    cfg = kdf_params(**(params or {}))
    try:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=int(cfg["timeCost"]),
            memory_cost=int(cfg["memoryCost"]),
            parallelism=int(cfg["parallelism"]),
            hash_len=int(cfg["hashLen"]),
            type=Type.ID,
        )
    except Exception as exc:  # pragma: no cover
        raise CryptoError(f"密钥派生失败: {exc}") from exc


def derive_key_legacy(password: str, salt: bytes, iterations: int = LEGACY_PBKDF2_ITERATIONS) -> bytes:
    """[只读兼容] 旧版 PBKDF2-HMAC-SHA256 派生，仅用于解密历史保险库文件"""
    if not isinstance(password, str):
        raise CryptoError("口令类型错误")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        int(iterations or LEGACY_PBKDF2_ITERATIONS),
        dklen=KEY_LEN,
    )


# ------------------------------------------------------------------
# 口令哈希（用户账户登录校验用）
# ------------------------------------------------------------------
def hash_password(password: str) -> str:
    """生成 Argon2id 口令哈希（PHC 字符串）"""
    if not isinstance(password, str) or not password:
        raise CryptoError("口令不能为空")
    try:
        return _password_hasher.hash(password)
    except Exception as exc:  # pragma: no cover
        raise CryptoError(f"口令哈希失败: {exc}") from exc


def verify_password(password: str, encoded: str) -> bool:
    """校验口令是否与 Argon2id 哈希匹配"""
    if not password or not encoded:
        return False
    try:
        return _password_hasher.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def password_needs_rehash(encoded: str) -> bool:
    """哈希参数是否已落后于当前配置（需要重新哈希）"""
    try:
        return _password_hasher.check_needs_rehash(encoded)
    except Exception:
        return True


# ------------------------------------------------------------------
# 随机数与 AES-GCM
# ------------------------------------------------------------------
def new_salt() -> bytes:
    """生成随机盐"""
    return os.urandom(SALT_LEN)


def new_iv() -> bytes:
    """生成随机初始化向量"""
    return os.urandom(IV_LEN)


def encrypt_with_key(key: bytes, plaintext: bytes, iv: bytes, aad: bytes = None) -> bytes:
    """使用已派生的密钥进行 AES-GCM 加密，返回 密文+认证标签"""
    try:
        return AESGCM(key).encrypt(iv, plaintext, aad)
    except Exception as exc:  # pragma: no cover
        raise CryptoError(f"加密失败: {exc}") from exc


def decrypt_with_key(key: bytes, ciphertext: bytes, iv: bytes, aad: bytes = None) -> bytes:
    """使用已派生的密钥进行 AES-GCM 解密，失败时抛出 CryptoError"""
    try:
        return AESGCM(key).decrypt(iv, ciphertext, aad)
    except Exception as exc:
        raise CryptoError("解密失败：口令错误或数据已损坏") from exc


def b64e(data: bytes) -> str:
    """bytes -> base64 字符串"""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """base64 字符串 -> bytes"""
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise CryptoError("base64 解码失败，数据格式不正确") from exc


def secure_zero(buf) -> None:
    """尽力清理内存中的敏感字节（Python 无法保证完全清除，但可减少残留）"""
    try:
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0
    except Exception:
        pass
