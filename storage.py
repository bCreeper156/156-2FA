# -*- coding: utf-8 -*-
"""
本地加密数据仓库（Vault）
- 读取/写入每个用户自持的加密 JSON 文件
- 账户数据在内存中以明文形式存在，写盘前整体加密
- 每个账户以纯数字 id 唯一标识，name 为备注名称，secret 加密存储
- 密钥由 Argon2id 从用户口令派生（读取早期 PBKDF2 文件时自动兼容）
MIT License
Copyright (c) 2026
"""

import json
import os
import threading
import time

from crypto_utils import (
    DATA_VERSION,
    KDF_NAME,
    LEGACY_PBKDF2_ITERATIONS,
    CryptoError,
    b64d,
    b64e,
    derive_key,
    derive_key_legacy,
    decrypt_with_key,
    encrypt_with_key,
    kdf_params,
    new_iv,
    new_salt,
    secure_zero,
)


# 重置标记文件名（需与 main.py 的 RESET_MARKER 保持一致）
RESET_MARKER = ".reset-pending"


class VaultError(Exception):
    """数据仓库相关错误"""
    pass


def _touch_reset_marker(directory: str):
    """在数据目录落下重置标记：即使进程随后被强杀，下次启动也会补齐清理"""
    try:
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, RESET_MARKER), "w", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
    except Exception:
        pass


def _remove_file(path: str, attempts: int = 6, delay: float = 0.25) -> bool:
    """反复尝试删除文件，返回是否已确认删除（应对文件被短暂占用的情况）"""
    for index in range(attempts):
        try:
            if not os.path.exists(path):
                return True
            os.remove(path)
        except Exception:
            pass
        if not os.path.exists(path):
            return True
        if index < attempts - 1:
            time.sleep(delay)
    return not os.path.exists(path)


class Vault:
    """加密账户仓库"""

    def __init__(self, path: str, password: str):
        self.path = path
        self._accounts = []
        self._lock = threading.RLock()
        # 加密参数（内存中缓存，避免每次落盘重复派生）
        self._key = None
        self._salt = None
        self._kdf = kdf_params()
        self._legacy = False      # 载入的是早期 PBKDF2 文件时置位
        # 口令不以明文 str 常驻内存：XOR 掩码存储（尽力而为的缓解，
        # Python 无法保证彻底清除，但可避免明文长期驻留、被内存转储直接检索到）
        self._pw_mask = None
        self._pw_bytes = None
        self._stash_password(password)

    # ---------- 口令内存保护 ----------
    def _stash_password(self, password: str):
        """把口令以「随机掩码 XOR」形式保存在可清零的 bytearray 中"""
        self._discard_password()
        if not password:
            return
        enc = password.encode("utf-8")
        mask = bytearray(os.urandom(len(enc)))
        self._pw_mask = mask
        self._pw_bytes = bytearray(b ^ m for b, m in zip(enc, mask))

    def _recall_password(self) -> str:
        """临时还原口令（仅在需要派生密钥的瞬间使用）"""
        if not self._pw_bytes:
            return ""
        try:
            return bytes(b ^ m for b, m in zip(self._pw_bytes, self._pw_mask)).decode(
                "utf-8", errors="replace")
        except Exception:
            return ""

    def _discard_password(self):
        """尽力清零内存中的口令副本"""
        secure_zero(self._pw_bytes)
        secure_zero(self._pw_mask)
        self._pw_bytes = None
        self._pw_mask = None

    # ---------- 内部工具 ----------
    def _ensure_parent(self):
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)

    @staticmethod
    def _default_doc() -> dict:
        return {"version": DATA_VERSION, "encrypted": True}

    @staticmethod
    def _is_legacy(doc: dict) -> bool:
        """早期版本的文件没有 kdf 字段，密钥由 PBKDF2 派生"""
        kdf = doc.get("kdf")
        if isinstance(kdf, str) and kdf:
            return kdf != KDF_NAME
        return True

    # ---------- 加载 / 保存 ----------
    def load(self):
        """加载并解密数据文件；若不存在则创建空仓库"""
        with self._lock:
            if not os.path.exists(self.path):
                self._init_empty()
                return

            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except Exception as exc:
                raise VaultError(f"数据文件无法读取：{exc}") from exc

            if not isinstance(doc, dict) or "salt" not in doc or "data" not in doc:
                raise VaultError("数据文件格式不正确，或不是本工具生成的文件")

            try:
                salt = b64d(doc["salt"])
                iv = b64d(doc["iv"])
                ciphertext = b64d(doc["data"])
            except CryptoError as exc:
                raise VaultError(str(exc)) from exc

            legacy = self._is_legacy(doc)
            if legacy:
                iterations = int(doc.get("iterations", LEGACY_PBKDF2_ITERATIONS))
                key = derive_key_legacy(self._recall_password(), salt, iterations)
                kdf = None
            else:
                iterations = 0
                params = doc.get("kdfParams") if isinstance(doc.get("kdfParams"), dict) else {}
                kdf = kdf_params(**params)
                key = derive_key(self._recall_password(), salt, kdf)

            try:
                plain = decrypt_with_key(key, ciphertext, iv)
            except CryptoError as exc:
                raise VaultError("解密失败：口令错误，或数据文件已损坏") from exc

            try:
                accounts = json.loads(plain.decode("utf-8"))
            except Exception as exc:
                raise VaultError(f"解密内容格式错误：{exc}") from exc

            if not isinstance(accounts, list):
                raise VaultError("解密后的账户数据格式不正确")

            self._accounts = [self._normalize(a) for a in accounts if isinstance(a, dict)]
            self._key = key
            self._salt = salt
            self._legacy = legacy
            # 旧文件在下一次保存时自动升级为 Argon2id
            self._kdf = kdf or kdf_params()

    def _init_empty(self):
        """初始化空仓库并落盘"""
        self._accounts = []
        self._salt = new_salt()
        self._kdf = kdf_params()
        self._legacy = False
        self._key = derive_key(self._recall_password(), self._salt, self._kdf)
        self.save()

    def save(self):
        """将内存中的账户数据整体加密后原子写盘"""
        with self._lock:
            if self._key is None or self._salt is None:
                raise VaultError("密钥未初始化，无法保存")

            plain = json.dumps(self._accounts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            iv = new_iv()
            ciphertext = encrypt_with_key(self._key, plain, iv)

            doc = {
                "version": DATA_VERSION,
                "encrypted": True,
                "kdf": KDF_NAME,
                "kdfParams": dict(self._kdf),
                "salt": b64e(self._salt),
                "iv": b64e(iv),
                "data": b64e(ciphertext),
            }

            self._ensure_parent()
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            self._legacy = False

    # ---------- 规范化 ----------
    @staticmethod
    def _normalize(account: dict) -> dict:
        try:
            acc_id = int(account.get("id"))
        except Exception:
            acc_id = 0
        return {
            "id": acc_id,
            "name": str(account.get("name", "")).strip(),
            "secret": str(account.get("secret", "")).strip().replace(" ", "").upper(),
            "issuer": str(account.get("issuer", "")).strip(),
            "createdAt": account.get("createdAt") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "algorithm": str(account.get("algorithm", "SHA1")).upper(),
            "digits": int(account.get("digits", 6) or 6),
            "period": int(account.get("period", 30) or 30),
        }

    def _next_id(self) -> int:
        used = [a["id"] for a in self._accounts if isinstance(a.get("id"), int)]
        return (max(used) + 1) if used else 1

    # ---------- 业务操作 ----------
    def list_accounts(self):
        with self._lock:
            return [dict(a) for a in self._accounts]

    def get_account(self, account_id: int):
        with self._lock:
            for acc in self._accounts:
                if acc["id"] == int(account_id):
                    return dict(acc)
        return None

    def add_account(self, name: str, secret: str, issuer: str = "",
                    algorithm: str = "SHA1", digits: int = 6, period: int = 30) -> dict:
        with self._lock:
            account = self._normalize({
                "id": self._next_id(),
                "name": name,
                "secret": secret,
                "issuer": issuer,
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "algorithm": algorithm,
                "digits": digits,
                "period": period,
            })
            self._accounts.append(account)
            self.save()
            return dict(account)

    def update_account(self, account_id: int, **fields) -> dict:
        with self._lock:
            for acc in self._accounts:
                if acc["id"] == int(account_id):
                    if "name" in fields and fields["name"] is not None:
                        acc["name"] = str(fields["name"]).strip()
                    if "issuer" in fields and fields["issuer"] is not None:
                        acc["issuer"] = str(fields["issuer"]).strip()
                    if "secret" in fields and fields["secret"]:
                        acc["secret"] = str(fields["secret"]).strip().replace(" ", "").upper()
                    if "algorithm" in fields and fields["algorithm"]:
                        acc["algorithm"] = str(fields["algorithm"]).upper()
                    if "digits" in fields and fields["digits"]:
                        acc["digits"] = int(fields["digits"])
                    if "period" in fields and fields["period"]:
                        acc["period"] = int(fields["period"])
                    self.save()
                    return dict(acc)
        raise VaultError(f"未找到 id={account_id} 的账户")

    def delete_account(self, account_id: int) -> bool:
        with self._lock:
            before = len(self._accounts)
            self._accounts = [a for a in self._accounts if a["id"] != int(account_id)]
            if len(self._accounts) == before:
                return False
            self.save()
            return True

    # ---------- 备份导出 / 导入 ----------
    def export_backup(self) -> str:
        """返回加密数据文件的原始文本，可作为可恢复的备份内容"""
        with self._lock:
            if not os.path.exists(self.path):
                self.save()
            with open(self.path, "r", encoding="utf-8") as fh:
                return fh.read()

    def parse_backup(self, content: str) -> list:
        """用当前用户口令解密备份内容，返回规范化后的账户列表"""
        with self._lock:
            if not self._pw_bytes:
                raise VaultError("用户口令不可用，无法解析备份")

            try:
                doc = json.loads(content)
            except Exception as exc:
                raise VaultError(f"备份内容不是合法的 JSON：{exc}") from exc

            if not isinstance(doc, dict) or "salt" not in doc or "data" not in doc:
                raise VaultError("备份格式不正确，或不是本工具生成的备份文件")

            try:
                salt = b64d(doc["salt"])
                iv = b64d(doc["iv"])
                ciphertext = b64d(doc["data"])
            except CryptoError as exc:
                raise VaultError(str(exc)) from exc

            if self._is_legacy(doc):
                iterations = int(doc.get("iterations", LEGACY_PBKDF2_ITERATIONS))
                key = derive_key_legacy(self._recall_password(), salt, iterations)
            else:
                params = doc.get("kdfParams") if isinstance(doc.get("kdfParams"), dict) else {}
                key = derive_key(self._recall_password(), salt, params)

            try:
                plain = decrypt_with_key(key, ciphertext, iv)
            except CryptoError as exc:
                raise VaultError("备份解密失败：该备份可能由不同的口令创建") from exc

            try:
                accounts = json.loads(plain.decode("utf-8"))
            except Exception as exc:
                raise VaultError(f"备份内容格式错误：{exc}") from exc

            if not isinstance(accounts, list):
                raise VaultError("备份中的账户数据格式不正确")

            return [self._normalize(a) for a in accounts if isinstance(a, dict)]

    def import_accounts(self, accounts, mode: str = "merge") -> dict:
        """把账户并入仓库。

        - mode="merge"   追加导入，密钥已存在的记录会被跳过
        - mode="replace" 先清空现有账户，再全部导入

        返回 {added, skipped, total, mode}
        """
        with self._lock:
            if mode == "replace":
                self._accounts = []

            existing = {a.get("secret") for a in self._accounts if a.get("secret")}
            added = 0
            skipped = 0

            for src in accounts or []:
                if not isinstance(src, dict):
                    skipped += 1
                    continue
                secret = str(src.get("secret") or "").strip().replace(" ", "").upper()
                if not secret or secret in existing:
                    skipped += 1
                    continue
                existing.add(secret)
                self._accounts.append(self._normalize({
                    "id": self._next_id(),
                    "name": src.get("name") or src.get("issuer") or "未命名账户",
                    "secret": secret,
                    "issuer": src.get("issuer", ""),
                    "createdAt": src.get("createdAt"),
                    "algorithm": src.get("algorithm", "SHA1"),
                    "digits": src.get("digits", 6),
                    "period": src.get("period", 30),
                }))
                added += 1

            self.save()
            return {"added": added, "skipped": skipped, "total": len(self._accounts), "mode": mode}

    # ---------- 清理 ----------
    def clear(self):
        """关闭前清理内存中的敏感数据"""
        with self._lock:
            self._accounts = []
            self._key = None
            self._salt = None
            self._discard_password()

    def purge(self):
        """重置程序：删除磁盘上的数据文件并清理内存，回到最初未使用的状态。

        删除失败时抛出 VaultError，避免前端误报「重置成功」。
        """
        with self._lock:
            self._accounts = []
            self._key = None
            self._salt = None
            self._discard_password()
            failed = [p for p in (self.path, self.path + ".tmp") if not _remove_file(p)]
            _touch_reset_marker(os.path.dirname(os.path.abspath(self.path)))
            if failed:
                raise VaultError("数据文件删除失败：" + "、".join(failed))
