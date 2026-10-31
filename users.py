# -*- coding: utf-8 -*-
"""
本地多用户账户模块
- 用户表保存在 <数据根目录>/users.json，仅记录用户名与 Argon2id 口令哈希
- 每个用户拥有独立的加密保险库 <数据根目录>/vaults/<vaultId>.json
- 口令明文永不落盘，只在登录校验与密钥派生时短暂存在于内存
MIT License
Copyright (c) 2026
"""

import json
import os
import re
import time
import uuid

from crypto_utils import (
    CryptoError,
    hash_password,
    password_needs_rehash,
    verify_password,
)

USERS_VERSION = 1
USERS_FILE = "users.json"
VAULT_DIR = "vaults"

# 用户名规则：中英文、数字、下划线、点、短横线，1~32 字符
USERNAME_RULE = re.compile(r"^[\w.\-]{1,32}$", re.UNICODE)
MAX_USERNAME_LEN = 32
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256

_dummy_digest = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _remove_file(path: str, attempts: int = 6, delay: float = 0.2) -> bool:
    """反复尝试删除文件，返回是否已确认删除（应对文件被占用的情况）"""
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


class UserError(Exception):
    """用户管理相关错误"""
    pass


def _absorb_timing(password: str):
    """用户名不存在时也执行一次口令校验，避免通过响应耗时枚举用户名"""
    global _dummy_digest
    try:
        if _dummy_digest is None:
            _dummy_digest = hash_password(uuid.uuid4().hex)
        verify_password(password or "-", _dummy_digest)
    except Exception:
        pass


class UserStore:
    """用户表读写与口令校验"""

    def __init__(self, root_dir: str):
        self.root = os.path.abspath(root_dir)
        self.users_file = os.path.join(self.root, USERS_FILE)
        self.vault_dir = os.path.join(self.root, VAULT_DIR)

    # ---------- 基础读写 ----------
    def _load(self) -> dict:
        try:
            with open(self.users_file, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict) and isinstance(doc.get("users"), list):
                doc.setdefault("version", USERS_VERSION)
                return doc
        except Exception:
            pass
        return {"version": USERS_VERSION, "users": []}

    def _save(self, doc: dict):
        os.makedirs(self.root, exist_ok=True)
        tmp = self.users_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.users_file)

    # ---------- 校验 ----------
    @staticmethod
    def normalize_name(username) -> str:
        return ("" if username is None else str(username)).strip()

    @classmethod
    def validate_username(cls, username) -> str:
        name = cls.normalize_name(username)
        if not name:
            raise UserError("用户名不能为空")
        if len(name) > MAX_USERNAME_LEN:
            raise UserError(f"用户名最长 {MAX_USERNAME_LEN} 个字符")
        if not USERNAME_RULE.match(name) or name in (".", ".."):
            raise UserError("用户名只能包含中英文、数字、下划线、点与短横线")
        return name

    @staticmethod
    def validate_password(password) -> str:
        pwd = "" if password is None else str(password)
        if len(pwd) < MIN_PASSWORD_LEN:
            raise UserError(f"口令至少需要 {MIN_PASSWORD_LEN} 位")
        if len(pwd) > MAX_PASSWORD_LEN:
            raise UserError(f"口令最长 {MAX_PASSWORD_LEN} 位")
        return pwd

    # ---------- 查询 ----------
    def has_users(self) -> bool:
        return bool(self._load()["users"])

    def usernames(self) -> list:
        names = []
        for item in self._load()["users"]:
            if isinstance(item, dict) and isinstance(item.get("username"), str):
                if item["username"]:
                    names.append(item["username"])
        return names

    def get(self, username) -> dict:
        target = self.normalize_name(username)
        for item in self._load()["users"]:
            if isinstance(item, dict) and item.get("username") == target:
                return dict(item)
        return None

    def vault_path(self, username) -> str:
        """该用户的加密保险库路径"""
        record = self.get(username)
        if not record:
            raise UserError(f"用户「{self.normalize_name(username)}」不存在")
        vault_id = record.get("vaultId") or ""
        if not vault_id:
            raise UserError("用户记录缺少保险库标识，数据文件可能已损坏")
        return os.path.join(self.vault_dir, f"{vault_id}.json")

    def all_vault_paths(self) -> list:
        paths = []
        for item in self._load()["users"]:
            if not isinstance(item, dict):
                continue
            vault_id = item.get("vaultId") or ""
            if vault_id:
                paths.append(os.path.join(self.vault_dir, f"{vault_id}.json"))
        return paths

    # ---------- 业务操作 ----------
    def register(self, username, password) -> dict:
        """创建新用户；用户名重复时抛出 UserError"""
        name = self.validate_username(username)
        pwd = self.validate_password(password)

        doc = self._load()
        for item in doc["users"]:
            if isinstance(item, dict) and item.get("username") == name:
                raise UserError(f"用户「{name}」已存在")

        try:
            digest = hash_password(pwd)
        except CryptoError as exc:
            raise UserError(str(exc)) from exc

        record = {
            "username": name,
            "password": digest,
            "vaultId": uuid.uuid4().hex,
            "createdAt": _now(),
            "lastLoginAt": None,
        }
        doc["version"] = USERS_VERSION
        doc["users"].append(record)
        try:
            self._save(doc)
        except Exception as exc:
            raise UserError(f"用户表写入失败：{exc}") from exc
        return dict(record)

    def verify(self, username, password):
        """校验用户名与口令；成功返回用户记录，失败返回 None"""
        name = self.normalize_name(username)
        pwd = "" if password is None else str(password)

        doc = self._load()
        for item in doc["users"]:
            if not isinstance(item, dict) or item.get("username") != name:
                continue
            if not pwd or not verify_password(pwd, item.get("password", "")):
                return None
            # 哈希参数升级时自动重哈希，用户无感
            if password_needs_rehash(item.get("password", "")):
                try:
                    item["password"] = hash_password(pwd)
                except Exception:
                    pass
            item["lastLoginAt"] = _now()
            try:
                self._save(doc)
            except Exception:
                pass
            return dict(item)

        _absorb_timing(pwd)
        return None

    def change_password(self, username, old_password, new_password) -> bool:
        """修改口令：需提供旧口令，成功后同步保存新的 Argon2id 哈希"""
        record = self.verify(username, old_password)
        if not record:
            return False
        pwd = self.validate_password(new_password)

        doc = self._load()
        for item in doc["users"]:
            if isinstance(item, dict) and item.get("username") == record["username"]:
                item["password"] = hash_password(pwd)
                self._save(doc)
                return True
        return False

    def remove(self, username) -> list:
        """删除用户记录及其保险库文件，返回已删除的保险库文件路径"""
        target = self.normalize_name(username)
        doc = self._load()
        kept = []
        removed = []
        for item in doc["users"]:
            if isinstance(item, dict) and item.get("username") == target:
                vault_id = item.get("vaultId") or ""
                if vault_id:
                    path = os.path.join(self.vault_dir, f"{vault_id}.json")
                    _remove_file(path)
                    _remove_file(path + ".tmp")
                    removed.append(path)
                continue
            kept.append(item)
        if len(kept) == len(doc["users"]):
            raise UserError(f"用户「{target}」不存在")
        doc["users"] = kept
        self._save(doc)
        return removed
