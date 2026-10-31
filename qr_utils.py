# -*- coding: utf-8 -*-
"""
二维码解码与 otpauth URI 解析模块
- 复用 OpenCV QRCodeDetector 解码图片中的二维码
- 解析 otpauth:// URI，提取 name / issuer / secret / 算法等参数
MIT License
Copyright (c) 2026
"""

import base64
import io
import re
import urllib.parse


def _data_url_to_bytes(data_url: str) -> bytes:
    """将 data:image/...;base64,xxx 或纯 base64 转为 bytes"""
    if not data_url:
        raise ValueError("图片数据为空")
    if "," in data_url and data_url.strip().lower().startswith("data:"):
        _, encoded = data_url.split(",", 1)
    else:
        encoded = data_url
    return base64.b64decode(encoded)


def decode_qr_from_data_url(data_url: str):
    """解码图片中的二维码，返回文本；失败返回 None"""
    try:
        import cv2
        import numpy as np
        from PIL import Image
    except Exception:
        raise RuntimeError("缺少二维码解码依赖，请先安装 opencv-python / Pillow / numpy")

    try:
        raw = _data_url_to_bytes(data_url)
        image = Image.open(io.BytesIO(raw))
        rgb = np.array(image.convert("RGB"))
        bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        data, _points, _straight = detector.detectAndDecode(bgr)
        if data:
            return data

        # 灰度再试一次，提升识别率
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        data, _points, _straight = detector.detectAndDecode(gray)
        return data or None
    except Exception as exc:
        print(f"[QR] 解码错误: {exc}")
        return None


def parse_otpauth(uri: str):
    """
    解析 otpauth:// URI，返回账户字典：
    {name, issuer, secret, algorithm, digits, period}
    解析失败抛出 ValueError
    """
    if not uri:
        raise ValueError("URI 为空")

    raw = uri.strip()
    if not raw.lower().startswith("otpauth://"):
        raise ValueError("不是有效的 otpauth URI")

    parsed = urllib.parse.urlparse(raw)
    if parsed.netloc.lower() not in ("totp", "hotp"):
        raise ValueError("仅支持 totp / hotp 类型的 otpauth URI")

    params = urllib.parse.parse_qs(parsed.query)

    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    issuer = (params.get("issuer", [""])[0] or "").strip()
    name = label
    if label and ":" in label:
        left, right = label.split(":", 1)
        if not issuer:
            issuer = left.strip()
        name = right.strip()
    name = name.strip() or issuer or "未命名账户"

    secret = (params.get("secret", [""])[0] or "").strip().replace(" ", "").upper()
    if not secret:
        raise ValueError("URI 中缺少 secret 参数")

    algorithm = (params.get("algorithm", ["SHA1"])[0] or "SHA1").upper()
    if algorithm not in ("SHA1", "SHA256", "SHA512"):
        algorithm = "SHA1"

    try:
        digits = int(params.get("digits", ["6"])[0])
    except Exception:
        digits = 6
    if digits not in (6, 7, 8):
        digits = 6

    try:
        period = int(params.get("period", ["30"])[0])
    except Exception:
        period = 30
    if period <= 0:
        period = 30

    return {
        "name": name,
        "issuer": issuer,
        "secret": secret,
        "algorithm": algorithm,
        "digits": digits,
        "period": period,
    }


def build_otpauth(account: dict) -> str:
    """
    由账户字典生成标准 otpauth:// URI，便于导出到其他 2FA 应用：
    otpauth://totp/Issuer:Name?secret=XXX&issuer=Issuer&algorithm=SHA1&digits=6&period=30
    """
    secret = (account.get("secret") or "").strip().replace(" ", "").upper()
    issuer = (account.get("issuer") or "").strip()
    name = (account.get("name") or "").strip() or issuer or "未命名账户"

    # 与主流 2FA 应用保持一致：保留分隔用的冒号，仅对 issuer / name 本身编码
    if issuer:
        label = urllib.parse.quote(issuer, safe="") + ":" + urllib.parse.quote(name, safe="")
    else:
        label = urllib.parse.quote(name, safe="")

    params = {"secret": secret}
    if issuer:
        params["issuer"] = issuer
    params.update({
        "algorithm": (account.get("algorithm") or "SHA1").upper(),
        "digits": str(int(account.get("digits") or 6)),
        "period": str(int(account.get("period") or 30)),
    })

    return "otpauth://totp/" + label + "?" + urllib.parse.urlencode(params)


def parse_otpauth_text(text: str) -> list:
    """
    从多行文本中批量解析 otpauth 链接（每行一个，跳过空行与注释行）。
    返回 (账户列表, 无法解析的行数)
    """
    accounts = []
    invalid = 0
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith("otpauth://"):
            invalid += 1
            continue
        try:
            accounts.append(parse_otpauth(line))
        except ValueError:
            invalid += 1
    return accounts, invalid


def looks_like_secret(text: str) -> bool:
    """判断文本是否像一个 base32 密钥"""
    if not text:
        return False
    clean = re.sub(r"\s", "", text).upper().rstrip("=")
    return bool(re.fullmatch(r"[A-Z2-7]{12,}", clean))
