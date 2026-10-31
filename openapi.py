# -*- coding: utf-8 -*-
"""
OpenAPI 3.1 规范生成（前后端分离）

- GET /api/openapi.json 返回本模块生成的机器可读文档
- GET /api/docs       返回可读的 HTML 文档页
- docs/API.md 中的接口说明与本规范保持同步
MIT License
Copyright (c) 2026
"""

API_VERSION = "1.0.0"
API_TITLE = "156-2FA API"
API_DESCRIPTION = (
    "156-2FA 动态验证码服务的 RESTful 接口。\n\n"
    "**鉴权方式（任选其一）**\n\n"
    "1. `Authorization: Bearer <accessToken>` —— 供远程 / 第三方客户端调用，不受来源限制；\n"
    "2. `Cookie: 2fa_frontend=<frontendToken>` 或 URL 参数 `?token=<frontendToken>` —— "
    "桌面端内置 WebView 使用，受 Host / Origin 白名单保护。\n\n"
    "前端只接收已计算好的验证码，密钥与口令永不通过本接口返回。"
)

ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean", "example": False},
        "error": {"type": "string", "example": "请求体不是合法的 JSON"},
    },
    "required": ["ok", "error"],
}

ACCOUNT_SCHEMA = {
    "type": "object",
    "description": "账户信息（不含 secret，接口永不返回密钥明文）",
    "properties": {
        "id": {"type": "integer", "example": 1},
        "name": {"type": "string", "example": "GitHub"},
        "issuer": {"type": "string", "example": "GitHub"},
        "createdAt": {"type": "string", "example": "2026-09-11T21:00:00Z"},
        "algorithm": {"type": "string", "enum": ["SHA1", "SHA256", "SHA512"], "example": "SHA1"},
        "digits": {"type": "integer", "example": 6},
        "period": {"type": "integer", "example": 30},
        "code": {"type": "string", "example": "123 456"},
        "remaining": {"type": "integer", "description": "当前验证码剩余有效秒数", "example": 27},
        "counter": {"type": "integer", "description": "当前时间片序号", "example": 59384291},
    },
    "required": ["id", "name", "code", "remaining"],
}

ACCOUNT_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "example": "GitHub"},
        "secret": {"type": "string", "description": "Base32 密钥，添加时必填", "example": "JBSWY3DPEHPK3PXP"},
        "issuer": {"type": "string", "example": "GitHub"},
        "algorithm": {"type": "string", "enum": ["SHA1", "SHA256", "SHA512"]},
        "digits": {"type": "integer", "minimum": 6, "maximum": 10},
        "period": {"type": "integer", "minimum": 5, "maximum": 300},
    },
    "required": ["name", "secret"],
}

PARAM_ID = {
    "name": "id",
    "in": "path",
    "required": True,
    "description": "账户数字 id",
    "schema": {"type": "integer"},
}


def _json_body(schema: dict, required: bool = True):
    return {
        "required": required,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/" + schema}}},
    }


PATHS = {
    "/api/health": {
        "get": {
            "summary": "健康检查",
            "description": "免鉴权探活接口，返回服务版本与鉴权要求，用于「测试连接」。",
            "operationId": "health",
            "tags": ["系统"],
            "security": [],
            "responses": {
                "200": {
                    "description": "服务在线",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Health"}}},
                }
            },
        }
    },
    "/api/info": {
        "get": {
            "summary": "服务信息",
            "description": "返回监听地址、端口、当前用户与可用访问地址。",
            "operationId": "info",
            "tags": ["系统"],
            "responses": {
                "200": {
                    "description": "成功",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Info"}}},
                },
                "403": {"description": "来源不被允许或令牌无效", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        }
    },
    "/api/openapi.json": {
        "get": {
            "summary": "OpenAPI 规范",
            "description": "返回本接口的 OpenAPI 3.1 描述文档（JSON）。",
            "operationId": "openapi",
            "tags": ["文档"],
            "security": [],
            "responses": {"200": {"description": "OpenAPI 文档"}},
        }
    },
    "/api/docs": {
        "get": {
            "summary": "接口文档页面",
            "description": "浏览器可直接打开的 HTML 文档页。",
            "operationId": "apiDocs",
            "tags": ["文档"],
            "security": [],
            "responses": {"200": {"description": "HTML 文档页", "content": {"text/html": {"schema": {"type": "string"}}}}},
        }
    },
    "/api/accounts": {
        "get": {
            "summary": "列出账户与验证码",
            "description": "返回全部账户及其当前验证码、剩余秒数；结果按 issuer / name 排序。",
            "operationId": "listAccounts",
            "tags": ["账户"],
            "responses": {
                "200": {
                    "description": "成功",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccountList"}}},
                }
            },
        },
        "post": {
            "summary": "新增账户",
            "description": "手动添加账户；secret 为 Base32 密钥。",
            "operationId": "addAccount",
            "tags": ["账户"],
            "requestBody": _json_body("AccountInput"),
            "responses": {
                "200": {
                    "description": "创建成功",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccountResult"}}},
                },
                "400": {"description": "参数不合法", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        },
    },
    "/api/accounts/{id}": {
        "put": {
            "summary": "修改账户",
            "description": "按 id 修改账户；字段留空表示不修改，secret 留空表示不更换密钥。",
            "operationId": "updateAccount",
            "tags": ["账户"],
            "parameters": [PARAM_ID],
            "requestBody": _json_body("AccountUpdate"),
            "responses": {
                "200": {
                    "description": "修改成功",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccountResult"}}},
                },
                "404": {"description": "账户不存在", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        },
        "delete": {
            "summary": "删除账户",
            "operationId": "deleteAccount",
            "tags": ["账户"],
            "parameters": [PARAM_ID],
            "responses": {
                "200": {"description": "删除成功", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OkResult"}}}},
                "404": {"description": "账户不存在", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        },
    },
    "/api/import": {
        "post": {
            "summary": "导入 otpauth 链接 / 二维码",
            "description": "传入 otpauth:// 链接，或图片的 data URL（服务端解码二维码后解析）。",
            "operationId": "importUri",
            "tags": ["账户"],
            "requestBody": _json_body("ImportInput"),
            "responses": {
                "200": {"description": "导入成功", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AccountResult"}}}},
                "400": {"description": "链接不合法或二维码无法识别", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        }
    },
    "/api/export": {
        "get": {
            "summary": "导出数据",
            "description": "format=backup 导出由当前用户口令保护的加密备份 JSON；format=otpauth 导出明文 otpauth 链接文本。",
            "operationId": "exportData",
            "tags": ["数据"],
            "parameters": [
                {
                    "name": "format",
                    "in": "query",
                    "required": False,
                    "description": "导出格式：backup（默认）或 otpauth",
                    "schema": {"type": "string", "enum": ["backup", "otpauth"], "default": "backup"},
                }
            ],
            "responses": {
                "200": {"description": "导出内容（纯文本）", "content": {"text/plain": {"schema": {"type": "string"}}}},
                "400": {"description": "导出失败", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        }
    },
    "/api/restore": {
        "post": {
            "summary": "导入备份或 otpauth 文本",
            "description": "自动识别加密备份 JSON 与明文 otpauth 文本；merge 为合并追加（按密钥去重），replace 为覆盖全部。",
            "operationId": "restore",
            "tags": ["数据"],
            "requestBody": _json_body("RestoreInput"),
            "responses": {
                "200": {"description": "导入结果", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RestoreResult"}}}},
                "400": {"description": "内容为空或无法识别", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        }
    },
    "/api/reset": {
        "post": {
            "summary": "重置程序",
            "description": "清空全部账户数据（保留用户口令），随后服务端按宿主回调退出或继续运行。",
            "operationId": "reset",
            "tags": ["系统"],
            "responses": {
                "200": {"description": "已清空", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OkResult"}}}},
                "500": {"description": "重置失败", "content": {"application/json": {"schema": ERROR_SCHEMA}}},
            },
        }
    },
    "/api/bye": {
        "post": {
            "summary": "关闭信号",
            "description": "页面关闭时通知服务端；服务端将在宽限期后退出（仅空闲超时模式下生效）。",
            "operationId": "bye",
            "tags": ["系统"],
            "responses": {"200": {"description": "已收到", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OkResult"}}}}},
        }
    },
}


def build_openapi(server_address: str = "127.0.0.1:0", secure: bool = False,
                  extra_servers: list = None) -> dict:
    """生成 OpenAPI 文档字典"""
    scheme = "https" if secure else "http"
    servers = [{"url": f"{scheme}://{server_address}", "description": "当前服务实例"}]
    for item in extra_servers or []:
        if item not in servers[0]["url"]:
            servers.append({"url": item, "description": "可访问地址"})

    return {
        "openapi": "3.1.0",
        "info": {
            "title": API_TITLE,
            "version": API_VERSION,
            "description": API_DESCRIPTION,
            "license": {"name": "MIT", "identifier": "MIT"},
        },
        "servers": servers,
        "tags": [
            {"name": "系统", "description": "服务信息与生命周期"},
            {"name": "账户", "description": "TOTP 账户的增删改查与导入"},
            {"name": "数据", "description": "导出、导入与还原"},
            {"name": "文档", "description": "接口自述文档"},
        ],
        "paths": PATHS,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "远程 / 第三方客户端使用的访问令牌（服务端配置的 accessToken）",
                },
                "frontendToken": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "2fa_frontend",
                    "description": "桌面端 WebView 会话令牌，也可用 ?token= 查询参数传递",
                },
            },
            "schemas": {
                "Account": ACCOUNT_SCHEMA,
                "AccountInput": ACCOUNT_INPUT_SCHEMA,
                "AccountUpdate": {
                    "type": "object",
                    "description": "全部字段可选，留空表示不修改",
                    "properties": {
                        "name": {"type": "string"},
                        "secret": {"type": "string", "description": "留空表示不更换密钥"},
                        "issuer": {"type": "string"},
                        "algorithm": {"type": "string", "enum": ["SHA1", "SHA256", "SHA512"]},
                        "digits": {"type": "integer", "minimum": 6, "maximum": 10},
                        "period": {"type": "integer", "minimum": 5, "maximum": 300},
                    },
                },
                "AccountList": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "address": {"type": "string", "example": "127.0.0.1:41234"},
                        "host": {"type": "string", "example": "127.0.0.1"},
                        "port": {"type": "integer", "example": 41234},
                        "username": {"type": "string", "example": "alice"},
                        "serverTime": {"type": "number", "description": "服务端 Unix 时间戳（秒），用于校准本地时钟"},
                        "accounts": {"type": "array", "items": {"$ref": "#/components/schemas/Account"}},
                    },
                    "required": ["ok", "accounts"],
                },
                "AccountResult": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "account": {"$ref": "#/components/schemas/Account"},
                    },
                },
                "OkResult": {"type": "object", "properties": {"ok": {"type": "boolean", "example": True}}},
                "Health": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "service": {"type": "string", "example": "156-2FA"},
                        "version": {"type": "string", "example": API_VERSION},
                        "mode": {"type": "string", "example": "local"},
                        "authRequired": {"type": "boolean", "example": True},
                        "username": {"type": "string", "example": "alice"},
                        "serverTime": {"type": "number"},
                    },
                },
                "Info": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "username": {"type": "string"},
                        "address": {"type": "string"},
                        "urls": {"type": "array", "items": {"type": "string"}},
                        "version": {"type": "string"},
                        "documentation": {"type": "string", "example": "/api/docs"},
                    },
                },
                "ImportInput": {
                    "type": "object",
                    "properties": {
                        "uri": {"type": "string", "description": "otpauth:// 链接", "example": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"},
                        "image": {"type": "string", "description": "二维码图片的 data URL（与 uri 二选一）"},
                    },
                },
                "RestoreInput": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "加密备份 JSON 全文或 otpauth 文本"},
                        "mode": {"type": "string", "enum": ["merge", "replace"], "default": "merge"},
                    },
                    "required": ["content"],
                },
                "RestoreResult": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "result": {
                            "type": "object",
                            "properties": {
                                "added": {"type": "integer"},
                                "skipped": {"type": "integer"},
                                "invalid": {"type": "integer"},
                                "source": {"type": "string", "enum": ["backup", "text"]},
                            },
                        },
                    },
                },
            },
        },
        "security": [{"bearerAuth": []}, {"frontendToken": []}],
    }
