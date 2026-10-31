#!/bin/bash
# ===================================================
# 2FA 备用密钥提取工具 - 全自动构建脚本 (Linux/macOS)
# ===================================================

set -e  # 遇到错误立即退出

echo "==================================================="
echo "  2FA 备用密钥提取工具 - 全自动构建脚本"
echo "==================================================="
echo

# ---------- 1. 检测 Python 环境 ----------
echo "[1/4] 检测 Python 环境..."
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "[错误] 未检测到 Python 环境！"
    echo "请从 https://www.python.org/downloads/ 下载安装 Python 3.6 或更高版本。"
    exit 1
fi

echo "[成功] 使用 Python 命令: $PYTHON_CMD"
$PYTHON_CMD --version
echo

# ---------- 2. 安装 requirements.txt 依赖 ----------
echo "[2/4] 安装项目依赖..."
if [ -f "requirements.txt" ]; then
    $PYTHON_CMD -m pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[错误] 依赖安装失败，请检查网络或 pip 配置。"
        exit 1
    fi
else
    echo "[提示] 未找到 requirements.txt，跳过依赖安装。"
fi
echo

# ---------- 3. 安装 PyInstaller ----------
echo "[3/4] 安装 PyInstaller 打包工具..."
$PYTHON_CMD -m pip install pyinstaller
if [ $? -ne 0 ]; then
    echo "[错误] PyInstaller 安装失败。"
    exit 1
fi
echo

# ---------- 4. 清理旧构建产物 ----------
echo "[4/4] 开始打包..."
if [ -d "build" ]; then
    echo "清理 build 目录..."
    rm -rf build
fi
if [ -d "dist" ]; then
    echo "清理 dist 目录..."
    rm -rf dist
fi
if [ -f "main.spec" ]; then
    echo "删除旧的 spec 文件..."
    rm main.spec
fi

# ---------- 5. 执行 PyInstaller 打包 ----------
# Linux/macOS 路径分隔符为冒号 (:)
echo "正在执行 PyInstaller 打包，请稍候..."
$PYTHON_CMD -m PyInstaller \
    --onefile \
    --windowed \
    --name "2FA-Tool" \
    --add-data "web:web" \
    --hidden-import cryptography \
    --hidden-import argon2 \
    --hidden-import cv2 \
    main.py

if [ $? -eq 0 ]; then
    echo
    echo "==================================================="
    echo "  ? 构建成功！"
    echo "  可执行文件位于: dist/2FA-Tool"
    echo "==================================================="
else
    echo
    echo "[错误] 打包失败，请检查上面的错误信息。"
    exit 1
fi