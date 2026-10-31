@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ===================================================
echo    2FA 备用密钥提取工具 - 全自动构建脚本
echo ===================================================
echo.

:: 1. 检测 Python 环境
echo [1/4] 检测 Python 环境...
set "PYTHON_CMD="

:: 尝试查找可用的 Python 命令（优先 py -3，其次 python，最后 python3）
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 --version >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_CMD=py -3"
        goto :python_found
    )
)

where python >nul 2>nul
if %errorlevel% equ 0 (
    python --version >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_CMD=python"
        goto :python_found
    )
)

where python3 >nul 2>nul
if %errorlevel% equ 0 (
    python3 --version >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_CMD=python3"
        goto :python_found
    )
)

:: 未找到 Python
echo [错误] 未检测到 Python 环境！
echo 请从 https://www.python.org/downloads/ 下载安装 Python 3.6 或更高版本。
echo 安装时请务必勾选 "Add Python to PATH"。
pause
exit /b 1

:python_found
echo [成功] 使用 Python 命令: %PYTHON_CMD%
%PYTHON_CMD% --version
echo.

:: 2. 安装 requirements.txt 依赖
echo [2/4] 安装项目依赖...
if exist "requirements.txt" (
    %PYTHON_CMD% -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [错误] 依赖安装失败，请检查网络或 pip 配置。
        pause
        exit /b %errorlevel%
    )
) else (
    echo [提示] 未找到 requirements.txt，跳过依赖安装。
)
echo.

:: 3. 安装 PyInstaller
echo [3/4] 安装 PyInstaller 打包工具...
%PYTHON_CMD% -m pip install pyinstaller
if %errorlevel% neq 0 (
    echo [错误] PyInstaller 安装失败。
    pause
    exit /b %errorlevel%
)
echo.

:: 4. 清理旧构建产物
echo [4/4] 开始打包...
if exist "build" (
    echo 清理 build 目录...
    rmdir /s /q build
)
if exist "dist" (
    echo 清理 dist 目录...
    rmdir /s /q dist
)
if exist "main.spec" (
    echo 删除旧的 spec 文件...
    del main.spec
)

:: 执行 PyInstaller 打包（带 --add-data，打包整个 web 目录）
echo 正在执行 PyInstaller 打包，请稍候...
%PYTHON_CMD% -m PyInstaller --onefile --windowed --name "2FA-Tool" --add-data "web;web" --hidden-import cryptography --hidden-import argon2 --hidden-import cv2 main.py

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo  ✅ 构建成功！
    echo  可执行文件位于: dist\2FA-Tool.exe
    echo ===================================================
) else (
    echo.
    echo [错误] 打包失败，请检查上面的错误信息。
)

pause
exit /b %errorlevel%