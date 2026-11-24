@echo off
rem PyShark Pro 一键启动（自动请求管理员权限）
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 python，请先安装 Python 3.8+ 并加入 PATH。
    pause
    exit /b 1
)

python main.py
if %errorlevel% neq 0 pause
