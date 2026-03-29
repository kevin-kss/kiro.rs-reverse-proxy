@echo off
REM 设置代理环境变量
set HTTP_PROXY=http://127.0.0.1:8888
set HTTPS_PROXY=http://127.0.0.1:8888
set NODE_TLS_REJECT_UNAUTHORIZED=0

REM 启动 Kiro IDE
start "" "C:\Users\Administrator\AppData\Local\Programs\Kiro\Kiro.exe"
