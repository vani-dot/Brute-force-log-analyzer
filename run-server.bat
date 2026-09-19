@echo off
REM Deployment wrapper for Brute Force Log Analyzer.
REM Starts the Flask server with the project's own production setting
REM (BFLA_DEBUG=false, taken from its Dockerfile/docker-compose.yml).
REM No application source code is modified by this file.

cd /d "%~dp0"
set BFLA_DEBUG=false
set PORT=5000
.\.venv\Scripts\pythonw.exe app.py >> server.log 2>&1
