@echo off
REM =====================================================
REM  COBRA Launcher
REM  Purpose: Run COBRA.ps1 with execution policy bypass
REM =====================================================

set SCRIPT_DIR=%~dp0
set SCRIPT=%SCRIPT_DIR%COBRA.ps1

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
pause

