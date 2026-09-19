# PowerShell Production Startup Script
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " Starting NTIA Platform Production Server..." -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Cyan

python "$ScriptDir\run_production.py"
