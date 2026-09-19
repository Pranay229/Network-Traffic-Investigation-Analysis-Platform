@echo off
cd /d "%~dp0frontend"
node node_modules\vite\bin\vite.js build
