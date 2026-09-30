@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Iniciando a Loja Amy Sam Doceria...
echo.
python server.py
if %errorlevel% neq 0 (
  echo.
  echo Nao foi possivel iniciar com "python". Tentando com "py"...
  py server.py
)
echo.
pause
