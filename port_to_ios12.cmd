@echo off
setlocal
python "%~dp0src\port_to_ios12.py" %*
exit /b %errorlevel%
