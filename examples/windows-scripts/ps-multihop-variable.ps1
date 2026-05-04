# === Loupe Test File: PowerShell Multi-Hop Variable Obfuscation ===
# HARMLESS test file — no actual malicious actions are performed.
# Exercises the 3-pass fixed-point evaluator added in Phase A and
# the paren-less invocation form added in Phase B.

# ── 1. Multi-hop variable chain → &($var) ─────────────────────────────
# Two-hop chain: $a + $b → $c; &($c) dispatches 'Invoke-Expression'.
$a = 'Invoke'
$b = '-Expression'
$c = $a + $b
& ($c) 'Write-Host hello'

# ── 2. Three-hop chain with paren-less call ──────────────────────────
$p1 = 'Inv'
$p2 = 'oke'
$p3 = '-Expression'
$cmd = $p1 + $p2 + $p3
iex $cmd

# ── 3. Alias via Set-Alias + call-operator ────────────────────────────
Set-Alias -Name myIEX -Value 'Invoke-Expression'
& myIEX 'Write-Host alias-resolved'

# ── 4. $env:var-backed stager invocation ──────────────────────────────
$env:payload = 'Invoke-Expression'
& ($env:payload) 'Write-Host env-resolved'

# ── 5. Quote-pair token splitting ─────────────────────────────────────
$split = 'i' + '' + 'e' + '' + 'x'
& ($split) 'Write-Host quote-pair'

# ── 6. ${braced} variable form inside interp ──────────────────────────
$name = 'Expression'
$joined = "Invoke-${name}"
& ($joined) 'Write-Host braced'

Write-Host "[DONE] Multi-hop variable obfuscation test renders."
