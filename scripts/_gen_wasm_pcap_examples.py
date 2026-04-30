#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# scripts/_gen_wasm_pcap_examples.py — One-shot generator for the WASM and
# PCAP example fixtures committed under `examples/`.
#
# Run once at fixture-creation time; the binary outputs are committed and
# this script is retained only so future regens are reproducible.
#
#     python scripts/_gen_wasm_pcap_examples.py
#
# Outputs:
#   examples/web/example.wasm                    — minimal WASM module that
#                                                  fires Info_Contains_WebAssembly
#                                                  + WASM_Network_Bridge_Imports
#                                                  + WASM_Eval_Bridge_Imports.
#   examples/forensics/example-capture.pcap      — libpcap capture with
#                                                  DNS lookup + HTTP GET +
#                                                  TLS ClientHello (SNI).
# ════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import struct
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# ─── WASM ───────────────────────────────────────────────────────────────────

def leb128_u(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def name(s: str) -> bytes:
    b = s.encode('utf-8')
    return leb128_u(len(b)) + b


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + leb128_u(len(payload)) + payload


def build_wasm() -> bytes:
    # Header: \0asm + version=1
    header = b'\x00asm\x01\x00\x00\x00'

    # Type section (id=1): one func sig () -> ()
    # vec(types). 1 type: form 0x60, params=[], results=[]
    type_section = leb128_u(1) + b'\x60' + leb128_u(0) + leb128_u(0)

    # Import section (id=2): 4 imports across modules; intentionally hits
    # WASM_Network_Bridge_Imports ($f1 "__wbg_fetch") and
    # WASM_Eval_Bridge_Imports ($e1 "__wbindgen_function_table" / use $e3
    # "emscripten_run_script" instead — easier ASCII match).
    imports = []
    # ("env", "__wbg_fetch", func type 0)
    imports.append(name('env') + name('__wbg_fetch') + b'\x00' + leb128_u(0))
    # ("env", "emscripten_run_script", func type 0) — eval bridge
    imports.append(name('env') + name('emscripten_run_script') + b'\x00' + leb128_u(0))
    # ("wasi_snapshot_preview1", "proc_exec", func type 0) — WASI surface
    # (synthetic; real wasi only exposes proc_exit/proc_raise — using
    #  proc_exec keeps the fixture concise while tripping the
    #  WASM_WASI_Process_Spawn rule which targets out-of-sandbox spawns.)
    imports.append(name('wasi_snapshot_preview1') + name('proc_exec') + b'\x00' + leb128_u(0))
    # ("env", "memory", memory: limits flag=0 min=1)
    imports.append(name('env') + name('memory') + b'\x02' + b'\x00' + leb128_u(1))
    import_section = leb128_u(len(imports)) + b''.join(imports)

    # Custom section "name" with module name — gives the renderer
    # something to print without changing rule outcomes.
    name_payload = name('example')
    custom_section = name('name') + name_payload  # ill-formed sub-sections;
    # The renderer's _parseCustom reads only the leading name + raw body,
    # so a custom section whose body is itself a name-like string is fine.
    return header + section(1, type_section) + section(2, import_section) + section(0, custom_section)


# ─── PCAP ───────────────────────────────────────────────────────────────────
# libpcap LE, link-layer 1 (ETHERNET), no FCS, ns precision off (use sec/usec).

def pcap_global_header() -> bytes:
    # magic 0xa1b2c3d4 LE, version 2.4, thiszone 0, sigfigs 0,
    # snaplen 65535, network 1 (ETHERNET).
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def pcap_record(payload: bytes, ts_sec: int, ts_usec: int) -> bytes:
    return struct.pack('<IIII', ts_sec, ts_usec, len(payload), len(payload)) + payload


def eth_ipv4_udp(src_mac: bytes, dst_mac: bytes,
                 src_ip: bytes, dst_ip: bytes,
                 src_port: int, dst_port: int,
                 udp_payload: bytes) -> bytes:
    eth = dst_mac + src_mac + b'\x08\x00'  # ethertype IPv4
    udp_len = 8 + len(udp_payload)
    udp = struct.pack('>HHHH', src_port, dst_port, udp_len, 0) + udp_payload
    total_ip = 20 + udp_len
    ip = struct.pack(
        '>BBHHHBBH4s4s',
        0x45,           # ver/IHL
        0x00,           # DSCP/ECN
        total_ip,       # total length
        0x1234,         # id
        0x0000,         # flags + frag
        64,             # TTL
        17,             # proto UDP
        0,              # checksum (left zero — most parsers don't validate)
        src_ip, dst_ip,
    )
    return eth + ip + udp


def eth_ipv4_tcp(src_mac: bytes, dst_mac: bytes,
                 src_ip: bytes, dst_ip: bytes,
                 src_port: int, dst_port: int,
                 seq: int,
                 tcp_payload: bytes) -> bytes:
    eth = dst_mac + src_mac + b'\x08\x00'
    tcp_hdr_len_words = 5
    flags = 0x18  # PSH + ACK
    window = 0xFAF0
    tcp = struct.pack(
        '>HHIIBBHHH',
        src_port, dst_port,
        seq, 0xDEADBEEF,
        tcp_hdr_len_words << 4,
        flags,
        window,
        0,  # checksum (left zero)
        0,  # urgent
    ) + tcp_payload
    total_ip = 20 + len(tcp)
    ip = struct.pack(
        '>BBHHHBBH4s4s',
        0x45, 0x00, total_ip, 0x4321, 0x0000, 64, 6, 0,
        src_ip, dst_ip,
    )
    return eth + ip + tcp


def dns_query(qname: str) -> bytes:
    # Header: id, flags=0x0100 (standard query, RD), qdcount=1, others=0.
    hdr = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    labels = b''
    for label in qname.split('.'):
        b = label.encode('ascii')
        labels += bytes([len(b)]) + b
    labels += b'\x00'
    qtail = struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    return hdr + labels + qtail


def http_get(host: str, path: str) -> bytes:
    return (
        f'GET {path} HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n'
        'Accept: */*\r\n'
        '\r\n'
    ).encode('ascii')


def tls_client_hello(sni: str) -> bytes:
    # TLS record: type=0x16 (handshake), version=0x0301, length=...
    # Handshake header: type=0x01 (ClientHello), length(3), version=0x0303,
    # random(32), session_id_length=0, cipher_suites(len2 + bytes),
    # compression(len1 + bytes), extensions(len2 + bytes:
    #     SNI extension type=0x0000 length=... payload).
    # We hand-roll a minimal but well-formed ClientHello with one SNI ext.
    sni_bytes = sni.encode('ascii')
    sni_entry = b'\x00' + struct.pack('>H', len(sni_bytes)) + sni_bytes  # name_type=0 + name
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry             # server_name_list
    sni_ext_data = sni_list
    sni_ext = struct.pack('>HH', 0x0000, len(sni_ext_data)) + sni_ext_data

    extensions = sni_ext
    ext_block = struct.pack('>H', len(extensions)) + extensions

    cipher_suites = struct.pack('>HH', 2, 0x002F)  # length=2, one cipher
    compression = b'\x01\x00'                       # length=1, null
    random = b'\x00' * 32
    body = (
        b'\x03\x03'                                  # legacy_version TLS 1.2
        + random
        + b'\x00'                                    # session_id length 0
        + cipher_suites
        + compression
        + ext_block
    )
    handshake = b'\x01' + struct.pack('>I', len(body))[1:] + body  # 24-bit length
    record = b'\x16' + b'\x03\x01' + struct.pack('>H', len(handshake)) + handshake
    return record


def build_pcap() -> bytes:
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\x66\x77\x88\x99\xAA\xBB'
    client_ip = bytes([10, 0, 0, 42])
    dns_server = bytes([8, 8, 8, 8])
    http_server = bytes([93, 184, 216, 34])  # public IP — exact value cosmetic

    # Packet 1: DNS A query for an evocative-but-public hostname.
    pkt1 = eth_ipv4_udp(src_mac, dst_mac, client_ip, dns_server,
                        54321, 53, dns_query('command-and-control.example.test'))
    # Packet 2: HTTP GET (plaintext) — surfaces HTTP Host extraction.
    # Avoid byte sequences that collide with cross-format magic-byte
    # detector rules (e.g. 0xCAFEBABE / Mach-O fat magic).
    pkt2 = eth_ipv4_tcp(src_mac, dst_mac, client_ip, http_server,
                        49000, 80, 0x10000001,
                        http_get('panel.example.test', '/admin/login.php'))
    # Packet 3: TLS ClientHello to a different host — exercises SNI parser.
    pkt3 = eth_ipv4_tcp(src_mac, dst_mac, client_ip, http_server,
                        49001, 443, 0x10000002,
                        tls_client_hello('cdn.example.test'))

    out = pcap_global_header()
    out += pcap_record(pkt1, 1700000000, 100000)
    out += pcap_record(pkt2, 1700000001, 200000)
    out += pcap_record(pkt3, 1700000002, 300000)
    return out


def main():
    wasm_path = REPO / 'examples' / 'web' / 'example.wasm'
    pcap_path = REPO / 'examples' / 'forensics' / 'example-capture.pcap'

    wasm_bytes = build_wasm()
    pcap_bytes = build_pcap()

    wasm_path.write_bytes(wasm_bytes)
    pcap_path.write_bytes(pcap_bytes)

    print(f'wrote {wasm_path}  ({len(wasm_bytes)} bytes)')
    print(f'wrote {pcap_path}  ({len(pcap_bytes)} bytes)')


if __name__ == '__main__':
    main()
