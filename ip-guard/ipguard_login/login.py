"""5 步重放登录 + 0x1005 凭据 body 重打包。

核心思路：把抓包里的 5 个 C→S 包按字节回放，只在 0x1005 sub=6 那一包里
把 Pwd2 字段换成 hash_pwd(user, pass) 的结果。
"""
import os
import socket
import struct
import zlib
from typing import Optional, Tuple
import pdb

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .crypto import (
    HDR_MAGIC, FLAG_CRYPT, FLAG_COMP,
    deobf_header, obf_header,
    encrypt_payload, hash_pwd,
)
from .packet import (
    parse_packet, recv_full_packet, dump_packet, rewrite_nonce,
)


# 抓包观测到的机器指纹 (8B)，写到 hdr[24:32] 重复 2 次
SESSION_FP_DEFAULT = bytes.fromhex("cd7598012e965cb5")


# ============== 5 步登录的回放包 ==============
CAPTURED_FLOW = [
    # (label, hex bytes, mutate_creds?)
    ("0x1001 sub=0 (能力/握手)",
     "4f4d000601100000000000001b5b750001000000000000000000ffff00000000",
     False),
    ("0x4661 sub=1 (握手 step2)",
     "4f4d00c6614601006b19f4835477883fcd7598012e965cb5cd7598012e965cb5",
     False),
    ("0x4401 sub=3 (profile 拉取)",
     "4f4d00c6014403001fca7678dc3d6c8ecd7598012e965cb5cd7598012e965cb5",
     False),
    ("0x1005 sub=6 (凭据提交)",
     "4f4d00c605100600f7e6e29ade66a5da"
     "948a72c0e8497118eb093af52816ebd4"
     "1449f88aa33a86da2c9fc8665fa4baf3"
     "37f973103c52e3bde4eec99f9fd812fa"
     "e76b231c38001513316bf6dcc8529779"
     "d755be0c229d0a5d8079e3eefad51dc8"
     "e92279776c1addcaa694ec7751ee3888"
     "34fb415de12c6905a135d3faf02ec909"
     "a9712b78427c24a873031c67793571e3"
     "013b3c5195052722d60f9c9be123c3cc",
     True),
    ("0x1100 sub=1 (登录后通知)",
     "4f4d00c600110100f655e667a3643979cd7598012e965cb5cd7598012e965cb5",
     False),
]


# ============== 0x1005 凭据 body ==============
def build_login_creds_body(
    username: str, password: str,
    computer_name: str = "DESEC",
    windows_user: str = "happy",
    sub_9B1540_data: bytes = b"\x00" * 8,
    relogin_token: int = 0,
) -> bytes:
    """构造 cmd 0x1005 sub=6 的 130B 凭据 body，对应 sub_65CFB0 输出布局。

    格式（7 个 DWORD 头 28B + 4 个 UTF-16 字符串）：
        [0] = wcslen(username)
        [1] = wcslen(pwd_hash) = 32
        [2] = wcslen(computer_name)
        [3..4] = sub_9B1540 的 8B (timestamp/IP)
        [5] = relogin_token
        [6] = wcslen(windows_user)
        utf16(username) + L"\\0"
        utf16(pwd_hash) + L"\\0"
        utf16(computer_name) + L"\\0"
        utf16(windows_user) + L"\\0"
    """
    pwd_hash = hash_pwd(username, password)
    s1 = username.encode("utf-16-le") + b"\x00\x00"
    s2 = pwd_hash.encode("utf-16-le") + b"\x00\x00"
    s3 = computer_name.encode("utf-16-le") + b"\x00\x00"
    s4 = windows_user.encode("utf-16-le") + b"\x00\x00"
    assert len(sub_9B1540_data) == 8
    head = (
        struct.pack("<III", len(username), len(pwd_hash), len(computer_name))
        + sub_9B1540_data
        + struct.pack("<II", relogin_token, len(windows_user))
    )
    assert len(head) == 28
    return head + s1 + s2 + s3 + s4


def mutate_creds_packet(captured_pkt: bytes, username: str, password: str,
                        computer_name: str = "DESEC",
                        windows_user: str = "happy") -> bytes:
    """把抓包的 0x1005 sub=6 包打开，换掉里面的 Pwd2 字段，再原路打包回去。

    保留 hdr[8:24] (nonce + sess_state)、hdr[24:32] (机器指纹)、flags 不动。
    保留原 plaintext 里的 [12:20] 8B (sub_9B1540 服务端 IP/时间戳) 和 relogin_token。
    """
    #pdb.set_trace()
    
    deobf = deobf_header(captured_pkt[:32])
    flags = struct.unpack_from("<H", deobf, 2)[0]
    key16 = bytes(deobf[8:24])

    body_ct = captured_pkt[32:]
    raw = AES.new(key16, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(body_ct)
    raw = raw[16:]
    try:
        raw = unpad(raw, 16)
    except ValueError:
        pass
    was_zlib = (raw[:2] == b"\x78\x01")
    if was_zlib:
        raw = zlib.decompress(raw)

    sub9b1540_data = bytes(raw[12:20])
    old_relogin_token = struct.unpack_from("<I", raw, 20)[0]

    new_plain = build_login_creds_body(
        username=username,
        password=password,
        computer_name=computer_name,
        windows_user=windows_user,
        sub_9B1540_data=sub9b1540_data,
        relogin_token=old_relogin_token,
    )

    if was_zlib or (flags & FLAG_COMP):
        compressed = zlib.compress(new_plain, level=1)
    else:
        compressed = new_plain
    new_body = encrypt_payload(flags, key16, compressed)

    new_hdr = bytearray(deobf)
    struct.pack_into("<I", new_hdr, 28, len(new_body))
    return obf_header(bytes(new_hdr)) + new_body


# ============== 完整 5 步登录入口 ==============
def replay_login(
    s: socket.socket,
    username: str, password: str,
    base_nonce: int,
    computer_name: str = "DESEC",
    windows_user: str = "happy",
    show_crypto: bool = False,
    verbose: bool = True,
) -> Tuple[int, int, int, dict]:
    """在已建立的 socket 上跑 5 步登录回放。

    返回 (next_nonce_index, login_role, session_token, last_resp_dict)
    """
    #pdb.set_trace()
    
    last_resp = None
    login_role = 0
    session_token = 0
    i = 0
    for label, hex_pkt, do_mutate in CAPTURED_FLOW:
        pkt = bytes.fromhex(hex_pkt)
        new_nonce = (base_nonce + i) & 0xFFFFFFFF
        pkt = rewrite_nonce(pkt, new_nonce)
        if do_mutate:
            pkt = mutate_creds_packet(pkt, username, password,
                                      computer_name=computer_name,
                                      windows_user=windows_user)
        if show_crypto:
            dump_packet("send", label, pkt)
        elif verbose:
            print(f"[→] {label}  nonce=0x{new_nonce:08x}  ({len(pkt)}B)")
        s.sendall(pkt)

        resp = recv_full_packet(s)
        if show_crypto:
            dump_packet("recv", f"应答 of {label}", resp)
        last_resp = parse_packet(resp)
        i += 1
        if last_resp["a2"] == 0x1005 and last_resp["a3"] == 6:
            d = bytes.fromhex(last_resp["hdr_deobf"])
            login_role    = struct.unpack_from("<I", d, 16)[0]
            session_token = struct.unpack_from("<I", d, 20)[0]
        if verbose and not show_crypto:
            print(f"[←] a2=0x{last_resp['a2']:04x} a3=0x{last_resp['a3']:04x} "
                  f"plen={last_resp['payload_len']}")

    if verbose:
        print(f"[√] 登录完成  login_role=0x{login_role:x} "
              f"session_token=0x{session_token:x}  Pwd2={hash_pwd(username, password)}")
    return i, login_role, session_token, last_resp


def ocp_login_replay(
    host: str, port: int,
    username: str, password: str,
    computer_name: str = "DESEC",
    windows_user: str = "happy",
    timeout: float = 30.0,
    show_crypto: bool = True,
    verbose: bool = True,
):
    #pdb.set_trace()
    
    """对 IPguard3 服务端发起登录的端到端入口（不再做后续业务 cmd）。"""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    if verbose:
        print(f"[*] 起始 nonce = 0x{base_nonce:08x}")
        print(f"[*] 用户        = {username}")
        print()

    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        idx, login_role, session_token, last_resp = replay_login(
            s, username, password, base_nonce,
            computer_name=computer_name, windows_user=windows_user,
            show_crypto=show_crypto, verbose=verbose,
        )
        return {
            "ok": last_resp is not None and last_resp["a2"] == 0x1100,
            "login_role": login_role,
            "session_token": session_token,
            "next_nonce_index": idx,
            "base_nonce": base_nonce,
            "last_resp": last_resp,
            "pwd2": hash_pwd(username, password),
        }
    finally:
        try: s.close()
        except: pass
