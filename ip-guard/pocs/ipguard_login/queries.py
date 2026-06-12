"""登录之后向服务端发各类业务 cmd 的高层接口。"""
import os
import socket
import struct
import zlib
from typing import Optional

from .crypto import hash_pwd
from .packet import (
    build_packet_with_state, dump_packet, recv_full_packet, parse_packet,
)
from .login import (
    SESSION_FP_DEFAULT, replay_login,
)
from .midtier import midtier_login


# ============== 通用 conn#0 cmd 发送 ==============
def post_login_cmd_replay(
    host: str, port: int,
    username: str, password: str,
    a2: int, a3: int = 0,
    body: bytes = b"",
    sess_state_16_24: Optional[bytes] = None,
    timeout: float = 15.0,
    verbose: bool = True,
):
    """完成 5 步登录后，在同一 socket (conn#0) 上发任意一个 cmd。

    sess_state_16_24: 写到 hdr[16:24] 的 8B；None 时填 (login_role, session_token)。
    """
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000

    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        idx, login_role, session_token, _ = replay_login(
            s, username, password, base_nonce,
            show_crypto=False, verbose=verbose,
        )

        if sess_state_16_24 is None:
            sess_state_16_24 = struct.pack("<II", login_role, session_token)
        next_nonce = (base_nonce + idx) & 0xFFFFFFFF

        # ★ 客户端请求用 0xC600 (与抓包里 0x1005/0x4661 等 C→S 包一致)
        # 0xC801 是服务端响应方向，发出去服务端会丢
        flags = 0xC600
        pkt = build_packet_with_state(
            flags=flags, a2=a2, a3=a3,
            nonce=next_nonce,
            sess_state_16_24=sess_state_16_24,
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body,
        )
        if verbose:
            dump_packet("send", f"cmd 0x{a2:04x} sub={a3}", pkt)
        s.sendall(pkt)

        try:
            resp = recv_full_packet(s)
        except (socket.timeout, ConnectionError) as e:
            if verbose:
                print(f"\n[!] cmd 0x{a2:04x} 没收到响应: {e}")
            return None

        if verbose:
            dump_packet("recv", f"应答 of 0x{a2:04x}", resp)
        return parse_packet(resp)
    finally:
        try: s.close()
        except: pass


# ============== 0x1111 GET_LOGIN_USER_INFO ==============
def parse_admin_info(plain: bytes) -> dict:
    """解析 cmd 0x1111 sub=5 的响应 (sub_A779F0 还原)。

    结构：40 DWORD 头 (160B) + 5 段 UTF-16 字符串 (含 NUL)。
    各字段长度记录在 a2[6/11/13/34/35]。
    """
    if len(plain) < 160:
        return {"raw": plain, "error": "payload < 160B"}
    a2 = list(struct.unpack_from("<40I", plain, 0))

    def read_wstr_at(off: int) -> str:
        if off >= len(plain):
            return ""
        end = off
        while end + 1 < len(plain) and plain[end:end+2] != b"\x00\x00":
            end += 2
        try:
            return plain[off:end].decode("utf-16-le", "ignore")
        except Exception:
            return ""

    L0, L1, L2, L3, L4 = a2[6], a2[11], a2[13], a2[34], a2[35]
    s_displayName = read_wstr_at(160)
    s_email       = read_wstr_at(162 + 2 * L0)
    s_phone       = read_wstr_at(166 + 2 * (L0 + L1 + L2))
    s_dept        = read_wstr_at(168 + 2 * (L0 + L1 + L2 + L3))
    s_misc        = read_wstr_at(170 + 2 * (L0 + L1 + L2 + L3 + L4))
    return {
        "enable_flag":     a2[1],
        "session_id":      a2[7],
        "len_displayName": L0,
        "len_email":       L1,
        "len_phone":       L2,
        "len_dept":        L3,
        "len_misc":        L4,
        "role_token_array":a2[15:31],
        "trailing":        a2[37:40],
        "displayName":     s_displayName,
        "email":           s_email,
        "phone":           s_phone,
        "dept":            s_dept,
        "misc":            s_misc,
        "raw_len":         len(plain),
    }


def query_admin_info_via_midtier(
    host: str, port: int,
    username: str, password: str,
    timeout: float = 30.0,
    verbose: bool = True,
):
    """完整流程：5 步登录 → midtier 握手 → 在 midtier 连接发 0x1111 sub=5。"""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000

    s_main = socket.create_connection((host, port), timeout=timeout)
    s_main.settimeout(timeout)
    s_mid: Optional[socket.socket] = None
    try:
        idx, login_role, session_token, _ = replay_login(
            s_main, username, password, base_nonce,
            show_crypto=False, verbose=verbose,
        )

        s_mid = midtier_login(
            s_main, base_nonce, idx, login_role, session_token,
            conn_id=1, timeout=timeout, verbose=verbose,
        )
        idx += 2

        # 在 midtier 上发 0x1111 sub=5 (客户端请求 = 0xC600)
        next_nonce = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=0xC600, a2=0x1111, a3=5,
            nonce=next_nonce,
            sess_state_16_24=b"\x00" * 8,
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=b"",
        )
        if verbose:
            dump_packet("send", "midtier 0x1111 sub=5", pkt)
        s_mid.sendall(pkt)

        resp = recv_full_packet(s_mid)
        if verbose:
            dump_packet("recv", "midtier 0x1111 应答", resp)
        r = parse_packet(resp)

        if r["payload_len"] and isinstance(r["plain"], bytes):
            plain = r["plain"]
            if plain[:2] == b"\x78\x01":
                try: plain = zlib.decompress(plain)
                except: pass
            info = parse_admin_info(plain)
            if verbose:
                print()
                print("=" * 60)
                print("[*] 当前管理员信息（midtier 路径）：")
                print("=" * 60)
                for k, v in info.items():
                    if k == "role_token_array":
                        print(f"  {k:22} = " + " ".join(f"{x:08x}" for x in v))
                    elif isinstance(v, (list, tuple, bytes)):
                        print(f"  {k:22} = {v}")
                    else:
                        print(f"  {k:22} = {v!r}")
            return info

        if verbose:
            print("[!] midtier 0x1111 响应无 payload")
        return None
    finally:
        try:
            if s_mid: s_mid.close()
        except: pass
        try: s_main.close()
        except: pass
