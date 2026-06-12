"""Midtier 握手：开第二条 socket 给 cmd 0x1111 / 0x4890 等用。

来自 IDA `sub_A79BF0` 反编译还原：
  1) 在 conn#0 上发 cmd 0x4713 (GET_MIDTIER) 拿到 midtier IP+SID
  2) 开新 TCP socket → midtier_IP:8263
  3) 在新 socket 上发 cmd 0x4714 (LOGIN_MIDTIER)
  4) 后续业务 cmd (0x1111 / 0x4890 等) 都走第 2 条 socket
"""
import socket
import struct

from .crypto import deobf_header
from .packet import (
    build_packet_with_state, dump_packet, recv_full_packet,
)
from .login import SESSION_FP_DEFAULT


def midtier_login(
    s_main: socket.socket,
    base_nonce: int,
    nonce_index: int,
    login_role: int,
    session_token: int,
    conn_id: int = 1,
    midtier_port: int = 8263,
    timeout: float = 15.0,
    verbose: bool = True,
) -> socket.socket:
    """完整 midtier 握手，返回已 LOGIN_MIDTIER 通过的新 socket。

    若任何一步失败抛 RuntimeError。
    """
    fp = SESSION_FP_DEFAULT
    sess = struct.pack("<II", login_role, session_token)

    # ---- 1) GET_MIDTIER on conn#0 ----
    nonce_a = (base_nonce + nonce_index) & 0xFFFFFFFF
    # 客户端请求方向 = 0xC600 (服务端响应才是 0xC801)
    pkt = build_packet_with_state(
        flags=0xC600, a2=0x4713, a3=0,
        nonce=nonce_a,
        sess_state_16_24=sess,
        fp_lo=fp, fp_hi=fp,
        plain=b"",
    )
    if verbose:
        dump_packet("send", "0x4713 GET_MIDTIER", pkt)
    s_main.sendall(pkt)

    resp = recv_full_packet(s_main)
    if verbose:
        dump_packet("recv", "GET_MIDTIER 应答", resp)

    deobf = deobf_header(resp[:32])
    a5 = struct.unpack_from("<I", deobf, 16)[0]   # midtier_SID
    a6 = struct.unpack_from("<I", deobf, 20)[0]   # midtier_IP_v6 候选
    a7 = struct.unpack_from("<I", deobf, 24)[0]   # midtier_IP_v0 候选
    midtier_sid = a5
    midtier_ip_int = a7 if a7 else a6
    if midtier_ip_int == 0:
        raise RuntimeError(f"midtier IP missing in response: a5=0x{a5:x} "
                           f"a6=0x{a6:x} a7=0x{a7:x}")

    ip_str = ".".join(str((midtier_ip_int >> (8 * i)) & 0xFF) for i in range(4))
    if verbose:
        print(f"[*] midtier_SID = 0x{midtier_sid:x}  IP = {ip_str}  "
              f"(raw=0x{midtier_ip_int:x})")
        print(f"[*] 连接 midtier {ip_str}:{midtier_port} ...")

    # ---- 2) 新 socket ----
    s_mid = socket.create_connection((ip_str, midtier_port), timeout=timeout)
    s_mid.settimeout(timeout)

    # ---- 3) LOGIN_MIDTIER ----
    nonce_b = (base_nonce + nonce_index + 1) & 0xFFFFFFFF
    sess_mid = struct.pack("<II", midtier_sid, conn_id)
    pkt2 = build_packet_with_state(
        flags=0xC600, a2=0x4714, a3=0,
        nonce=nonce_b,
        sess_state_16_24=sess_mid,
        fp_lo=fp, fp_hi=fp,
        plain=b"",
    )
    if verbose:
        dump_packet("send", "0x4714 LOGIN_MIDTIER", pkt2)
    s_mid.sendall(pkt2)

    resp2 = recv_full_packet(s_mid)
    if verbose:
        dump_packet("recv", "LOGIN_MIDTIER 应答", resp2)

    deobf2 = deobf_header(resp2[:32])
    err = struct.unpack_from("<I", deobf2, 24)[0]
    if err and err != 61586:
        s_mid.close()
        raise RuntimeError(f"LOGIN_MIDTIER failed, error_code = 0x{err:x}")

    if verbose:
        print(f"[√] midtier connected. err=0x{err:x}")
    return s_mid
