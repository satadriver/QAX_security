"""32 字节 OCP 头打包/拆包 + 调试可视化。

头部偏移 (来自 OCP_BuildHeader32 反编译)：
  +0  u16  magic       = 0x4D4F (字节序 'O' 'M')
  +2  u16  flags       = 加密/压缩/方向 位掩码
  +4  u16  a2          = cmd id
  +6  u16  a3          = sub
  +8  u32  a8          = (业务字段)
 +12  u32  a4          = nonce / 业务字段 (登录后由 transport 注入 nonce)
 +16  u32  a5          = (业务字段)
 +20  u32  a6          = (业务字段)
 +24  u32  a7          = (业务字段)
 +28  u32  a9          = payload_len (载荷字节数, 不含头)

flags 位含义（已逆向）：
  0x4000 = 载荷加密开启
  0x4100 = 头部 DES-ECB 混淆触发
  0x0800 = zlib 压缩
  0x0100 = AES-GCM (而非 CBC)
"""
import socket
import struct
import zlib
from typing import Optional

from Crypto.Cipher import AES

from .crypto import (
    HDR_MAGIC, FLAG_CRYPT, FLAG_OBF_FULL, FLAG_COMP, FLAG_GCM_BIT,
    deobf_header, obf_header,
    decrypt_payload, encrypt_payload,
)


# ============== 解析 / 构造 ==============
def parse_packet(pkt: bytes) -> dict:
    """从 wire bytes 还原一个 OCP 包：DES 反混淆头 → AES 解密 body → zlib 解压。"""
    assert pkt[:2] == HDR_MAGIC, "magic mismatch"
    hdr = deobf_header(pkt[:32])
    flags = struct.unpack_from("<H", hdr, 2)[0]
    a2, a3 = struct.unpack_from("<HH", hdr, 4)
    key = hdr[8:24]
    payload_len = struct.unpack_from("<I", hdr, 28)[0]
    body = pkt[32 : 32 + payload_len]
    plain = b""
    try:
        plain = decrypt_payload(flags, key, body)
        if plain and (flags & FLAG_COMP) and plain[:2] == b"\x78\x01":
            try:
                plain = zlib.decompress(plain)
            except zlib.error:
                pass
    except Exception as e:
        plain = f"<decrypt err: {e}>".encode()
    return {
        "flags": flags,
        "a2": a2,
        "a3": a3,
        "key": key.hex(),
        "payload_len": payload_len,
        "hdr_deobf": hdr.hex(),
        "body_ct": body.hex(),
        "plain": plain,
    }


def build_packet_with_state(
    flags: int, a2: int, a3: int,
    nonce: int, sess_state_16_24: bytes,
    fp_lo: bytes, fp_hi: bytes,
    plain: bytes,
) -> bytes:
    """以"现代"方式从 0 起手构造一个 OCP 包。

       hdr[8:12]   = 00000000  (a8)
       hdr[12:16]  = nonce LE  (a4)
       hdr[16:24]  = sess_state_16_24  (a5/a6)
       hdr[24:32]  = fp_lo + fp_hi
       payload     = plain → (压缩) → AES-CBC → DES 头混淆
    """
    assert len(sess_state_16_24) == 8
    key16 = b"\x00" * 4 + struct.pack("<I", nonce) + sess_state_16_24
    if flags & FLAG_COMP and plain:
        plain = zlib.compress(plain, level=1)
    body = encrypt_payload(flags, key16, plain) if plain else b""
    hdr = bytearray(32)
    hdr[0:2] = HDR_MAGIC
    struct.pack_into("<H", hdr, 2, flags)
    struct.pack_into("<H", hdr, 4, a2)
    struct.pack_into("<H", hdr, 6, a3)
    hdr[8:12] = b"\x00" * 4
    struct.pack_into("<I", hdr, 12, nonce)
    hdr[16:24] = sess_state_16_24
    hdr[24:32] = fp_lo + fp_hi
    struct.pack_into("<I", hdr, 28, len(body))
    return obf_header(bytes(hdr)) + body


def rewrite_nonce(pkt: bytes, new_nonce: int) -> bytes:
    """把一个 OCP 包的 hdr[12:16] (a4 = nonce) 换成 new_nonce，
       保持 flags / cmd / sub / 其余 hdr 字段不变；如带加密载荷则用旧 key 解密
       后用新 key 重新加密（payload_len 不变）。
    """
    flags = struct.unpack_from("<H", pkt, 2)[0]
    deobf = bytearray(deobf_header(pkt[:32]))
    old_key = bytes(deobf[8:24])
    struct.pack_into("<I", deobf, 12, new_nonce)
    new_key = bytes(deobf[8:24])

    body = pkt[32:]
    if body and (flags & FLAG_CRYPT):
        c_old = AES.new(old_key, AES.MODE_CBC, iv=b"\x00" * 16)
        raw = c_old.decrypt(body)
        c_new = AES.new(new_key, AES.MODE_CBC, iv=b"\x00" * 16)
        body = c_new.encrypt(raw)
    return obf_header(bytes(deobf)) + body


# ============== I/O ==============
def recv_full_packet(s: socket.socket) -> bytes:
    """从 socket 收一个完整 OCP 包：先 32B 头，再读 payload_len 字节。"""
    hdr = b""
    while len(hdr) < 32:
        chunk = s.recv(32 - len(hdr))
        if not chunk:
            raise ConnectionError("server closed during header")
        hdr += chunk
    deobf = deobf_header(hdr)
    plen = struct.unpack_from("<I", deobf, 28)[0]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            raise ConnectionError("server closed during body")
        body += chunk
    return hdr + body


# ============== 调试可视化 ==============
def dump_packet(direction: str, label: str, pkt: bytes,
                indent: str = "    ") -> None:
    """把一个完整 OCP 包打开看：
       1. 线上原始密文 (hex)
       2. DES 反混淆后的 32B 头 (hex + 字段切分 + 符号名)
       3. AES-CBC 解密后的载荷 (hex)
       4. zlib 解压（若有）后的最终明文 (hex + UTF-16 视图)
    """
    # 延迟导入，避免循环
    from .crypto import unpad
    from .cmds import OCP_CMD_BY_ID

    arrow = "→ C2S" if direction == "send" else "← S2C"
    deobf = deobf_header(pkt[:32])
    flags = struct.unpack_from("<H", deobf, 2)[0]
    a2 = struct.unpack_from("<H", deobf, 4)[0]
    a3 = struct.unpack_from("<H", deobf, 6)[0]
    a8 = struct.unpack_from("<I", deobf, 8)[0]
    a4 = struct.unpack_from("<I", deobf, 12)[0]
    a5 = struct.unpack_from("<I", deobf, 16)[0]
    a6 = struct.unpack_from("<I", deobf, 20)[0]
    a7 = struct.unpack_from("<I", deobf, 24)[0]
    plen = struct.unpack_from("<I", deobf, 28)[0]
    sym_row = OCP_CMD_BY_ID.get(a2)
    sym = sym_row[2] if sym_row else f"UNKNOWN_0x{a2:04x}"
    print(f"\n=========  {arrow}  {label}  [{sym} a3={a3}]  ({len(pkt)}B)  =========")
    print(f"{indent}wire   ({len(pkt):3d}B): {pkt.hex()}")
    print(f"{indent}deobf  hdr  : {bytes(deobf).hex()}")
    print(f"{indent}             flags=0x{flags:04x}  a2=0x{a2:04x} ({sym})  a3=0x{a3:04x}")
    print(f"{indent}             a8=0x{a8:08x}  a4(nonce)=0x{a4:08x}")
    print(f"{indent}             a5=0x{a5:08x}  a6=0x{a6:08x}  a7=0x{a7:08x}")
    print(f"{indent}             payload_len = {plen}")
    key16 = bytes(deobf[8:24])
    print(f"{indent}AES key     : {key16.hex()}")
    body_ct = pkt[32:]
    if not body_ct:
        print(f"{indent}body         : <empty>")
        return
    print(f"{indent}body ct ({len(body_ct):3d}B): {body_ct.hex()}")
    if not (flags & FLAG_CRYPT):
        print(f"{indent}body         : (未加密) {body_ct.hex()}")
        return
    raw = AES.new(key16, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(body_ct)
    raw = raw[16:]
    try:
        from Crypto.Util.Padding import unpad as _unpad
        raw = _unpad(raw, 16)
    except ValueError:
        pass
    print(f"{indent}AES dec ({len(raw):3d}B): {raw.hex()}")
    final = raw
    if raw[:2] == b"\x78\x01":
        try:
            final = zlib.decompress(raw)
            print(f"{indent}zlib     ({len(final):3d}B): {final.hex()}")
        except Exception as e:
            print(f"{indent}zlib err: {e}")
    if final:
        try:
            u = final.decode("utf-16-le", "ignore")
            vis = "".join(c if 32 <= ord(c) < 127 else "." for c in u)
            print(f"{indent}utf-16le    : {vis!r}")
        except Exception:
            pass
