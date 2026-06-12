"""IPguard3 / OConsole3 加密与哈希原语。

3 个分层：
  1. DES-ECB("ocularv3") —— 32B 头部混淆（仅覆盖 hdr[8:32] 共 24B = 3 块）
  2. AES-128-CBC (IV=0, 16B 噪声前缀, PKCS7) —— 载荷加密
     AES-128-GCM (AAD="TECLINK!@#$") —— 备用 (n9=9)
  3. HMAC-MD5 password hash —— key 由用户名派生

来源：见 ../OConsole3.md
"""
import hashlib
import hmac
import os
import struct
from typing import Optional

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

# ====== 常量 ======
HDR_MAGIC = b"\x4F\x4D"                  # "OM"
OBF_KEY = b"ocularv3"                    # DES 头部混淆密钥
GCM_AAD = b"TECLINK!@#$"                 # AES-GCM AAD

FLAG_GCM_BIT = 0x0100                    # 0x0100 → 走 AES-GCM 而非 CBC
FLAG_CRYPT = 0x4000                      # 载荷加密开启
FLAG_OBF_FULL = 0x4100                   # 头部 DES-ECB 混淆触发位
FLAG_COMP = 0x0800                       # zlib 压缩位


# ====== 32B 头混淆：DES-ECB ======
def deobf_header(hdr: bytes) -> bytes:
    """对 32B 头的 [8:32] 共 24B 用 DES-ECB("ocularv3") 解密。

    若 flags & 0x4100 == 0 则原样返回。
    """
    flags = struct.unpack_from("<H", hdr, 2)[0]
    if not (flags & FLAG_OBF_FULL):
        return hdr
    des = DES.new(OBF_KEY, DES.MODE_ECB)
    return hdr[:8] + des.decrypt(hdr[8:32])


def obf_header(hdr: bytes) -> bytes:
    """deobf_header 的反向操作。"""
    flags = struct.unpack_from("<H", hdr, 2)[0]
    if not (flags & FLAG_OBF_FULL):
        return hdr
    des = DES.new(OBF_KEY, DES.MODE_ECB)
    return hdr[:8] + des.encrypt(hdr[8:32])


# ====== 载荷加解密：AES-128-CBC / GCM ======
def decrypt_payload(flags: int, key: bytes, body: bytes) -> bytes:
    """按 OCP_Cipher_Decrypt 语义：
       1. CBC: 用 hdr[8:24] 当 key, IV=0, 解密后丢首 16B 噪声块, 再 PKCS7 unpad
       2. GCM (n9=9): 末 16B 是 tag, 首 16B 是 IV, 校验 AAD="TECLINK!@#$"
    """
    if not (flags & FLAG_CRYPT) or not body:
        return body
    if flags & FLAG_GCM_BIT:
        iv, ct, tag = body[:16], body[16:-16], body[-16:]
        c = AES.new(key, AES.MODE_GCM, nonce=iv)
        c.update(GCM_AAD)
        return c.decrypt_and_verify(ct, tag)
    c = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
    raw = c.decrypt(body)[16:]            # 丢首 16B 随机噪声块
    try:
        raw = unpad(raw, 16)
    except ValueError:
        pass
    return raw


def encrypt_payload(flags: int, key: bytes, plain: bytes,
                    iv_prefix: Optional[bytes] = None) -> bytes:
    """与 decrypt_payload 对称。
       iv_prefix: 16B 噪声前缀；None 时用 os.urandom(16)
    """
    if not (flags & FLAG_CRYPT):
        return plain
    if flags & FLAG_GCM_BIT:
        iv = iv_prefix or os.urandom(16)
        c = AES.new(key, AES.MODE_GCM, nonce=iv)
        c.update(GCM_AAD)
        ct, tag = c.encrypt_and_digest(plain)
        return iv + ct + tag
    c = AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)
    prefix = iv_prefix or os.urandom(16)
    return c.encrypt(prefix + pad(plain, 16))


# ====== Password hash (HMAC-MD5)  ======
def hash_pwd(username: str, password: str) -> str:
    """计算 IPguard3 控制台登录密码哈希 (32 hex chars, uppercase)。

    与 OConsole3 二进制 sub_A72790 行为完全等价：
      key = ("OCU3" + UPPER(username) + "      ")[:10]   # 10 字节 ASCII
      msg = utf-16-le(password)                          # 不含 NUL
      Pwd2 = HMAC-MD5(key, msg).hexdigest().upper()
    """
    upper = username.upper()
    key_str = ("OCU3" + upper + "      ")[:10]
    key = key_str.encode("latin-1")
    msg = password.encode("utf-16-le")
    return hmac.new(key, msg, hashlib.md5).hexdigest().upper()
