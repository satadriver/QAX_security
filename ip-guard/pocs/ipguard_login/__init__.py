"""ipguard_login —— IPguard3 / OConsole3 OCP 协议登录与业务客户端。

模块结构：
  crypto.py   ——  DES 头混淆、AES 载荷加解密、HMAC-MD5 password hash
  packet.py   ——  32B 头 parse/build/dump、socket I/O、nonce 重写
  cmds.py     ——  OCP cmd id 命名常量 + 速查表
  login.py    ——  5 步重放登录 + 0x1005 凭据 body 重打包
  midtier.py  ——  midtier 握手（GET_MIDTIER + LOGIN_MIDTIER 第 2 socket）
  queries.py  ——  post-login 业务 cmd（generic + 0x1111 admin 资料）
  cli.py      ——  argparse 入口

依赖：pycryptodome (`pip install pycryptodome`)

CLI 用法：
  python -m ipguard_login login    <host> <port> <user> <pwd>
  python -m ipguard_login hash     <user> <pwd>
  python -m ipguard_login cmds
  python -m ipguard_login query    <host> <port> <user> <pwd> <a2> [--sub N]
  python -m ipguard_login admin    <host> <port> <user> <pwd>

代码 API：
  from ipguard_login import (
      hash_pwd,
      ocp_login_replay,
      query_admin_info_via_midtier,
      post_login_cmd_replay,
  )
"""

# 顶层 re-export ——
from .crypto import (
    HDR_MAGIC, OBF_KEY, GCM_AAD,
    FLAG_GCM_BIT, FLAG_CRYPT, FLAG_OBF_FULL, FLAG_COMP,
    deobf_header, obf_header,
    decrypt_payload, encrypt_payload,
    hash_pwd,
)
from .packet import (
    parse_packet, build_packet_with_state, rewrite_nonce,
    recv_full_packet, dump_packet,
)
from .cmds import (
    OCP_CMD_TABLE, OCP_CMD_BY_ID, cmd_name, print_cmd_table,
)
from .login import (
    SESSION_FP_DEFAULT, CAPTURED_FLOW,
    build_login_creds_body, mutate_creds_packet,
    replay_login, ocp_login_replay,
)
from .midtier import midtier_login
from .queries import (
    post_login_cmd_replay,
    parse_admin_info,
    query_admin_info_via_midtier,
)

__all__ = [
    # crypto
    "hash_pwd", "deobf_header", "obf_header",
    "decrypt_payload", "encrypt_payload",
    "HDR_MAGIC", "OBF_KEY", "GCM_AAD",
    "FLAG_CRYPT", "FLAG_OBF_FULL", "FLAG_COMP", "FLAG_GCM_BIT",
    # packet
    "parse_packet", "build_packet_with_state", "rewrite_nonce",
    "recv_full_packet", "dump_packet",
    # cmds
    "OCP_CMD_TABLE", "OCP_CMD_BY_ID", "cmd_name", "print_cmd_table",
    # login
    "SESSION_FP_DEFAULT", "CAPTURED_FLOW",
    "build_login_creds_body", "mutate_creds_packet",
    "replay_login", "ocp_login_replay",
    # midtier
    "midtier_login",
    # queries
    "post_login_cmd_replay", "parse_admin_info",
    "query_admin_info_via_midtier",
]
