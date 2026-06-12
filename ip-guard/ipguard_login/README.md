# ipguard_login

IPguard3 / OConsole3 自定义二进制协议（OCP）的 Python 客户端。

实现内容：
- DES-ECB 头部混淆（密钥 `ocularv3`）
- AES-128-CBC / AES-128-GCM 载荷加解密
- zlib 压缩
- HMAC-MD5 用户密码哈希（key 由用户名派生）
- 5 步重放登录（0x1001 → 0x4661 → 0x4401 → 0x1005 → 0x1100）
- midtier 二级握手（cmd 0x4713 GET_MIDTIER + 0x4714 LOGIN_MIDTIER 在第 2 条 socket 上）
- 后续业务 cmd 通用工具

详细协议分析参见上一级目录的 `OConsole3.md`。

## 安装

```bash
pip install pycryptodome
```

## 命令行用法

```bash
# 算密码哈希（不联网）
python -m ipguard_login hash Admin admin123456

# 完整登录（5 步重放）
python -m ipguard_login login 192.168.221.136 8236 Admin admin123456

# 关掉每包解密展开
python -m ipguard_login login 192.168.221.136 8236 Admin admin123456 --no-show-crypto

# 打印 OCP cmd 速查表
python -m ipguard_login cmds

# 登录后向 conn#0 发任意一个 cmd（通用）
python -m ipguard_login query 192.168.221.136 8236 Admin admin123456 0x4715

# 登录 + midtier 握手 + 0x1111 拿管理员资料
python -m ipguard_login admin 192.168.221.136 8236 Admin admin123456
```

## 代码 API

```python
from ipguard_login import (
    hash_pwd,                       # 密码哈希
    ocp_login_replay,               # 5 步登录端到端
    query_admin_info_via_midtier,   # 登录 + midtier + 取管理员资料
    post_login_cmd_replay,          # 登录后发任意 cmd（generic）
    OCP_CMD_TABLE, cmd_name,        # cmd id 查表
    parse_packet, dump_packet,      # 协议解包 / 调试输出
)
```

## 模块结构

```
ipguard_login/
├── __init__.py    顶层 re-export
├── __main__.py    python -m ipguard_login → cli.cli()
├── cli.py         argparse 命令行入口
├── crypto.py      DES + AES + HMAC-MD5
├── packet.py      32B 头 parse/build/dump、socket I/O
├── cmds.py        OCP cmd id 命名常量 + 速查表
├── login.py       5 步重放登录 + 0x1005 凭据 body 重打包
├── midtier.py     GET_MIDTIER + LOGIN_MIDTIER 第 2 socket 握手
└── queries.py     post-login 业务 cmd（admin info、generic）
```
