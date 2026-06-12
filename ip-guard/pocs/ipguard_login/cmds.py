"""OCP cmd 命名常量与速查表。

来源：IDA `sub_672890` 字典分发器 + `HelperCmd_NNNNN_*` 命名函数 +
`SessionInit_Send_*` + `sub_66B940/sub_66ACE0/sub_66A400/sub_63A9D0` +
实际抓包解码。
"""

# ===== Login session handshake =====
CMD_HELLO              = 0x1001  # 4097
CMD_OPEN_SESSION       = 0x4661  # 18017
CMD_PROFILE_FETCH      = 0x4401  # 17409
CMD_LOGIN_SUBMIT       = 0x1005  # 4101  ★凭据提交
CMD_LOGIN_NOTIFY       = 0x1100  # 4352
CMD_POLICY_REFRESH     = 0x2100  # 8448
CMD_REMOTE_RECONNECT   = 0x4020  # 16416

# ===== Heartbeat =====
CMD_HEARTBEAT_REQ      = 0x2502  # 9474
CMD_HEARTBEAT_ACK      = 0x2503  # 9475
CMD_VERIFY_CODE        = 0x2500  # 9472

# ===== 字典 / 配置查询（来自 sub_672890 分发器）=====
CMD_CLASSIFY_LEVEL     = 0x2000  # 8192 (sub=8)
CMD_FILE_OBJECT        = 0x2001  # 8193
CMD_LOOKUP_2010        = 0x2010  # 8208
CMD_WORK_SCHEDULE      = 0x2020  # 8224
CMD_REGISTER_STATUS    = 0x2050  # 8272
CMD_TREE_TYPE_B        = 0x2081  # 8321
CMD_TREE_TYPE_A        = 0x2090  # 8336
CMD_TREE_TYPE_D        = 0x20a1  # 8353
CMD_TREE_TYPE_C        = 0x20b0  # 8368
CMD_APPROVE_LEVEL      = 0x2b00  # 11008
CMD_NETWORK_RANGE      = 0x3600  # 13824
CMD_OUTSEND_CHANNEL    = 0x3700  # 14080
CMD_CONFIG_XML_GET     = 0x4570  # 17776
CMD_MIDTIER_LIST       = 0x4715  # 18197
CMD_USER_PROPERTY      = 0x4890  # 18576

# ===== License feature =====
CMD_LICENSE_FEATURE    = 0x1500  # 5376
CMD_LICENSE_FEATURE_EX = 0x1501  # 5377

# ===== Midtier handshake (sub_A79BF0) =====
CMD_GET_MIDTIER        = 0x4713  # 18195
CMD_LOGIN_MIDTIER      = 0x4714  # 18196

# ===== TUserSystem32.dll 远程模式 =====
CMD_TUS_LOGIN          = 0xE603  # 58883
CMD_TUS_GET_ITEM       = 0xE608  # 58888
CMD_TUS_GET_CHILDREN   = 0xE609  # 58889
CMD_TUS_CHECK_CHILD    = 0xE60A  # 58890

# ===== 杂项已识别 =====
CMD_GET_LOGIN_USER_INFO  = 0x1111  # 4369  (sub=5) — 当前管理员资料
CMD_DATALEVEL_FETCH      = 0x462a  # 17962 — 数据等级双类拉取
CMD_DATALEVEL_SAVE_B     = 0x4625  # 17957
CMD_DATALEVEL_SAVE_C     = 0x4621  # 17953
CMD_REGIONLEVEL_FETCH    = 0x46fa  # 18170 — 区域等级双类拉取
CMD_REGIONLEVEL_SAVE_B   = 0x46f9  # 18169
CMD_REGIONLEVEL_SAVE_C   = 0x46f6  # 18166
CMD_GET_CONFIG_SNAPSHOT  = 0x4551  # 17745 — 全局配置快照
CMD_EDOC_ERROR_JSON      = 0x4042  # 16450


# ===== 完整速查表（含元数据） =====
# 格式：(cmd_id, sub, "Symbol", "中文/英文含义说明")
OCP_CMD_TABLE = [
    (0x1001, 0,      "OCP_HELLO",                "握手首包：客户端能力位/版本协商 (96B body)"),
    (0x4661, 1,      "OCP_OPEN_SESSION",         "握手 step2：开会话；服务端塞 n16[] dword 数组到全局"),
    (0x4661, 0,      "OCP_OPEN_SESSION_LEGACY",  "降级路径：0x4661 sub=1 返 61442 时改发 sub=0"),
    (0x4401, [3,2,1],"OCP_PROFILE_FETCH",        "握手 step3 拉用户 profile (license key、SUID 等)"),
    (0x1005, 6,      "OCP_LOGIN_SUBMIT",         "★凭据提交：[user, Pwd2, computer, winuser]"),
    (0x1005, 5,      "OCP_LOGIN_SUBMIT_LEGACY",  "0x1005 降级路径 (sub_65C8E0)"),
    (0x1100, [1,2],  "OCP_LOGIN_NOTIFY",         "登录完成通知（含 session_token 等字段）"),
    (0x2100, 5,      "OCP_POLICY_REFRESH",       "重拉用户策略 LoginInfo+OTHER XML (744B)"),
    (0x4020, 0,      "OCP_REMOTE_RECONNECT",     "RemoteControl agent 重连检查"),
    (0x2502, 0,      "OCP_HEARTBEAT_REQ",        "★心跳：5min/次，body=16B 配置 hash"),
    (0x2503, 0,      "OCP_HEARTBEAT_ACK",        "心跳响应"),
    (0x2500, 1,      "OCP_VERIFY_CODE",          "验证码刷新 (4B body)"),
    (0x2000, 8,      "OCP_CLASSIFY_LEVEL",       "密级枚举 → Unclassified 等"),
    (0x2001, [0,1],  "OCP_FILE_OBJECT",          "文件/对象类型查询"),
    (0x2010, 0,      "OCP_LOOKUP_2010",          "字典查询 — 设备相关"),
    (0x2020, 0,      "OCP_WORK_SCHEDULE",        "工时表 → All Day/Working/Rest/Weekend"),
    (0x2050, 0,      "OCP_REGISTER_STATUS",      "设备注册状态 → Registered/Unregistered"),
    (0x2081, 0,      "OCP_TREE_TYPE_B",          "树根 type B"),
    (0x2090, 0,      "OCP_TREE_TYPE_A",          "树根 type A body=ROOT"),
    (0x20a1, 0,      "OCP_TREE_TYPE_D",          "树根 type D"),
    (0x20b0, 0,      "OCP_TREE_TYPE_C",          "树根 type C body=ROOT"),
    (0x2b00, 4,      "OCP_APPROVE_LEVEL",        "审批级别枚举"),
    (0x3000, 0,      "OCP_LOOKUP_3000",          "字典"),
    (0x3010, 1,      "OCP_LOOKUP_3010",          "字典"),
    (0x3600, 0,      "OCP_NETWORK_RANGE",        "网络范围 → Intranet + IP 段"),
    (0x3700, 0,      "OCP_OUTSEND_CHANNEL",      "外发渠道 → Mail/Web/Netshare"),
    (0x1500, 1,      "OCP_LICENSE_FEATURE",      "license feature 名查询 (zlib 压缩)"),
    (0x1501, 1,      "OCP_LICENSE_FEATURE_EX",   "license feature 扩展 (FILING_REASON 等)"),
    (0x4570, 3,      "OCP_CONFIG_XML_GET",       "XML 配置读 (LastConnectServerID 等)"),
    (0x4580, 0,      "OCP_LOOKUP_4580",          "(n600=0x20A)"),
    (0x46b1, 0,      "OCP_LOOKUP_46B1",          "加密设置"),
    (0x46c1, 0,      "OCP_LOOKUP_46C1",          "字典"),
    (0x4715, 0,      "OCP_MIDTIER_LIST",         "★中间层服务器列表 → <MIDTIER>...<ADDR>"),
    (0x4731, 1,      "OCP_LOOKUP_4731",          "8B body"),
    (0x4904, 0,      "OCP_LOOKUP_4904",          "工时绑定"),
    (0x4890, 1,      "OCP_USER_PROPERTY",        "★CUserPropertyTransfer 入口  body=[16B GUID + 4B IncreNo]"),
    (0x4713, 0,      "OCP_GET_MIDTIER",          "★midtier 握手 step1：拿到 midtier IP+SID"),
    (0x4714, 0,      "OCP_LOGIN_MIDTIER",        "★midtier 握手 step2：在新 socket 上 login"),
    (0xE603, 0,      "TUS_LOGIN",                "TUserSystem 登录 (HelperCmd_58883)"),
    (0xE608, 0,      "TUS_GET_ITEM",             "TUS 取单对象 (HelperCmd_58888)"),
    (0xE609, 0,      "TUS_GET_CHILDREN",         "★TUS 列子节点 — 真正列用户路径"),
    (0xE60A, 0,      "TUS_CHECK_CHILD",          "TUS 存在性检查"),
    (0x4042, 0,      "OCP_EDOC_ERROR_JSON",      "EDoc_Error.json — 加密文档错误日志"),
    (0x4551, 0,      "OCP_GET_CONFIG_SNAPSHOT",  "全局配置快照 (sub_66A400)"),
    (0x4621, 3,      "OCP_DATALEVEL_SAVE_C",     "数据等级类 C 保存"),
    (0x4625, 3,      "OCP_DATALEVEL_SAVE_B",     "数据等级类 B 保存"),
    (0x462a, 0,      "OCP_DATALEVEL_FETCH",      "数据等级双类拉取 (sub_66B940)"),
    (0x46f6, 1,      "OCP_REGIONLEVEL_SAVE_C",   "区域等级类 C 保存"),
    (0x46f9, 1,      "OCP_REGIONLEVEL_SAVE_B",   "区域等级类 B 保存"),
    (0x46fa, 0,      "OCP_REGIONLEVEL_FETCH",    "区域等级双类拉取 (sub_66ACE0)"),
    (0x1111, 5,      "OCP_GET_LOGIN_USER_INFO",  "★当前管理员完整资料 (姓名/邮箱/电话/部门/角色 token)"),
]

OCP_CMD_BY_ID = {row[0]: row for row in OCP_CMD_TABLE}


def cmd_name(a2: int, a3: int = None) -> str:
    """根据 cmd id (a2) + 可选 sub (a3) 返回符号名 + 含义说明。"""
    row = OCP_CMD_BY_ID.get(a2)
    if not row:
        return f"UNKNOWN_0x{a2:04x}"
    cid, sub, sym, desc = row
    return f"{sym} (a3={a3}) — {desc}"


def print_cmd_table():
    """打印整张 OCP cmd 速查表。"""
    print("OCP CMD 列表（按 cmd id 排序）")
    print("=" * 100)
    print(f"{'a2':>10}  {'sub':>10}  {'符号名':<26}  说明")
    print("-" * 100)
    for cid, sub, sym, desc in sorted(OCP_CMD_TABLE):
        sub_s = (str(sub) if not isinstance(sub, list)
                 else "/".join(str(s) for s in sub))
        print(f"  0x{cid:04x}  ({cid:5d}) {sub_s:>4}  {sym:<26}  {desc}")
    print("=" * 100)
    print(f"共 {len(OCP_CMD_TABLE)} 条")
