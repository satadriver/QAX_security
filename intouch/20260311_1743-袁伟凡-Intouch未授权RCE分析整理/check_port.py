# -*- coding: utf-8 -*-
# @Time     : 2025/11/7 15:34
# @Author   : Desec
# @FIle     : detect.py
# @Software : Pycharm


import socket
import sys

message = "42d5cfc7f80bcdd311aa1000a0c9ecfd9fff9855c83d25d411aa2700a0c9ecfd9f0100000041006c00610072006d004d006700720000000400000000000000f4380000"
message3 = "42D5CFC7F80BCDD311AA1000A0C9ECFD9FFF9855C83D25D411AA2700A0C9ECFD9F01000000630061006C006300000000000000000000000400000000000000F4380000"
message4 = "42D5CFC7F80BCDD311AA1000A0C9ECFD9FFF9855C83D25D411AA2700A0C9ECFD9F01000000630061006C0063002E6500780065000000000400000000000000F4380000"


def check_port(host, port, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except:
        print(f"[-] {host}:{port} 未开放")
        return
    print(f"[+] {host}:{port} 开放")
    data = bytes.fromhex(message3)
    try:
        s.send(data)
        data = s.recv(1024)
        print(data.hex())
    except:
        print(f"[*] {host}:{port} 不确定是否intouch端口")
    data = data.hex()
    if len(data) == len("1496e27844fccdd311aa1000a0c9ecfd9f03000000") and "1496e27844fccdd311aa1000a0c9ecfd9f" in data:
        print("[+] intouch 5413")
    s.close()


if __name__ == "__main__":
    port = 5413
    host = sys.argv[1]
    print(f"[*] 5413")
    check_port(host, port)
