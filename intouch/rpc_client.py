# 修正导入部分
import struct, hashlib, argparse
from time import sleep
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.ndr import NDRUniConformantArray, NDRPOINTER, NDRSTRUCT, NDRCALL, NDR
from impacket.dcerpc.v5.dtypes import BOOL, ULONG, DWORD, PULONG, PWCHAR, PBYTE, WIDESTR, UCHAR, WORD, LPSTR, PUINT, WCHAR
from impacket.uuid import uuidtup_to_bin
from Cryptodome.Util.number import bytes_to_long
from wincrypto import CryptEncrypt, CryptImportKey
import pdb
import sys
import time
from threading import Thread
import threading
import traceback

class BlindRPCClient:
    def __init__(self, target_ip, target_port, interface_uuid):
        self.target_ip = target_ip
        self.target_port = target_port
        self.interface_uuid = interface_uuid
        self.rpc_con = None

    def connect(self):
        # 1. 构建传输层字符串
        # 格式: ncacn_ip_tcp:<IP>[<PORT>]
        string_binding = r'ncacn_ip_tcp:%s[%d]' % (self.target_ip, self.target_port)
        
        # 2. 创建传输对象
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        
        # 3. 获取 RPC 连接对象
        self.rpc_con = rpctransport.get_dce_rpc()
        
        # 4. 设置认证级别 (通常设为 NONE)
        # 注意：常量现在通过 rpcrt 模块访问
        #self.rpc_con.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_NONE)

        print(f"[*] 正在连接到 {self.target_ip}:{self.target_port} ...")
        self.rpc_con.connect()
        print("[+] TCP 连接建立")

    def bind(self):
        # 5. 绑定接口 UUID
        print(f"[*] 正在绑定 UUID: {self.interface_uuid} ...")
        
        # 使用服务端实际的 UUID 进行绑定
        self.rpc_con.bind(ndr.uuidtup_to_bin((self.interface_uuid, '1.0')))
        print("[+] 绑定成功！")

    def call_unknown(self, opnum, val1, val2):
        """
        调用假设的函数: int* unknown(int*, int*)
        """
        print(f"[*] 正在调用 OpNum: {opnum}, 参数: {val1}, {val2} ...")
        
        try:
            # --- 构造 NDR Payload ---
            # 构造两个 int* 的完整 NDR 结构
            referent_id_1 = 0x00020000 
            referent_id_2 = 0x00020004 
            max_count = 1
            offset = 0
            
            # 构造第一个 int* (val1)
            p1 = struct.pack('<IIII', referent_id_1, max_count, offset, val1)
            
            # 构造第二个 int* (val2)
            p2 = struct.pack('<IIII', referent_id_2, max_count, offset, val2)
            
            payload = p1 + p2

            # 6. 发送请求
            resp = self.rpc_con.request(opnum, payload)
            
            if resp:
                print(f"[+] 收到响应 (长度: {len(resp)}):")
                print(f"    Hex: {resp.hex()}")
                
                # 尝试解析返回值
                if len(resp) >= 8:
                    ret_val = struct.unpack('<i', resp[4:8])[0]
                    print(f"    解析返回值 (int): {ret_val}")
            else:
                print("[+] 调用成功，无返回数据 (Void)")
                
        except DCERPCException as e:
            print(f"[-] RPC 调用失败: {e}")
        except Exception as e:
            print(f"[-] 发生未知错误: {e}")

# ================= 配置区域 =================

TARGET_IP = '10.43.201.172'      
TARGET_PORT = 54894              

# 必须使用服务端的 UUID
SERVER_UUID = '2cdd8e9d-7183-4900-a818-6a75b3eec6f6'
OPNUM_TO_CALL = 1                

# ================= 执行区域 =================

if __name__ == '__main__':
    client = BlindRPCClient(TARGET_IP, TARGET_PORT, SERVER_UUID)
    
    try:
        client.connect()
        client.bind()
        
        # 调用函数，传入两个整数 10 和 20
        client.call_unknown(OPNUM_TO_CALL, 10, 20)
        
    except Exception as e:
        print(f"[-] 发生错误: {e}")
    finally:
        if client.rpc_con:
            pass
            #client.rpc_con.disconnect()
            
            
            