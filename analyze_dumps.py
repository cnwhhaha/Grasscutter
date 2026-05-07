#!/usr/bin/env python3
"""Analyze payload dump files and extract proto field tags.

Dump format (from GameSession.java):
  [4 bytes opcode LE][4 bytes dataLen LE][data bytes]

Usage:
  python3 analyze_dumps.py payload_dump/          # analyze all dumps
  python3 analyze_dumps.py payload_dump/recv_4210_GetPlayerTokenReq_*.bin  # specific file
"""

import struct
import sys
import os
from pathlib import Path
from collections import defaultdict


def read_varint(data, offset):
    """Read a protobuf varint starting at offset, return (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, offset
        shift += 7
    return None, offset


def read_length_delimited(data, offset):
    """Read a length-delimited field, return (raw_bytes, new_offset)."""
    length, offset = read_varint(data, offset)
    if length is None or offset + length > len(data):
        return None, offset
    return data[offset:offset + length], offset + length


def read_fixed32(data, offset):
    """Read a fixed32, return (value, new_offset)."""
    if offset + 4 > len(data):
        return None, offset
    return struct.unpack('<I', data[offset:offset+4])[0], offset + 4


def read_fixed64(data, offset):
    """Read a fixed64, return (value, new_offset)."""
    if offset + 8 > len(data):
        return None, offset
    return struct.unpack('<Q', data[offset:offset+8])[0], offset + 8


def parse_proto_fields(data):
    """Parse proto wire-format fields from raw bytes, return list of (field_number, wire_type, value_repr)."""
    fields = []
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        if tag is None:
            break
        field_number = tag >> 3
        wire_type = tag & 0x7

        wt_names = {0: 'varint', 1: 'fixed64', 2: 'length-delimited', 5: 'fixed32'}

        if wire_type == 0:  # varint
            val, offset = read_varint(data, offset)
            fields.append((field_number, wire_type, f"varint={val}"))
        elif wire_type == 1:  # fixed64
            val, offset = read_fixed64(data, offset)
            fields.append((field_number, wire_type, f"fixed64={val}"))
        elif wire_type == 2:  # length-delimited
            raw, offset = read_length_delimited(data, offset)
            if raw is None:
                fields.append((field_number, wire_type, "ERROR: bad length"))
                break
            # Try to decode as string
            try:
                s = raw.decode('utf-8')
                if s.isprintable() or len(s) < 40:
                    fields.append((field_number, wire_type, f'str="{s}" ({len(raw)}B)'))
                else:
                    fields.append((field_number, wire_type, f'bytes({len(raw)}B) hex={raw[:24].hex()}{"..." if len(raw)>24 else ""}'))
            except:
                fields.append((field_number, wire_type, f'bytes({len(raw)}B) hex={raw[:24].hex()}{"..." if len(raw)>24 else ""}'))
        elif wire_type == 5:  # fixed32
            val, offset = read_fixed32(data, offset)
            fields.append((field_number, wire_type, f"fixed32={val} (0x{val:08X})"))
        else:
            fields.append((field_number, wire_type, f"UNKNOWN wire_type={wire_type}"))
            break

    return fields


def analyze_file(filepath):
    """Analyze a single dump file."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) < 8:
        print(f"  [SKIP] File too small ({len(data)} bytes)")
        return

    opcode = struct.unpack('<I', data[0:4])[0]
    data_len = struct.unpack('<I', data[4:8])[0]
    payload = data[8:8 + data_len] if data_len > 0 else b''

    fname = os.path.basename(filepath)
    print(f"\n{'='*70}")
    print(f"  📦 {fname}")
    print(f"  Opcode: {opcode} (0x{opcode:04X})  |  Payload: {data_len} bytes")
    print(f"{'='*70}")

    if not payload:
        print("  (empty payload)")
        return

    # Show raw hex
    print(f"  Raw hex: {payload[:64].hex()}{'...' if len(payload) > 64 else ''}")
    print()

    # Parse proto fields
    fields = parse_proto_fields(payload)

    if not fields:
        print("  ⚠️  Could not parse any proto fields")
        return

    print(f"  {'Field#':<8} {'Wire':<8} {'Value'}")
    print(f"  {'-'*8} {'-'*8} {'-'*50}")
    for fn, wt, val in fields:
        wt_name = {0: 'varint', 1: 'fixed64', 2: 'len', 5: 'fixed32'}.get(wt, f'?{wt}')
        print(f"  {fn:<8} {wt_name:<8} {val}")

    return fields


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_dumps.py <dump_dir_or_file> [...]")
        sys.exit(1)

    paths = sys.argv[1:]
    files = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            files.extend(sorted(pp.glob("*.bin")))
        elif pp.is_file():
            files.append(pp)
        else:
            # Support glob patterns
            import glob
            files.extend([Path(x) for x in glob.glob(p)])

    if not files:
        print("No .bin dump files found!")
        sys.exit(1)

    print(f"\n🔍 Analyzing {len(files)} dump file(s)...\n")

    # Group by opcode for summary
    by_opcode = defaultdict(list)
    for fpath in files:
        try:
            fields = analyze_file(str(fpath))
            by_opcode[os.path.basename(fpath)].append(fields)
        except Exception as e:
            print(f"  ❌ Error analyzing {fpath}: {e}")

    print(f"\n{'='*70}")
    print(f"  ✅ Done. {len(files)} files analyzed.")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
