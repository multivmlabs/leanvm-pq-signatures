#!/usr/bin/env python3
"""Attribute actual interpreter instruction counts to ELF function ranges."""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def functions(encoded):
    if encoded[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected little endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", encoded)
    sections = [struct.unpack_from("<IIQQQQIIQQ", encoded, header[6] + i * header[11])
                for i in range(header[12])]
    result = {}
    for symbols in (s for s in sections if s[1] == 2):
        strings = sections[symbols[6]]
        names = encoded[strings[4]:strings[4] + strings[5]]
        for offset in range(symbols[4], symbols[4] + symbols[5], symbols[9]):
            name, info, _, _, address, size = struct.unpack_from("<IBBHQQ", encoded, offset)
            if info & 15 != 2 or not size:
                continue
            label = names[name:].split(b"\0", 1)[0].decode("utf-8")
            previous = result.get(address)
            if previous is None or size > previous[0]:
                result[address] = (size, label)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    encoded = args.elf.read_bytes()
    report = json.loads(args.report.read_text())
    elf_hash = hashlib.sha256(encoded).hexdigest()
    if report["elf_sha256"] != elf_hash:
        raise ValueError("profile was produced by another ELF")
    symbols = functions(encoded)
    starts = sorted(symbols)
    counts = Counter()
    profile = report["instruction_profile"]
    total = 0
    for item in profile:
        address, count = int(item["pc_hex"], 16), item["count"]
        total += count
        i = bisect_right(starts, address) - 1
        if i >= 0 and address < starts[i] + symbols[starts[i]][0]:
            counts[starts[i]] += count
        else:
            counts[None] += count
    if total != report["interpreter_instructions"]:
        raise ValueError("profile does not account for every executed instruction")
    rows = [{"address_hex": None if start is None else f"{start:x}",
             "symbol": "<outside function ranges>" if start is None else symbols[start][1],
             "instructions": count, "fraction": count / total}
            for start, count in counts.most_common()]
    output = {
        "scope": "Actual interpreter instructions attributed to current PC function ranges. This is neither inclusive stage timing nor a STARK benchmark.",
        "elf_sha256": elf_hash,
        "profile_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "instructions": total, "functions_executed": len(rows), "functions": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(rows[:15], indent=2))


if __name__ == "__main__":
    main()
