#!/usr/bin/env python3
"""Decode the real XBE section table for default.xbe.

Corrects opencode's 2026-10-01 table, which anchored the table 0xC bytes
too late (0x37C instead of the header-specified 0x370) and, as a result,
read the RVA/VirtualSize columns one section header forward. Verified via:
  1. raw (addr,size) ranges tile the file with pure-zero gaps
  2. RVA (addr,size) ranges also tile contiguously in virtual space
  3. retail-XOR entry point / kernel-thunk decodes land on real section
     boundaries using THIS table's ranges

Struct layout source: XboxDev/cromwell lib/imagebld/xbe-header.h
(cross-checked against xboxdevwiki.net/Xbe).
"""
import struct
import hashlib
import sys
import os

XBE = os.path.join(os.path.dirname(__file__), "..", "xbe", "default.xbe")

XOR_EP_DEBUG = 0x94859D4B
XOR_EP_RETAIL = 0xA8FC57AB
XOR_KT_DEBUG = 0xEFB1F152
XOR_KT_RETAIL = 0x5B6D40B6


def cstr(d, off):
    end = d.index(b"\x00", off)
    return d[off:end].decode("latin1", "replace")


def decode(path=XBE):
    d = open(path, "rb").read()
    base, = struct.unpack_from("<I", d, 0x104)
    nsec, = struct.unpack_from("<I", d, 0x11C)
    sec_hdr_rva, = struct.unpack_from("<I", d, 0x120)
    table_off = sec_hdr_rva - base

    rows = []
    for i in range(nsec):
        o = table_off + i * 0x38
        flags, rva, vsize, rawaddr, rawsize, nameaddr, refcnt, headref, tailref = \
            struct.unpack_from("<IIIIIIIII", d, o)
        sha = d[o + 0x24:o + 0x38]
        name = cstr(d, nameaddr - base) if nameaddr else f"sec{i}"
        rows.append(dict(i=i, name=name, flags=flags, rva=rva, vsize=vsize,
                          rawaddr=rawaddr, rawsize=rawsize, sha=sha))

    ep_enc, = struct.unpack_from("<I", d, 0x128)
    kt_enc, = struct.unpack_from("<I", d, 0x158)
    entry = (ep_enc ^ XOR_EP_RETAIL) & 0xFFFFFFFF
    kthunk = (kt_enc ^ XOR_KT_RETAIL) & 0xFFFFFFFF

    return d, base, rows, entry, kthunk


if __name__ == "__main__":
    d, base, rows, entry, kthunk = decode()
    print(f"base=0x{base:X}  sections={len(rows)}  entry(retail)=0x{entry:X}  "
          f"kthunk(retail)=0x{kthunk:X}")
    print(f"{'#':<3}{'name':<18}{'flags':<8}{'rva':<10}{'vsize':<10}{'raw':<10}{'rawsz':<10}")
    for r in rows:
        print(f"{r['i']:<3}{r['name']:<18}0x{r['flags']:<6x}0x{r['rva']:<8x}"
              f"0x{r['vsize']:<8x}0x{r['rawaddr']:<8x}0x{r['rawsize']:<8x}")

    print("\nhash check (sha1 of raw bytes vs stored digest):")
    mismatches = 0
    for r in rows:
        h = hashlib.sha1(d[r["rawaddr"]:r["rawaddr"] + r["rawsize"]]).digest()
        ok = h == r["sha"]
        mismatches += (not ok)
        print(f"  {r['name']:<18} match={ok}")
    print(f"\n{mismatches}/{len(rows)} mismatched")
