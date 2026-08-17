"""macOS ARP/neighbor table via PF_ROUTE sysctl (sockaddr_inarp layout)."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import socket
from dataclasses import dataclass

from netdiag.terminal import terminal_safe

CTL_NET = 4
PF_ROUTE = 17
NET_RT_FLAGS = 2
RTF_LLINFO = 0x400
AF_LINK = 18


class RtMetrics(ctypes.Structure):
    _fields_ = [
        ("rmx_locks", ctypes.c_uint32),
        ("rmx_mtu", ctypes.c_uint32),
        ("rmx_hopcount", ctypes.c_uint32),
        ("rmx_expire", ctypes.c_int32),
        ("rmx_recvpipe", ctypes.c_uint32),
        ("rmx_sendpipe", ctypes.c_uint32),
        ("rmx_ssthresh", ctypes.c_uint32),
        ("rmx_rtt", ctypes.c_uint32),
        ("rmx_rttvar", ctypes.c_uint32),
        ("rmx_pksent", ctypes.c_uint32),
        ("rmx_filler", ctypes.c_uint32 * 4),
    ]


class RtMsgHdr(ctypes.Structure):
    _fields_ = [
        ("rtm_msglen", ctypes.c_uint16),
        ("rtm_version", ctypes.c_uint8),
        ("rtm_type", ctypes.c_uint8),
        ("rtm_index", ctypes.c_uint16),
        ("rtm_flags", ctypes.c_int32),
        ("rtm_addrs", ctypes.c_int32),
        ("rtm_pid", ctypes.c_int32),
        ("rtm_seq", ctypes.c_int32),
        ("rtm_errno", ctypes.c_int32),
        ("rtm_use", ctypes.c_int32),
        ("rtm_inits", ctypes.c_uint32),
        ("rtm_rmx", RtMetrics),
    ]


RT_MSGHDR_SIZE = ctypes.sizeof(RtMsgHdr)


@dataclass(frozen=True)
class ArpProbeResult:
    entries: list[dict]
    source: str
    status: str
    detail: str = ""


def _sa_size(sa_len: int) -> int:
    if sa_len <= 0:
        return 8
    return 1 + ((sa_len - 1) | 7)


def _parse_mac(raw: bytes, offset: int) -> str | None:
    if offset + 8 > len(raw) or raw[offset + 1] != AF_LINK:
        return None
    name_len = raw[offset + 5]
    addr_len = raw[offset + 6]
    if addr_len != 6:
        return None
    start = offset + 8 + name_len
    mac = raw[start : start + addr_len]
    if len(mac) != 6 or mac == bytes(6) or mac == bytes([0xFF]) * 6 or mac[0] & 1:
        return None
    return ":".join(f"{byte:02x}" for byte in mac)


def _sysctl_raw_buffer(*, mib_flags: int = NET_RT_FLAGS) -> bytes:
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    mib = (ctypes.c_int * 6)(CTL_NET, PF_ROUTE, 0, 0, mib_flags, RTF_LLINFO)
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 6, None, ctypes.byref(size), None, 0) != 0:
        raise OSError("sysctl route-sysctl-estimate failed")
    if size.value == 0:
        return b""

    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 6, buf, ctypes.byref(size), None, 0) != 0:
        raise OSError("sysctl route-table read failed")
    return bytes(buf.raw[: size.value])


def read_arp_table_sysctl(*, mib_flags: int = NET_RT_FLAGS) -> list[dict]:
    """Read the IPv4 neighbor cache using PF_ROUTE/RTF_LLINFO sysctl data."""
    raw = _sysctl_raw_buffer(mib_flags=mib_flags)
    if not raw:
        return []
    entries: list[dict] = []
    offset = 0
    while offset + RT_MSGHDR_SIZE <= len(raw):
        header = RtMsgHdr.from_buffer_copy(raw, offset)
        if header.rtm_msglen < RT_MSGHDR_SIZE:
            break

        pos = offset + RT_MSGHDR_SIZE
        if pos + 8 > len(raw):
            break

        ip = socket.inet_ntoa(raw[pos + 4 : pos + 8])
        link_offset = pos + _sa_size(raw[pos])
        mac = _parse_mac(raw, link_offset)
        hostname = "?"
        entries.append(
            {
                "ip": ip,
                "mac": mac or "(incomplete)",
                "hostname": hostname,
                "ifindex": int(header.rtm_index),
            }
        )
        offset += header.rtm_msglen
    return entries


def _entries_have_mac(entries: list[dict]) -> bool:
    for entry in entries:
        mac = entry.get("mac", "")
        if mac not in {"", "(incomplete)", "incomplete", "failed"}:
            return True
    return False


def probe_arp_table() -> ArpProbeResult:
    """Read the ARP table from PF_ROUTE sysctl data."""
    try:
        entries = read_arp_table_sysctl()
    except OSError as exc:
        return ArpProbeResult([], "sysctl_rtm", "error", str(exc))

    if not entries:
        return ArpProbeResult([], "sysctl_rtm", "empty", "No IPv4 neighbor cache entries returned")

    if _entries_have_mac(entries):
        return ArpProbeResult(entries, "sysctl_rtm", "ok")

    return ArpProbeResult(
        entries,
        "sysctl_rtm",
        "partial",
        "Neighbor MAC addresses were not exposed to this Python runtime",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dump macOS ARP table via sysctl")
    parser.add_argument("--json", action="store_true", help="Print JSON entries")
    args = parser.parse_args(argv)
    entries = read_arp_table_sysctl()
    if args.json:
        print(json.dumps(entries))
    else:
        for entry in entries:
            print(
                f"{terminal_safe(entry['ip'])}\t{terminal_safe(entry['mac'])}\t"
                f"{terminal_safe(entry['ifindex'])}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
