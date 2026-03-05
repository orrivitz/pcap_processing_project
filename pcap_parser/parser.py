import logging
import struct
from typing import Iterator, Optional, Tuple

import dpkt
import pandas as pd

# cache commonly used dpkt classes to avoid repeated attribute lookups
_ETHERNET = dpkt.ethernet.Ethernet
_IP = dpkt.ip.IP
_ARP = dpkt.arp.ARP


def _int_to_ip(ip_int: int) -> str:
    """Convert 32-bit integer to dotted-quad notation."""
    return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"


def _extract_ports(transport_data: bytes) -> Tuple[Optional[int], Optional[int]]:
    """Extract source and destination ports from TCP/UDP header (first 4 bytes)."""
    try:
        # Ensure we have bytes (dpkt may return parsed objects)
        if not isinstance(transport_data, bytes):
            transport_data = bytes(transport_data)
        if len(transport_data) >= 4:
            src_port = struct.unpack("!H", transport_data[:2])[0]
            dst_port = struct.unpack("!H", transport_data[2:4])[0]
            return src_port, dst_port
    except Exception:
        pass
    return None, None


def parse_packet(ts: float, buf: bytes, datalink: int) -> Optional[dict]:
    """
    Fast packet parsing returning dict with extracted packet data.
    Supports IPv4 packets (TCP, UDP, ICMP, other) and ARP packets.
    Uses protocol numbers to avoid object instantiation.
    """
    payload = None

    try:
        # ---- Ethernet ----
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = _ETHERNET(buf)
            payload = eth.data

        # ---- Linux cooked capture (SLL) ----
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            payload = sll.data

        # ---- Raw IP ----
        elif datalink == dpkt.pcap.DLT_RAW:
            payload = _IP(buf)

        # ---- Loopback ----
        elif datalink == dpkt.pcap.DLT_NULL:
            payload = _IP(buf[4:])

        # ---- 802.11 (no radio header) or radiotap ----
        elif datalink in (dpkt.pcap.DLT_IEEE802_11, dpkt.pcap.DLT_IEEE802_11_RADIO):
            frame = buf
            if datalink == dpkt.pcap.DLT_IEEE802_11_RADIO:
                try:
                    rt = dpkt.radiotap.Radiotap(buf)
                    frame = rt.data
                    if hasattr(frame, "pack"):
                        frame = bytes(frame)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    return None

            payload = None
            idx = frame.find(b"\xaa\xaa\x03")
            if idx != -1:
                try:
                    llc = dpkt.llc.LLC(frame[idx:])
                    payload = llc.data
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    pass
            if payload is None:
                return None
        else:
            return None

    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None

    # ---- Check for ARP packets ----
    if isinstance(payload, _ARP):
        try:
            src_ip = int.from_bytes(payload.spa, "big")
            dst_ip = int.from_bytes(payload.tpa, "big")
            return {
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": None,
                "dst_port": None,
                "l4_protocol": "arp",
                "packet_length": len(buf),
            }
        except Exception:
            return None

    # ---- Only IPv4 for remaining packet types ----
    if not isinstance(payload, _IP):
        return None

    ip = payload

    # Convert IPs to integers (avoid string conversion during loop)
    src_ip = int.from_bytes(ip.src, "big")
    dst_ip = int.from_bytes(ip.dst, "big")

    # Use protocol number instead of isinstance checks to avoid object creation
    proto_num = ip.p
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto_str = "other"

    if proto_num == 6:  # TCP
        proto_str = "tcp"
        src_port, dst_port = _extract_ports(ip.data)
    elif proto_num == 17:  # UDP
        proto_str = "udp"
        src_port, dst_port = _extract_ports(ip.data)
    elif proto_num == 1:  # ICMP
        proto_str = "icmp"

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "l4_protocol": proto_str,
        "packet_length": len(buf),
    }


def _open_pcap(f):
    """Open a pcap or pcapng file, returning (reader, datalink_type).

    Tries classic pcap first, then falls back to pcapng.
    Returns ``None`` if neither format can parse the file.
    """
    try:
        reader = dpkt.pcap.Reader(f)
        return reader, reader.datalink()
    except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        f.seek(0)
    try:
        reader = dpkt.pcapng.Reader(f)
        return reader, reader.datalink()
    except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None


def iter_pcap(file_path: str) -> Iterator[dict]:
    """Yield parsed packet dicts one at a time for memory-efficient streaming.

    Each yielded dict contains the same fields as a row in the DataFrame
    returned by :func:`parse_pcap` (with IPs already converted to
    dotted-quad strings).  Supports both pcap and pcapng formats.

    Parameters
    ----------
    file_path : str
        Path to the PCAP file to read.

    Yields
    ------
    dict
        A single parsed packet record.
    """
    with open(file_path, "rb") as f:
        result = _open_pcap(f)
        if result is None:
            return
        pcap, dl = result

        for ts, buf in pcap:
            record = parse_packet(ts, buf, dl)
            if record is not None:
                record["src_ip"] = _int_to_ip(record["src_ip"])
                record["dst_ip"] = _int_to_ip(record["dst_ip"])
                yield record


def parse_pcap(file_path: str) -> pd.DataFrame:
    """Parse a PCAP file and return a pandas DataFrame with one row per packet.

    The DataFrame contains the following columns:

    - ``timestamp``: epoch seconds when the packet was captured
    - ``src_ip``: source IPv4 address
    - ``dst_ip``: destination IPv4 address
    - ``src_port``: L4 source port (``None`` for ICMP/other)
    - ``dst_port``: L4 destination port (``None`` for ICMP/other)
    - ``l4_protocol``: one of ``'tcp'``, ``'udp'``, ``'icmp'`` or ``'other'``
    - ``packet_length``: length of the raw packet bytes

    A packet that cannot be decoded as IPv4 is silently skipped.

    Parameters
    ----------
    file_path : str
        Path to the PCAP file to read.

    Returns
    -------
    pandas.DataFrame
        Table of packets and extracted fields.
    """
    # we'll build column lists efficiently, avoiding per-packet dict allocation
    with open(file_path, "rb") as f:
        result = _open_pcap(f)
        if result is None:
            # file is empty or not a valid pcap/pcapng
            return pd.DataFrame(
                columns=[
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "l4_protocol",
                    "packet_length",
                ]
            )

        pcap, dl = result
        # Pre-allocate column lists (optimization: avoid per-packet dict allocation)
        timestamps = []
        src_ips = []
        dst_ips = []
        src_ports = []
        dst_ports = []
        l4_protos = []
        pkt_lens = []
        skipped_count = 0

        for ts, buf in pcap:
            if record := parse_packet(ts, buf, dl):
                timestamps.append(record["timestamp"])
                src_ips.append(_int_to_ip(record["src_ip"]))
                dst_ips.append(_int_to_ip(record["dst_ip"]))
                src_ports.append(record["src_port"])
                dst_ports.append(record["dst_port"])
                l4_protos.append(record["l4_protocol"])
                pkt_lens.append(record["packet_length"])
            else:
                skipped_count += 1

        if skipped_count > 0:
            logging.info(f"Skipped {skipped_count} non-IPv4/non-ARP packets")

    return pd.DataFrame(
        {
            "timestamp": timestamps,
            "src_ip": src_ips,
            "dst_ip": dst_ips,
            "src_port": src_ports,
            "dst_port": dst_ports,
            "l4_protocol": l4_protos,
            "packet_length": pkt_lens,
        }
    )
