import os

import pandas as pd
import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap

from pcap_parser.parser import iter_pcap, parse_pcap

# helper to create a small pcap file containing a handful of packets


def create_sample_pcap(path: str):
    pkt1 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)
    pkt2 = Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=5353)
    pkt3 = Ether() / IP(src="5.5.5.5", dst="6.6.6.6") / ICMP()
    # write the packets to disk
    wrpcap(path, [pkt1, pkt2, pkt3])


def test_parse_pcap_returns_dataframe(tmp_path):
    pcap_file = tmp_path / "sample.pcap"
    create_sample_pcap(str(pcap_file))

    df = parse_pcap(str(pcap_file))
    assert isinstance(df, pd.DataFrame)

    expected_cols = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "l4_protocol",
        "packet_length",
    ]
    assert list(df.columns) == expected_cols
    assert df.shape[0] == 3

    # basic content checks
    assert set(df["l4_protocol"]) == {"tcp", "udp", "icmp"}
    tcp_row = df[df.l4_protocol == "tcp"].iloc[0]
    assert tcp_row.src_ip == "1.1.1.1"
    assert tcp_row.dst_ip == "2.2.2.2"
    assert tcp_row.src_port == 1234
    assert tcp_row.dst_port == 80

    udp_row = df[df.l4_protocol == "udp"].iloc[0]
    assert udp_row.src_port == 53
    assert udp_row.dst_port == 5353

    icmp_row = df[df.l4_protocol == "icmp"].iloc[0]
    assert pd.isna(icmp_row.src_port)
    assert pd.isna(icmp_row.dst_port)


def test_parse_pcap_skips_non_ip(tmp_path):
    # create a file containing an ethernet frame with no IP payload
    pcap_file = tmp_path / "nonip.pcap"
    pkt = Ether() / b"\x00\x01\x02"
    wrpcap(str(pcap_file), [pkt])

    df = parse_pcap(str(pcap_file))
    assert df.empty


def test_parse_pcap_handles_empty_file(tmp_path):
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")
    df = parse_pcap(str(empty_file))
    assert df.empty


def test_parse_packet_with_datalink():
    # craft a minimal IPv4 TCP packet in an Ethernet frame and pass datalink
    eth = Ether() / IP(src="7.7.7.7", dst="8.8.8.8") / TCP(sport=1111, dport=2222)
    buf = bytes(eth)
    # datalink 1 corresponds to EN10MB (Ethernet)
    from pcap_parser import parser

    rec = parser.parse_packet(123456.0, buf, parser.dpkt.pcap.DLT_EN10MB)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "7.7.7.7"
    assert parser._int_to_ip(rec["dst_ip"]) == "8.8.8.8"
    assert rec["l4_protocol"] == "tcp"

    # unsupported datalink should return None
    rec2 = parser.parse_packet(0, buf, 9999)
    assert rec2 is None


def test_parse_packet_dlt_raw():
    """Test parsing raw IP packets (DLT_RAW = 12)"""
    from pcap_parser import parser

    # Create a raw IP packet without any link-layer header
    ip = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=443)
    buf = bytes(ip)

    rec = parser.parse_packet(999.0, buf, parser.dpkt.pcap.DLT_RAW)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "10.0.0.1"
    assert parser._int_to_ip(rec["dst_ip"]) == "10.0.0.2"
    assert rec["src_port"] == 5000
    assert rec["dst_port"] == 443
    assert rec["l4_protocol"] == "tcp"


def test_parse_packet_dlt_raw_udp():
    """Test parsing raw IP UDP packets"""
    from pcap_parser import parser

    ip = IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=68, dport=67)
    buf = bytes(ip)

    rec = parser.parse_packet(111.0, buf, parser.dpkt.pcap.DLT_RAW)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "192.168.1.10"
    assert parser._int_to_ip(rec["dst_ip"]) == "192.168.1.1"
    assert rec["src_port"] == 68
    assert rec["dst_port"] == 67
    assert rec["l4_protocol"] == "udp"


def test_parse_packet_dlt_null():
    """Test parsing loopback packets (DLT_NULL = 0)"""
    import struct

    from pcap_parser import parser

    # Loopback format: 4 bytes for address family (little-endian) + IP packet
    ip = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=12345, dport=8080)
    af = struct.pack("<I", 2)  # AF_INET = 2 in little-endian
    buf = af + bytes(ip)

    rec = parser.parse_packet(555.0, buf, parser.dpkt.pcap.DLT_NULL)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "127.0.0.1"
    assert parser._int_to_ip(rec["dst_ip"]) == "127.0.0.1"
    assert rec["src_port"] == 12345
    assert rec["dst_port"] == 8080
    assert rec["l4_protocol"] == "tcp"


def test_parse_packet_dlt_linux_sll():
    """Test parsing Linux cooked capture packets (DLT_LINUX_SLL = 113)"""
    import struct

    from pcap_parser import parser

    # SLL header is 16 bytes:
    # 2 bytes: packet type (host=0, broadcast=1, multicast=2, othhost=3, outgoing=4)
    # 2 bytes: ARPHRD type (e.g., 1 for Ethernet)
    # 2 bytes: link layer address length
    # 8 bytes: link layer source address (padded)
    # 2 bytes: protocol type (0x0800 for IPv4)
    sll_header = struct.pack(
        "!HHHBBBBBBBBH",
        0,  # pkttype: host
        1,  # arphrd: ARPHRD_ETHER
        6,  # addr_len: 6 (MAC address)
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        0xFF,  # src_addr (MAC, 6 bytes)
        0x00,
        0x00,  # padding (2 bytes)
        0x0800,  # protocol: IPv4
    )

    ip = IP(src="172.16.0.1", dst="172.16.0.2") / UDP(sport=5353, dport=5353)
    buf = sll_header + bytes(ip)

    rec = parser.parse_packet(777.0, buf, parser.dpkt.pcap.DLT_LINUX_SLL)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "172.16.0.1"
    assert parser._int_to_ip(rec["dst_ip"]) == "172.16.0.2"
    assert rec["src_port"] == 5353
    assert rec["dst_port"] == 5353
    assert rec["l4_protocol"] == "udp"


def test_parse_packet_dlt_en10mb_icmp():
    """Test parsing Ethernet ICMP packets"""
    from pcap_parser import parser

    eth = Ether() / IP(src="8.8.8.8", dst="1.1.1.1") / ICMP()
    buf = bytes(eth)

    rec = parser.parse_packet(444.0, buf, parser.dpkt.pcap.DLT_EN10MB)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "8.8.8.8"
    assert parser._int_to_ip(rec["dst_ip"]) == "1.1.1.1"
    assert rec["l4_protocol"] == "icmp"
    assert pd.isna(rec["src_port"])
    assert pd.isna(rec["dst_port"])


def test_parse_packet_raw_icmp():
    """Test parsing raw ICMP packets"""
    from pcap_parser import parser

    ip = IP(src="8.8.8.8", dst="1.1.1.1") / ICMP()
    buf = bytes(ip)

    rec = parser.parse_packet(333.0, buf, parser.dpkt.pcap.DLT_RAW)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "8.8.8.8"
    assert parser._int_to_ip(rec["dst_ip"]) == "1.1.1.1"
    assert rec["l4_protocol"] == "icmp"
    assert pd.isna(rec["src_port"])
    assert pd.isna(rec["dst_port"])


def test_parse_packet_unsupported_datalink():
    """Test that unsupported datalinks gracefully return None"""
    from pcap_parser import parser

    eth = Ether() / IP(src="10.10.10.10", dst="20.20.20.20") / TCP(sport=22, dport=22)
    buf = bytes(eth)

    # Pass an unsupported datalink code
    rec = parser.parse_packet(0, buf, 9999)
    assert rec is None


def test_various_l4_protocols(tmp_path):
    """Generate a pcap with multiple L4 protocols and check parsed values."""
    # create packets for tcp, udp, icmp, and an unknown proto (99)
    pkts = []
    pkts.append(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=111, dport=80))
    pkts.append(Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=5353))
    pkts.append(Ether() / IP(src="5.5.5.5", dst="6.6.6.6") / ICMP())
    # other protocol number 99 with raw payload
    pkts.append(Ether() / IP(src="7.7.7.7", dst="8.8.8.8", proto=99) / b"abcdef")

    pcap_file = tmp_path / "mixed.pcap"
    wrpcap(str(pcap_file), pkts)

    df = parse_pcap(str(pcap_file))
    assert df.shape[0] == 4
    # check classification
    assert set(df.l4_protocol) == {"tcp", "udp", "icmp", "other"}
    # ports present only for tcp/udp
    assert df[df.l4_protocol == "tcp"].src_port.iloc[0] == 111
    assert df[df.l4_protocol == "udp"].dst_port.iloc[0] == 5353
    # other and icmp should have NaN ports
    assert pd.isna(df[df.l4_protocol == "icmp"].src_port.iloc[0])
    assert pd.isna(df[df.l4_protocol == "other"].src_port.iloc[0])


def test_wifi_datalinks_radiotap_tcp():
    """Test parsing WiFi packets with Radiotap header (DLT_IEEE802_11_RADIO = 127)"""
    import struct

    from pcap_parser import parser

    # Build a minimal Radiotap header
    # Radiotap header format:
    # - 1 byte: version (0)
    # - 1 byte: padding (0)
    # - 2 bytes: header length (little-endian)
    # - 4 bytes: presence flags (little-endian)
    rt_version = 0
    rt_padding = 0
    rt_length = 8  # minimal header: version(1) + padding(1) + length(2) + flags(4)
    rt_flags = 0  # no fields present

    radiotap_header = struct.pack("<BBHI", rt_version, rt_padding, rt_length, rt_flags)

    # Build a minimal 802.11 data frame with LLC header and IP payload
    # 802.11 frame control: Data frame (0x0841 = QoS data, from AP)
    frame_control = struct.pack("<H", 0x0841)
    duration = struct.pack("<H", 0)
    addr1 = b"\xff\xff\xff\xff\xff\xff"  # DA (broadcast)
    addr2 = b"\x00\x11\x22\x33\x44\x55"  # SA (transmitter)
    addr3 = b"\x66\x77\x88\x99\xaa\xbb"  # BSSID
    seq_ctrl = struct.pack("<H", 0)
    qos_ctrl = struct.pack("<H", 0)

    frame_header = (
        frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + qos_ctrl
    )

    # LLC header: 0xaaaa0300 (SNAP with IPv4 EtherType 0x0800)
    llc_header = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

    # IP payload
    ip = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=443)
    ip_payload = bytes(ip)

    # Complete WiFi frame
    wifi_frame = frame_header + llc_header + ip_payload

    # Complete packet with radiotap
    buf = radiotap_header + wifi_frame

    rec = parser.parse_packet(1234567890.0, buf, parser.dpkt.pcap.DLT_IEEE802_11_RADIO)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "192.168.1.100"
    assert parser._int_to_ip(rec["dst_ip"]) == "192.168.1.1"
    assert rec["src_port"] == 54321
    assert rec["dst_port"] == 443
    assert rec["l4_protocol"] == "tcp"


def test_wifi_datalinks_radiotap_udp():
    """Test parsing WiFi UDP packets with Radiotap header"""
    import struct

    from pcap_parser import parser

    # Minimal Radiotap header
    radiotap_header = struct.pack("<BBHI", 0, 0, 8, 0)

    # Minimal 802.11 data frame header
    frame_control = struct.pack("<H", 0x0841)
    duration = struct.pack("<H", 0)
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr2 = b"\x00\x11\x22\x33\x44\x55"
    addr3 = b"\x66\x77\x88\x99\xaa\xbb"
    seq_ctrl = struct.pack("<H", 0)
    qos_ctrl = struct.pack("<H", 0)

    frame_header = (
        frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + qos_ctrl
    )

    # LLC header for IPv4
    llc_header = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

    # IP payload with UDP
    ip = IP(src="10.0.0.50", dst="10.0.0.1") / UDP(sport=5353, dport=53)
    ip_payload = bytes(ip)

    wifi_frame = frame_header + llc_header + ip_payload
    buf = radiotap_header + wifi_frame

    rec = parser.parse_packet(9876543210.0, buf, parser.dpkt.pcap.DLT_IEEE802_11_RADIO)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "10.0.0.50"
    assert parser._int_to_ip(rec["dst_ip"]) == "10.0.0.1"
    assert rec["src_port"] == 5353
    assert rec["dst_port"] == 53
    assert rec["l4_protocol"] == "udp"


def test_wifi_datalinks_plain_802_11():
    """Test parsing plain 802.11 frames without Radiotap (DLT_IEEE802_11 = 105)"""
    import struct

    from pcap_parser import parser

    # 802.11 data frame without Radiotap
    frame_control = struct.pack("<H", 0x0841)
    duration = struct.pack("<H", 0)
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr2 = b"\x00\x11\x22\x33\x44\x55"
    addr3 = b"\x66\x77\x88\x99\xaa\xbb"
    seq_ctrl = struct.pack("<H", 0)
    qos_ctrl = struct.pack("<H", 0)

    frame_header = (
        frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + qos_ctrl
    )

    # LLC header for IPv4
    llc_header = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

    # IP payload with ICMP
    ip = IP(src="172.16.0.10", dst="172.16.0.254") / ICMP()
    ip_payload = bytes(ip)

    buf = frame_header + llc_header + ip_payload

    rec = parser.parse_packet(5555555.0, buf, parser.dpkt.pcap.DLT_IEEE802_11)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "172.16.0.10"
    assert parser._int_to_ip(rec["dst_ip"]) == "172.16.0.254"
    assert rec["l4_protocol"] == "icmp"
    assert pd.isna(rec["src_port"])
    assert pd.isna(rec["dst_port"])


def test_wifi_datalinks_pcap_file(tmp_path):
    """Test parsing a complete PCAP file with WiFi Radiotap packets"""
    import struct

    from pcap_parser import parser

    # Create a PCAP file with Radiotap+802.11 packets
    # Using Scapy to generate packets, then manually convert to WiFi format

    pkts = []

    # Generate 3 WiFi packets
    for i in range(3):
        # Minimal Radiotap header
        radiotap_header = struct.pack("<BBHI", 0, 0, 8, 0)

        # 802.11 frame header
        frame_control = struct.pack("<H", 0x0841)
        duration = struct.pack("<H", 0)
        addr1 = b"\xff\xff\xff\xff\xff\xff"
        addr2 = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x50 + i])
        addr3 = b"\x66\x77\x88\x99\xaa\xbb"
        seq_ctrl = struct.pack("<H", i)
        qos_ctrl = struct.pack("<H", 0)

        frame_header = (
            frame_control + duration + addr1 + addr2 + addr3 + seq_ctrl + qos_ctrl
        )

        # LLC header
        llc_header = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

        # Create varied IP packets
        if i == 0:
            ip = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=45000, dport=443)
        elif i == 1:
            ip = IP(src="192.168.1.101", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        else:
            ip = IP(src="192.168.1.102", dst="8.8.8.8") / ICMP()

        ip_payload = bytes(ip)
        wifi_frame = frame_header + llc_header + ip_payload
        buf = radiotap_header + wifi_frame

        # Create Ether wrapper (will be replaced by WiFi datalink in pcap)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / bytes(buf)
        pkts.append(pkt)

    pcap_file = tmp_path / "wifi.pcap"
    wrpcap(str(pcap_file), pkts)

    # Parse with DLT_IEEE802_11_RADIO datalink type
    # Note: We can't directly change the PCAP datalink via scapy wrpcap,
    # so instead test individual packet parsing
    rec1 = parser.parse_packet(
        1000.0, bytes(pkts[0][1]), parser.dpkt.pcap.DLT_IEEE802_11_RADIO
    )
    rec2 = parser.parse_packet(
        2000.0, bytes(pkts[1][1]), parser.dpkt.pcap.DLT_IEEE802_11_RADIO
    )
    rec3 = parser.parse_packet(
        3000.0, bytes(pkts[2][1]), parser.dpkt.pcap.DLT_IEEE802_11_RADIO
    )

    assert rec1 is not None and rec1["l4_protocol"] == "tcp"
    assert rec2 is not None and rec2["l4_protocol"] == "udp"
    assert rec3 is not None and rec3["l4_protocol"] == "icmp"


def test_arp_packet_extraction():
    """Test that ARP packets are parsed and extract sender/target IPs"""
    from pcap_parser import parser

    # Create an ARP request packet
    # sender IP: 192.168.1.100, target IP: 192.168.1.1
    arp = Ether() / ARP(op="who-has", psrc="192.168.1.100", pdst="192.168.1.1")
    buf = bytes(arp)

    rec = parser.parse_packet(1000.0, buf, parser.dpkt.pcap.DLT_EN10MB)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "192.168.1.100"
    assert parser._int_to_ip(rec["dst_ip"]) == "192.168.1.1"
    assert rec["l4_protocol"] == "arp"
    assert pd.isna(rec["src_port"])
    assert pd.isna(rec["dst_port"])


def test_arp_packet_reply():
    """Test ARP reply packet extraction"""
    from pcap_parser import parser

    # Create an ARP reply packet
    # sender IP: 192.168.1.1, target IP: 192.168.1.100
    arp = Ether() / ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.100")
    buf = bytes(arp)

    rec = parser.parse_packet(2000.0, buf, parser.dpkt.pcap.DLT_EN10MB)
    assert rec is not None
    assert parser._int_to_ip(rec["src_ip"]) == "192.168.1.1"
    assert parser._int_to_ip(rec["dst_ip"]) == "192.168.1.100"
    assert rec["l4_protocol"] == "arp"
    assert pd.isna(rec["src_port"])
    assert pd.isna(rec["dst_port"])


def test_arp_mixed_with_ip_packets(tmp_path):
    """Test that ARP and IP packets are both extracted in a mixed PCAP"""
    # Create a PCAP with IP packets and ARP packets
    pkts = []

    # TCP packet
    pkts.append(
        Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / TCP(sport=443, dport=443)
    )

    # ARP request
    pkts.append(Ether() / ARP(op="who-has", psrc="192.168.1.100", pdst="192.168.1.1"))

    # UDP packet
    pkts.append(
        Ether() / IP(src="192.168.1.101", dst="8.8.8.8") / UDP(sport=53, dport=53)
    )

    # ARP reply
    pkts.append(Ether() / ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.100"))

    # ICMP packet
    pkts.append(Ether() / IP(src="192.168.1.102", dst="8.8.8.8") / ICMP())

    pcap_file = tmp_path / "mixed_arp_ip.pcap"
    wrpcap(str(pcap_file), pkts)

    df = parse_pcap(str(pcap_file))

    # Should have 5 packets total (3 IP + 2 ARP)
    assert len(df) == 5

    # Check protocol distribution
    protocols = set(df["l4_protocol"])
    assert "tcp" in protocols
    assert "udp" in protocols
    assert "icmp" in protocols
    assert "arp" in protocols

    # Count ARP packets
    arp_packets = df[df["l4_protocol"] == "arp"]
    assert len(arp_packets) == 2

    # ARP packets should have no ports
    assert pd.isna(arp_packets["src_port"].iloc[0])
    assert pd.isna(arp_packets["dst_port"].iloc[0])

    # Verify ARP IPs were extracted correctly
    arp_ips = set(arp_packets["src_ip"].unique())
    assert "192.168.1.100" in arp_ips
    assert "192.168.1.1" in arp_ips


def test_arp_with_various_ips():
    """Test ARP packet extraction with different IP ranges"""
    from pcap_parser import parser

    test_cases = [
        ("10.0.0.1", "10.0.0.254"),
        ("172.16.0.1", "172.16.0.254"),
        ("192.168.0.1", "192.168.0.255"),
        ("8.8.8.8", "8.8.4.4"),
    ]

    for src_ip, dst_ip in test_cases:
        arp = Ether() / ARP(op="who-has", psrc=src_ip, pdst=dst_ip)
        buf = bytes(arp)

        rec = parser.parse_packet(3000.0, buf, parser.dpkt.pcap.DLT_EN10MB)
        assert rec is not None
        assert parser._int_to_ip(rec["src_ip"]) == src_ip
        assert parser._int_to_ip(rec["dst_ip"]) == dst_ip
        assert rec["l4_protocol"] == "arp"


def test_iter_pcap_yields_packets(tmp_path):
    """Test that iter_pcap yields packet dicts one at a time (streaming)."""
    pcap_file = tmp_path / "stream.pcap"
    create_sample_pcap(str(pcap_file))

    packets = list(iter_pcap(str(pcap_file)))

    assert len(packets) == 3
    assert all(isinstance(p, dict) for p in packets)
    assert packets[0]["src_ip"] == "1.1.1.1"
    assert packets[0]["l4_protocol"] == "tcp"
    assert packets[1]["l4_protocol"] == "udp"
    assert packets[2]["l4_protocol"] == "icmp"
    # Verify IPs are already string format (dotted-quad)
    assert "." in packets[0]["src_ip"]


def test_iter_pcap_empty_file(tmp_path):
    """Test that iter_pcap handles empty/invalid files gracefully."""
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")

    packets = list(iter_pcap(str(empty_file)))
    assert packets == []
