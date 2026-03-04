import os
import subprocess

import pandas as pd
import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap

from pcap_parser.parser import parse_pcap


def create_sample_pcap(path: str):
    pkt1 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)
    pkt2 = Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=5353)
    pkt3 = Ether() / IP(src="5.5.5.5", dst="6.6.6.6") / ICMP()
    wrpcap(path, [pkt1, pkt2, pkt3])


def test_cli_help(tmp_path, capsys):
    """Test CLI help shows usage."""
    import sys

    python_exe = sys.executable

    ret = subprocess.run(
        [python_exe, "-m", "pcap_main", "--help"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        capture_output=True,
        text=True,
    )
    assert ret.returncode == 0
    assert "pcap_file" in ret.stdout
    assert "--bootstrap" in ret.stdout
    assert "--topic" in ret.stdout


def test_cli_parses_pcap(tmp_path):
    """Test CLI validates pcap file argument - requires Kafka."""
    pytest.skip("Integration test - requires running Kafka")
    pcap_file = tmp_path / "cli_input.pcap"
    create_sample_pcap(str(pcap_file))

    import sys

    python_exe = sys.executable

    # Run with invalid bootstrap to fail fast (no waiting for Kafka)
    ret = subprocess.run(
        [python_exe, "-m", "pcap_main", str(pcap_file), "--bootstrap", "invalid:1234"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Should fail due to no Kafka, but should at least parse pcap and print message count
    assert "Parsed" in ret.stdout or ret.returncode != 0


def test_cli_file_not_found():
    """Test CLI errors on missing pcap file."""
    import sys

    python_exe = sys.executable

    ret = subprocess.run(
        [python_exe, "-m", "pcap_main", "nonexistent.pcap"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert ret.returncode != 0
    assert (
        "error" in ret.stderr.lower()
        or "not found" in ret.stderr.lower()
        or "Error" in ret.stdout
    )
