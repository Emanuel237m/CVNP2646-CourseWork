import pytest
from types import SimpleNamespace

from network_monitor import (
    NetworkConfig,
    parse_packet_line,
    is_syn_packet,
    detect_port_scan,
    detect_syn_flood,
    analyze_traffic,
    main,
)
@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return NetworkConfig(
        port_scan_threshold=25,
        syn_flood_threshold=100
    )


@pytest.fixture
def valid_packet_line():
    """Sample valid packet log line."""
    return "192.168.1.5,10.0.0.1,54321,443,TCP,SYN"


@pytest.fixture
def sample_packets():
    """Sample parsed packets."""
    return [
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "SYN",
        },
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.2",
            "src_port": 54322,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "SYN",
        },
    ]
def test_parse_valid_packet(valid_packet_line):
    """Valid packet line parses correctly."""
    packet = parse_packet_line(valid_packet_line)

    assert packet["src_ip"] == "192.168.1.5"
    assert packet["dst_ip"] == "10.0.0.1"
    assert packet["src_port"] == 54321
    assert packet["dst_port"] == 443
    assert packet["protocol"] == "TCP"
    assert packet["flags"] == "SYN"

def test_parse_too_few_fields():
    """Packet with too few fields raises ValueError."""
    with pytest.raises(ValueError):
        parse_packet_line("192.168.1.5,10.0.0.1,443")

def test_parse_non_numeric_port():
    """Non-numeric ports raise ValueError."""
    with pytest.raises(ValueError):
        parse_packet_line(
            "192.168.1.5,10.0.0.1,abc,443,TCP,SYN"
        )
def test_port_scan_below_threshold(sample_packets, sample_config):
    """No port scan when below threshold."""
    result = detect_port_scan(
        sample_packets,
        "192.168.1.5",
        sample_config.port_scan_threshold
    )
    assert result is False
def test_port_scan_above_threshold(sample_config):
    """Port scan detected when over threshold."""
    packets = [
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "dst_port": port,
            "protocol": "TCP",
            "flags": "SYN",
        }
        for port in range(1, 31)
    ]

    result = detect_port_scan(
        packets,
        "192.168.1.5",
        sample_config.port_scan_threshold
    )
    assert result is True

def test_syn_flood_detection(sample_config):
    """SYN flood detected correctly."""
    packets = [
        {
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 10000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "SYN",
        }
        for i in range(101)
    ]

    assert detect_syn_flood(
        packets,
        "192.168.1.5",
        sample_config.syn_flood_threshold
    ) is True
def test_analyze_traffic_full_pipeline(
    sample_packets,
    sample_config
):
    """Full traffic analysis returns correct structure."""
    results = analyze_traffic(sample_packets, sample_config)

    assert results["total_packets"] == len(sample_packets)
    assert isinstance(results["port_scans"], list)
    assert isinstance(results["syn_floods"], list)

def test_analyze_empty_traffic(sample_config):
    """Empty traffic returns safe defaults."""
    results = analyze_traffic([], sample_config)

    assert results["total_packets"] == 0
    assert results["port_scans"] == []
    assert results["syn_floods"] == []
def test_main_success(tmp_path):
    """main() returns 0 on success."""
    traffic_file = tmp_path / "traffic.log"
    traffic_file.write_text(
        "192.168.1.5,10.0.0.1,12345,80,TCP,SYN\n"
    )

    args = SimpleNamespace(
        input_file=str(traffic_file),
        port_scan_threshold=25,
        syn_flood_threshold=100,
        log_level="INFO",
    )

    exit_code = main(args)
    assert exit_code == 0
