class NetworkConfig:
    """
    Configuration container for network traffic analysis thresholds.

    This class centralizes all tunable detection parameters so that:
    - No magic numbers exist in the code
    - Thresholds are easy to adjust at runtime
    - Tests can override values cleanly
    """

    # Default detection thresholds (class-level constants)
    DEFAULT_PORT_SCAN_THRESHOLD = 25
    DEFAULT_SYN_FLOOD_THRESHOLD = 100
    DEFAULT_PACKET_RATE_THRESHOLD = 1000

    def __init__(
        self,
        port_scan_threshold: int | None = None,
        syn_flood_threshold: int | None = None
    ) -> None:
        """
        Initialize configuration with optional overrides.

        Args:
            port_scan_threshold: Maximum unique ports a source IP can
                                 contact before being flagged as a port scan.
            syn_flood_threshold: Maximum number of TCP SYN packets allowed
                                 from a source IP before flagging a SYN flood.
        """
        self.port_scan_threshold = (
            port_scan_threshold
            if port_scan_threshold is not None
            else self.DEFAULT_PORT_SCAN_THRESHOLD
        )

        self.syn_flood_threshold = (
            syn_flood_threshold
            if syn_flood_threshold is not None
            else self.DEFAULT_SYN_FLOOD_THRESHOLD
        )
def parse_packet_line(line: str) -> dict:
    """
    Parse a single CSV packet log line into a structured dictionary.

    Expected format:
        src_ip,dst_ip,src_port,dst_port,protocol,flags

    Args:
        line: Raw CSV line from traffic log.

    Returns:
        Dictionary containing parsed packet fields.

    Raises:
        ValueError: If the line is malformed or contains invalid values.
    """
    parts = [field.strip() for field in line.split(",")]

    if len(parts) != 6:
        raise ValueError("Invalid packet format: expected 6 fields")

    src_ip, dst_ip, src_port, dst_port, protocol, flags = parts

    try:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": protocol.upper(),
            "flags": flags.upper(),
        }
    except ValueError as exc:
        raise ValueError("Port values must be numeric") from exc

def is_syn_packet(packet: dict) -> bool:
    """
    Determine whether a packet is a TCP SYN packet.

    Args:
        packet: Parsed packet dictionary.

    Returns:
        True if packet is TCP and has SYN flag set, else False.
    """
    return (
        packet.get("protocol") == "TCP"
        and "SYN" in packet.get("flags", "")
    )
def detect_port_scan(packets: list, src_ip: str, threshold: int) -> bool:
    """
    Detect whether a source IP is performing a port scan.

    A port scan is defined as a source IP contacting more unique
    destination ports than the configured threshold.

    Args:
        packets: List of packet dictionaries.
        src_ip: Source IP address to analyze.
        threshold: Unique port count threshold.

    Returns:
        True if port scan detected, else False.
    """
    ports = {
        pkt["dst_port"]
        for pkt in packets
        if pkt.get("src_ip") == src_ip
    }

    return len(ports) > threshold

def detect_syn_flood(packets: list, src_ip: str, threshold: int) -> bool:
    """
    Detect SYN flood activity from a source IP.

    Args:
        packets: List of packet dictionaries.
        src_ip: Source IP address to analyze.
        threshold: SYN packet count threshold.

    Returns:
        True if SYN flood detected, else False.
    """
    syn_count = sum(
        1
        for pkt in packets
        if pkt.get("src_ip") == src_ip and is_syn_packet(pkt)
    )

    return syn_count > threshold
    
def load_traffic_log(filepath: str) -> list:
    """
    Load and parse a network traffic log file.

    This function is responsible ONLY for file I/O and parsing.
    It does not perform any traffic analysis.

    Args:
        filepath: Path to the traffic log file.

    Returns:
        List of parsed packet dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
        ValueError: If a line in the file is malformed.
    """
    packets = []

    with open(filepath, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            # Skip blank lines safely
            if not line:
                continue

            try:
                packet = parse_packet_line(line)
                packets.append(packet)
            except ValueError as exc:
                raise ValueError(
                    f"Error parsing line {line_number}: {exc}"
                ) from exc

    return packets
def analyze_traffic(packets: list, config: NetworkConfig) -> dict:
    """
    Analyze parsed network traffic for suspicious patterns.

    This function contains ONLY analysis logic.
    It performs no file I/O and produces no output.

    Args:
        packets: List of parsed packet dictionaries.
        config: NetworkConfig instance with detection thresholds.

    Returns:
        Dictionary containing analysis results.
    """
    source_ips = {pkt.get("src_ip") for pkt in packets if "src_ip" in pkt}

    port_scans = []
    syn_floods = []

    for src_ip in source_ips:
        if detect_port_scan(
            packets,
            src_ip,
            config.port_scan_threshold
        ):
            port_scans.append(src_ip)

        if detect_syn_flood(
            packets,
            src_ip,
            config.syn_flood_threshold
        ):
            syn_floods.append(src_ip)

    return {
        "total_packets": len(packets),
        "port_scans": port_scans,
        "syn_floods": syn_floods,
    }    