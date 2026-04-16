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
    