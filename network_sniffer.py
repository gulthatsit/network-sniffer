"""
Basic Network Packet Sniffer
-----------------------------
Captures live network traffic and displays:
  - Source/Destination IP addresses
  - Protocol (TCP, UDP, ICMP, etc.)
  - Port numbers
  - Payload preview (first 80 chars)

Requirements:
  pip install scapy
Run with sudo/admin privileges:
  sudo python network_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from datetime import datetime


# ── Colour codes for terminal output ──────────────────────────────────────────
RESET  = "\033[0m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

# ── Counters to track statistics ───────────────────────────────────────────────
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0, "Total": 0}


def get_protocol_color(proto: str) -> str:
    """Return a colour code based on protocol name."""
    return {
        "TCP":  GREEN,
        "UDP":  CYAN,
        "ICMP": YELLOW,
    }.get(proto, DIM)


def extract_payload(packet) -> str:
    """Extract a readable preview of the packet payload."""
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        try:
            # Try to decode as UTF-8 text (e.g. HTTP)
            decoded = raw_data.decode("utf-8", errors="replace")
            # Take first line or first 80 chars — whichever is shorter
            first_line = decoded.split("\n")[0][:80]
            return first_line.strip()
        except Exception:
            # Fall back to hex representation
            return raw_data[:20].hex()
    return ""


def packet_callback(packet):
    """
    Called automatically for every captured packet.
    Dissects the packet and prints a summary line.
    """
    # We only care about packets with an IP layer
    if not packet.haslayer(IP):
        return

    stats["Total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    ip_layer  = packet[IP]
    src_ip    = ip_layer.src
    dst_ip    = ip_layer.dst

    # ── Determine protocol and ports ──────────────────────────────────────────
    if packet.haslayer(TCP):
        proto    = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags  # e.g. SYN, ACK, FIN
        extra    = f"flags={flags}"
        stats["TCP"] += 1

    elif packet.haslayer(UDP):
        proto    = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        extra    = ""
        stats["UDP"] += 1

        # Special case: parse DNS queries (UDP port 53)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            queried = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            extra   = f"DNS query → {queried}"

    elif packet.haslayer(ICMP):
        proto    = "ICMP"
        src_port = "-"
        dst_port = "-"
        icmp_type = packet[ICMP].type
        extra    = f"type={icmp_type}"  # 8=echo request, 0=echo reply
        stats["ICMP"] += 1

    else:
        # Unknown / other IP protocol
        proto    = f"IP({ip_layer.proto})"
        src_port = "-"
        dst_port = "-"
        extra    = ""
        stats["Other"] += 1

    # ── Payload preview ───────────────────────────────────────────────────────
    payload = extract_payload(packet)
    payload_str = f'  payload="{payload}"' if payload else ""

    # ── Format and print the packet summary ───────────────────────────────────
    color = get_protocol_color(proto)
    proto_tag = f"{color}{BOLD}{proto:<5}{RESET}"

    print(
        f"{DIM}[{timestamp}]{RESET} "
        f"{proto_tag} "
        f"{src_ip}:{src_port}  →  {dst_ip}:{dst_port}"
        + (f"  {DIM}{extra}{RESET}" if extra else "")
        + (f"\n         {DIM}{payload_str}{RESET}" if payload_str else "")
    )


def print_stats():
    """Print a summary of captured packet counts."""
    print(f"\n{BOLD}{'─'*50}")
    print("  Capture Summary")
    print(f"{'─'*50}{RESET}")
    for key, val in stats.items():
        bar = "█" * min(val, 40)
        print(f"  {key:<8}: {val:>5}  {GREEN}{bar}{RESET}")
    print(f"{BOLD}{'─'*50}{RESET}\n")


def main():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════╗
║      Basic Network Packet Sniffer    ║
╚══════════════════════════════════════╝{RESET}

  Capturing packets... Press {BOLD}Ctrl+C{RESET} to stop.
  Tip: Open a browser or run 'ping google.com' to generate traffic.
{'─'*42}
""")

    try:
        # sniff() is the core Scapy function:
        #   prn      = function called for each packet
        #   store    = False means don't keep packets in memory
        #   filter   = BPF filter string (like Wireshark filters)
        #              "ip" means only capture IP packets
        sniff(
            prn=packet_callback,
            store=False,
            filter="ip",        # Only IP traffic (removes noise like ARP)
        )
    except KeyboardInterrupt:
        print_stats()
    except PermissionError:
        print(f"\n{RED}Permission denied.{RESET} Run with sudo:\n  sudo python network_sniffer.py\n")


if __name__ == "__main__":
    main()
