"""
PCAP Analyzer - a single-file Flask web app.

Upload a .pcap, .pcapng or .cap capture through a web form and get a traffic
summary produced with scapy: protocol breakdown, top talkers, conversations,
ports, DNS queries, HTTP requests, TLS SNI, and a few simple security
indicators (port scans, cleartext credentials, ARP spoofing hints).

Run:
    pip install flask scapy
    python app.py            # then open http://127.0.0.1:5000
"""

import os
import socket
import struct
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

from flask import Flask, flash, redirect, render_template_string, request, url_for
from werkzeug.exceptions import BadRequest, InternalServerError, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# Keep scapy quiet and avoid it touching network interfaces at import time.
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, PcapReader  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402

try:  # TLS dissection is optional; fall back to manual SNI parsing.
    from scapy.layers.tls.all import TLS  # noqa: F401
except Exception:  # pragma: no cover
    TLS = None

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
MAX_UPLOAD_MB = 50
MAX_PACKETS = 200_000  # hard cap on packets analyzed, protects the server
TOP_N = 10

# Magic numbers for pcap (both endiannesses, micro/nano second) and pcapng.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",  # pcapng Section Header Block
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024  # rejects bigger uploads
app.config["DEBUG"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False  # route errors to the 500 handler
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return "n/a"


def extract_sni(payload: bytes):
    """Pull the Server Name Indication out of a raw TLS ClientHello, if present."""
    try:
        # TLS record: type 0x16 (handshake), handshake type 0x01 (ClientHello)
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 43  # 5 record hdr + 4 hs hdr + 2 version + 32 random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000:  # server_name
                # list len (2), name type (1), name len (2), name
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                return payload[pos + 5:pos + 5 + name_len].decode("ascii", "replace")
            pos += ext_len
    except (IndexError, ValueError):
        return None
    return None


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def parse_http_request(payload: bytes):
    if not payload.startswith(HTTP_METHODS):
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    except Exception:
        return None
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "method": parts[0],
        "path": parts[1][:200],
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", "")[:120],
        "has_auth": "authorization" in headers,
    }


CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP"}

# Well-known service names, keyed by (transport, port). Ports that are the
# same service on both TCP and UDP are listed under both.
_COMMON = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS-SSN", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}
_UDP_ONLY = {
    67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 123: "NTP",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-Trap",
    443: "QUIC", 500: "IKE", 514: "Syslog", 1900: "SSDP", 4500: "IPsec-NAT-T",
    5353: "mDNS", 5355: "LLMNR",
}
SERVICES = {("TCP", p): n for p, n in _COMMON.items()}
SERVICES.update({("UDP", p): n for p, n in _COMMON.items()})
SERVICES.update({("UDP", p): n for p, n in _UDP_ONLY.items()})


def service_name(proto: str, port: int) -> str:
    if (proto, port) in SERVICES:
        return SERVICES[(proto, port)]
    try:  # fall back to the OS services database (/etc/services)
        return socket.getservbyport(port, proto.lower()).upper()
    except (OSError, OverflowError, TypeError):
        return "Ephemeral" if port >= 49152 else "Unknown"
CRED_MARKERS = (b"USER ", b"PASS ", b"AUTH ", b"LOGIN ")


# --------------------------------------------------------------------------- #
# Capture integrity check
# --------------------------------------------------------------------------- #
# scapy silently accepts truncated or corrupted captures, so before analysis
# we walk the file's record structure ourselves. This only reads headers and
# seeks over packet data, so it's fast even for large files.
MAX_RECORD_LEN = 262_144  # largest sane packet record (tcpdump's max snaplen)
PCAPNG_PACKET_BLOCKS = {0x00000002, 0x00000003, 0x00000006}  # PB, SPB, EPB


class CaptureError(Exception):
    """The capture is unreadable; the message is safe to show to the user."""


def check_capture(path: str):
    """Validate a pcap/pcapng file's structure.

    Returns (intact_packets, problem): the number of packets before any damage
    and a description of the damage (None if the file is intact).
    Raises CaptureError if the file header itself is invalid.
    """
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            return _check_pcapng(fh, file_size)
        return _check_pcap(fh, magic, file_size)


def _check_pcap(fh, magic, file_size):
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
              b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        raise CaptureError("Unrecognized capture format.")
    header = fh.read(20)
    if len(header) < 20:
        raise CaptureError("The capture's file header is incomplete.")
    major, _minor, _zone, _sigfigs, snaplen, _linktype = struct.unpack(endian + "HHiIII", header)
    if major != 2:
        raise CaptureError("The capture's file header is corrupted (bad version).")
    limit = max(snaplen, MAX_RECORD_LEN) if snaplen else MAX_RECORD_LEN

    packets, pos = 0, 24
    while pos < file_size:
        rec = fh.read(16)
        if len(rec) < 16:
            return packets, f"the file ends in the middle of packet #{packets + 1}'s header"
        _sec, _usec, caplen, _origlen = struct.unpack(endian + "IIII", rec)
        if caplen > limit:
            return packets, f"packet #{packets + 1} has an impossible length ({caplen:,} bytes)"
        if pos + 16 + caplen > file_size:
            return packets, f"the file ends in the middle of packet #{packets + 1}"
        pos += 16 + caplen
        fh.seek(pos)
        packets += 1
    return packets, None


def _check_pcapng(fh, file_size):
    fh.seek(0)
    endian, packets, pos, block_no = None, 0, 0, 0
    while pos < file_size:
        block_no += 1
        head = fh.read(8)
        if len(head) < 8:
            return packets, f"the file ends in the middle of block #{block_no}"
        if head[:4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block: (re)sets byte order
            bom = fh.read(4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if endian is None:
                if block_no == 1:
                    raise CaptureError("The pcapng section header is corrupted.")
                return packets, f"section header in block #{block_no} is corrupted"
        elif endian is None:
            raise CaptureError("The pcapng file does not start with a section header.")
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12 or blen % 4 or blen > MAX_RECORD_LEN + 4096:
            if block_no == 1:
                raise CaptureError("The pcapng section header is corrupted.")
            return packets, f"block #{block_no} has an invalid length ({blen:,} bytes)"
        if pos + blen > file_size:
            return packets, f"the file ends in the middle of block #{block_no}"
        fh.seek(pos + blen - 4)
        (trailer,) = struct.unpack(endian + "I", fh.read(4))
        if trailer != blen:
            return packets, f"block #{block_no} is corrupted (length fields disagree)"
        if btype in PCAPNG_PACKET_BLOCKS:
            packets += 1
        pos += blen
    return packets, None


# --------------------------------------------------------------------------- #
# Dashboard helpers
# --------------------------------------------------------------------------- #
# Fixed category order for the traffic-mix pie. Every packet lands in exactly
# one category, so the slices add up to 100%. The order is also the color
# order, so a category keeps the same color across every capture.
MIX_ORDER = ["HTTPS", "HTTP", "DNS", "Other TCP", "Other UDP", "ICMP", "ARP", "Other"]


def classify_packet(pkt, l4, sport, dport, is_http) -> str:
    ports = {sport, dport}
    if pkt.haslayer(DNS):
        return "DNS"
    if l4 == "TCP":
        if ports & {443, 8443}:
            return "HTTPS"
        if is_http or ports & {80, 8080}:
            return "HTTP"
        return "Other TCP"
    if l4 == "UDP":
        return "Other UDP"
    if l4 in ("ICMP", "ICMPv6"):
        return "ICMP"
    return "Other"


NICE_BIN_SECONDS = [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30,
                    60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400]


def bin_timeline(timeline, target_bins=60):
    """Bucket (ts, length) pairs into evenly sized time bins for the line chart."""
    if not timeline:
        return {"labels": [], "packets": [], "bytes": [], "bin_label": "n/a"}
    start = min(t for t, _ in timeline)
    end = max(t for t, _ in timeline)
    span = max(end - start, 1e-9)
    width = next((w for w in NICE_BIN_SECONDS if span / w <= target_bins), NICE_BIN_SECONDS[-1])
    n_bins = int(span // width) + 1
    packets = [0] * n_bins
    byts = [0] * n_bins
    for t, length in timeline:
        i = min(int((t - start) // width), n_bins - 1)
        packets[i] += 1
        byts[i] += length
    if width < 1:
        fmt, trim = "%H:%M:%S.%f", True
    else:
        fmt, trim = "%H:%M:%S" if span < 86400 else "%m-%d %H:%M", False
    labels = []
    for i in range(n_bins):
        s = datetime.fromtimestamp(start + i * width, tz=timezone.utc).strftime(fmt)
        labels.append(s[:-3] if trim else s)
    bin_label = f"{width * 1000:g} ms" if width < 1 else f"{width:g} s"
    return {"labels": labels, "packets": packets, "bytes": byts, "bin_label": bin_label}


# Plain-language protocol definitions. "match" lists every protocol/service
# name in the analysis that should mark the entry as present in the capture.
GLOSSARY = [
    ("Ethernet", "Link", {"Ethernet"},
     "The local-network framing layer. Each frame carries source and destination MAC "
     "(hardware) addresses so devices on the same LAN segment can deliver packets to each other."),
    ("ARP", "Link", {"ARP"},
     "Address Resolution Protocol. Maps an IPv4 address to a MAC address on the local network "
     "(\"who has 10.0.0.1?\"). It has no authentication, so attackers can forge replies (ARP spoofing)."),
    ("IPv4", "Network", {"IPv4"},
     "Internet Protocol version 4. Gives every packet a 32-bit source and destination address "
     "(e.g. 192.168.1.10) and routes it across networks."),
    ("IPv6", "Network", {"IPv6"},
     "Internet Protocol version 6. The successor to IPv4, using 128-bit addresses "
     "(e.g. fe80::1) to solve address exhaustion."),
    ("ICMP / ICMPv6", "Network", {"ICMP", "ICMPv6"},
     "Internet Control Message Protocol. Carries error and diagnostic messages, such as the echo "
     "request and reply used by ping, and \"destination unreachable\" notices."),
    ("TCP", "Transport", {"TCP", "Other TCP"},
     "Transmission Control Protocol. A reliable, ordered, connection-based stream. Connections "
     "open with a SYN / SYN-ACK / ACK handshake. Used by the web, email, SSH and file transfer."),
    ("UDP", "Transport", {"UDP", "Other UDP"},
     "User Datagram Protocol. Connectionless and lightweight, with no delivery guarantee. Used "
     "where speed matters more than reliability: DNS, streaming, VoIP, games."),
    ("DNS", "Application", {"DNS"},
     "Domain Name System (port 53). Translates names like example.com into IP addresses. Queries "
     "are usually unencrypted, so they show which sites a device looks up."),
    ("HTTP", "Application", {"HTTP", "HTTP-Alt"},
     "Hypertext Transfer Protocol (port 80). The web's request/response protocol. Plain HTTP is "
     "unencrypted, so URLs, headers, cookies and passwords are readable on the wire."),
    ("HTTPS / TLS", "Application", {"HTTPS", "TLS", "HTTPS-Alt"},
     "HTTP carried inside Transport Layer Security (port 443). The content is encrypted, but the "
     "server name (SNI) in the first ClientHello message is usually still visible."),
    ("QUIC", "Application", {"QUIC"},
     "A UDP-based encrypted transport (UDP 443) used by HTTP/3. Combines TCP-like reliability "
     "with TLS 1.3 encryption."),
    ("FTP", "Application", {"FTP", "FTP-Data"},
     "File Transfer Protocol (ports 20/21). Transfers files, and sends usernames and passwords "
     "in cleartext."),
    ("SSH", "Application", {"SSH"},
     "Secure Shell (port 22). Encrypted remote login and command execution. Repeated connection "
     "attempts often indicate brute-forcing."),
    ("Telnet", "Application", {"Telnet"},
     "An old remote-terminal protocol (port 23) with no encryption. Every keystroke, including "
     "passwords, travels in cleartext."),
    ("SMTP", "Application", {"SMTP", "SMTPS", "SMTP-Submission"},
     "Simple Mail Transfer Protocol (ports 25, 465, 587). Sends email between clients and "
     "mail servers."),
    ("POP3", "Application", {"POP3", "POP3S"},
     "Post Office Protocol v3 (port 110, or 995 over TLS). Downloads email from a mailbox. "
     "The plain version sends credentials in cleartext."),
    ("IMAP", "Application", {"IMAP", "IMAPS"},
     "Internet Message Access Protocol (port 143, or 993 over TLS). Reads and syncs email that "
     "stays on the server."),
    ("SMB", "Application", {"SMB"},
     "Server Message Block (port 445). Windows file and printer sharing. A common target for "
     "lateral movement and ransomware."),
    ("NetBIOS", "Application", {"NetBIOS-NS", "NetBIOS-DGM", "NetBIOS-SSN"},
     "Legacy Windows naming and session services (ports 137-139) used by older file sharing."),
    ("DHCP", "Application", {"DHCP-Server", "DHCP-Client"},
     "Dynamic Host Configuration Protocol (UDP 67/68). Automatically hands out IP addresses, "
     "gateways and DNS servers to devices joining a network."),
    ("NTP", "Application", {"NTP"},
     "Network Time Protocol (UDP 123). Keeps device clocks synchronized."),
    ("SNMP", "Application", {"SNMP", "SNMP-Trap"},
     "Simple Network Management Protocol (UDP 161/162). Monitors and manages network devices. "
     "v1/v2c use plaintext \"community strings\" as passwords."),
    ("mDNS / LLMNR", "Application", {"mDNS", "LLMNR"},
     "Multicast DNS (UDP 5353) and Link-Local Multicast Name Resolution (5355). Name lookups on "
     "the local network without a DNS server. LLMNR can be abused to capture credentials."),
    ("SSDP", "Application", {"SSDP"},
     "Simple Service Discovery Protocol (UDP 1900). Part of UPnP, used by devices such as "
     "printers and smart TVs to announce themselves."),
    ("LDAP", "Application", {"LDAP", "LDAPS"},
     "Lightweight Directory Access Protocol (port 389, or 636 over TLS). Queries directories "
     "such as Active Directory for users and groups."),
    ("Kerberos", "Application", {"Kerberos"},
     "Ticket-based network authentication (port 88) used by Active Directory."),
    ("RDP", "Application", {"RDP"},
     "Remote Desktop Protocol (port 3389). Graphical remote access to Windows machines. "
     "Exposed RDP is a frequent attack target."),
    ("Databases", "Application", {"MySQL", "PostgreSQL", "MS-SQL", "Oracle", "Redis",
                                  "MongoDB", "Elasticsearch"},
     "Database protocols such as MySQL (3306), PostgreSQL (5432), MS-SQL (1433), Redis (6379) "
     "and MongoDB (27017). They should rarely be reachable from outside a network."),
]


def build_glossary(seen_names):
    entries = []
    for name, layer, match, text in GLOSSARY:
        entries.append({"name": name, "layer": layer, "text": text,
                        "seen": bool(match & seen_names)})
    entries.sort(key=lambda e: not e["seen"])  # stable: seen first, original order kept
    return entries


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def analyze_pcap(path: str, intact_packets=None) -> dict:
    """Analyze a capture. `intact_packets` (from check_capture) stops reading
    before any damaged region; MAX_PACKETS is always enforced on top of it."""
    stop_at = MAX_PACKETS if intact_packets is None else min(MAX_PACKETS, intact_packets)
    total_packets = 0
    total_bytes = 0
    first_ts = last_ts = None
    truncated = False

    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    ip_packets = Counter()  # packets sent + received per host
    ip_bytes = Counter()  # bytes sent + received per host
    # Host-pair conversations, keyed by the sorted (ip_a, ip_b) pair.
    conversations = defaultdict(
        lambda: {"packets": 0, "bytes": 0, "a_to_b": 0, "b_to_a": 0, "protos": set()}
    )
    dst_ports = Counter()  # (transport, port) -> packets
    dns_queries = Counter()
    http_requests = []
    tls_sni = Counter()
    mac_addrs = Counter()

    # Security indicators
    syn_targets = defaultdict(set)  # src ip -> {(dst, dport)} for bare SYNs
    cleartext_creds = []
    arp_map = defaultdict(set)  # ip -> {mac}
    icmp_count = Counter()

    # Dashboard data
    traffic_mix = Counter()  # one exclusive category per packet (for the pie)
    timeline = []  # (timestamp, length) per packet (for the line chart)

    with PcapReader(path) as reader:
        for pkt in reader:
            if total_packets >= stop_at:
                truncated = total_packets >= MAX_PACKETS
                break
            total_packets += 1
            plen = len(pkt)
            total_bytes += plen

            ts = float(getattr(pkt, "time", 0) or 0)
            if ts:
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)
                timeline.append((ts, plen))

            if pkt.haslayer(Ether):
                mac_addrs[pkt[Ether].src] += 1

            # --- ARP ---------------------------------------------------------
            if pkt.haslayer(ARP):
                protocols["ARP"] += 1
                traffic_mix["ARP"] += 1
                arp = pkt[ARP]
                if arp.op == 2:  # is-at (reply)
                    arp_map[arp.psrc].add(arp.hwsrc)
                continue

            # --- Network layer ----------------------------------------------
            src = dst = None
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
                protocols["IPv4"] += 1
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
                protocols["IPv6"] += 1
            else:
                protocols[pkt.lastlayer().name or "Other"] += 1
                traffic_mix["Other"] += 1
                continue

            src_ips[src] += 1
            dst_ips[dst] += 1
            ip_packets[src] += 1
            ip_bytes[src] += plen
            if dst != src:
                ip_packets[dst] += 1
                ip_bytes[dst] += plen

            # --- Transport layer --------------------------------------------
            sport = dport = None
            l4 = "Other-L4"
            if pkt.haslayer(TCP):
                l4 = "TCP"
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                # Count only client->server packets (dport <= sport) so that
                # replies to random ephemeral client ports don't crowd the list.
                if dport <= sport:
                    dst_ports[("TCP", dport)] += 1
                flags = int(tcp.flags)
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    syn_targets[src].add((dst, dport))
            elif pkt.haslayer(UDP):
                l4 = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                if dport <= sport:
                    dst_ports[("UDP", dport)] += 1
            elif pkt.haslayer(ICMP):
                l4 = "ICMP"
                icmp_count[src] += 1
            elif pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
                l4 = "ICMPv6"
            protocols[l4] += 1
            is_http = False

            a, b = sorted((src, dst))
            conv = conversations[(a, b)]
            conv["packets"] += 1
            conv["bytes"] += plen
            conv["a_to_b" if src == a else "b_to_a"] += 1
            conv["protos"].add(l4)

            # --- Application layer ------------------------------------------
            if pkt.haslayer(DNS):
                protocols["DNS"] += 1
                dns = pkt[DNS]
                if dns.qr == 0 and dns.haslayer(DNSQR):
                    try:
                        name = dns[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
                        dns_queries[name] += 1
                    except Exception:
                        pass

            if pkt.haslayer(Raw) and l4 == "TCP":
                payload = bytes(pkt[Raw].load)

                http = parse_http_request(payload)
                if http:
                    is_http = True
                    protocols["HTTP"] += 1
                    if len(http_requests) < 200:
                        http["src"] = src
                        http["dst"] = f"{dst}:{dport}"
                        http_requests.append(http)
                    if http["has_auth"]:
                        cleartext_creds.append(
                            {"proto": "HTTP", "src": src, "dst": f"{dst}:{dport}",
                             "detail": "Authorization header sent over plain HTTP"}
                        )

                if dport == 443 or sport == 443 or payload[:1] == b"\x16":
                    sni = extract_sni(payload)
                    if sni:
                        protocols["TLS"] += 1
                        tls_sni[sni] += 1

                port = dport if dport in CLEARTEXT_PORTS else sport if sport in CLEARTEXT_PORTS else None
                if port and payload.upper().startswith(CRED_MARKERS) and len(cleartext_creds) < 100:
                    line = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                    verb = line.split(" ", 1)[0].upper()
                    # Mask the actual secret; show only that it was observed.
                    shown = line if verb in ("USER", "LOGIN") else f"{verb} ********"
                    cleartext_creds.append(
                        {"proto": CLEARTEXT_PORTS[port], "src": src,
                         "dst": f"{dst}:{dport}", "detail": shown[:120]}
                    )

            traffic_mix[classify_packet(pkt, l4, sport, dport, is_http)] += 1

    duration =(last_ts - first_ts) if first_ts is not None and last_ts is not None else 0

    # --- Build alerts --------------------------------------------------------
    alerts = []
    for src, targets in syn_targets.items():
        ports = {p for _, p in targets}
        hosts = {h for h, _ in targets}
        if len(ports) >= 20:
            alerts.append(("high", f"Possible port scan from {src}: SYNs to {len(ports)} "
                                   f"distinct ports across {len(hosts)} host(s)."))
        elif len(hosts) >= 20:
            alerts.append(("medium", f"Possible host sweep from {src}: SYNs to "
                                     f"{len(hosts)} distinct hosts."))
    for ip, macs in arp_map.items():
        if len(macs) > 1:
            alerts.append(("high", f"Possible ARP spoofing: {ip} claimed by "
                                   f"{len(macs)} MACs ({', '.join(sorted(macs))})."))
    for src, n in icmp_count.items():
        if n >= 100:
            alerts.append(("medium", f"High ICMP volume from {src}: {n} packets."))
    if cleartext_creds:
        alerts.append(("high", f"{len(cleartext_creds)} cleartext credential "
                               f"exchange(s) observed (see table below)."))
    if truncated:
        alerts.append(("info", f"Capture truncated: only the first {MAX_PACKETS:,} "
                               f"packets were analyzed."))

    top_convs = sorted(
        conversations.items(), key=lambda kv: (kv[1]["packets"], kv[1]["bytes"]), reverse=True
    )[:TOP_N]

    top_ports = [
        {"proto": proto, "port": port, "service": service_name(proto, port), "packets": n}
        for (proto, port), n in dst_ports.most_common(TOP_N)
    ]
    mix_total = sum(traffic_mix.values()) or 1
    mix_rows = [
        {"label": cat, "value": traffic_mix[cat], "slot": MIX_ORDER.index(cat) + 1,
         "pct": f"{100 * traffic_mix[cat] / mix_total:.1f}%"}
        for cat in MIX_ORDER if traffic_mix[cat]
    ]
    seen_names = set(protocols) | set(traffic_mix)
    if mac_addrs:
        seen_names.add("Ethernet")
    seen_names |={service_name(proto, port) for proto, port in dst_ports}

    def host_row(ip):
        return {"ip": ip, "packets": ip_packets[ip], "bytes": human_bytes(ip_bytes[ip])}

    return {
        "total_packets": total_packets,
        "total_bytes": human_bytes(total_bytes),
        "avg_size": f"{(total_bytes / total_packets):.0f} B" if total_packets else "n/a",
        "start": fmt_ts(first_ts),
        "end": fmt_ts(last_ts),
        "duration": f"{duration:.2f} s",
        "pps": f"{(total_packets / duration):.1f}" if duration > 0 else "n/a",
        "unique_ips": len(set(src_ips) | set(dst_ips)),
        "unique_macs": len(mac_addrs),
        "protocols": protocols.most_common(),
        "max_proto": max(protocols.values()) if protocols else 1,
        "top_src": src_ips.most_common(TOP_N),
        "top_dst": dst_ips.most_common(TOP_N),
        "busiest_by_packets": [host_row(ip) for ip, _ in ip_packets.most_common(TOP_N)],
        "busiest_by_bytes": [host_row(ip) for ip, _ in ip_bytes.most_common(TOP_N)],
        "conversations": [
            {"a": a, "b": b, "packets": v["packets"], "bytes": human_bytes(v["bytes"]),
             "a_to_b": v["a_to_b"], "b_to_a": v["b_to_a"],
             "protos": ", ".join(sorted(v["protos"]))}
            for (a, b), v in top_convs
        ],
        "dst_ports": top_ports,
        "dns_queries": dns_queries.most_common(25),
        "http_requests": http_requests[:50],
        "tls_sni": tls_sni.most_common(25),
        "cleartext_creds": cleartext_creds,
        "alerts": alerts,
        "mix_table": mix_rows,
        "chart": {
            "mix": mix_rows,
            "services": [
                {"label": f"{p['port']} {p['service']} ({p['proto']})", "value": p["packets"]}
                for p in top_ports
            ],
            "timeline": bin_timeline(timeline),
        },
        "glossary": build_glossary(seen_names),
        "truncated": truncated,
    }


# --------------------------------------------------------------------------- #
# Templates (Jinja autoescaping is on for render_template_string)
# --------------------------------------------------------------------------- #
BASE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCAP Analyzer</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --fg:#e2e8f0; --muted:#94a3b8;
          --accent:#38bdf8; --border:#334155; --high:#f87171; --med:#fbbf24; --info:#60a5fa; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         background:var(--bg); color:var(--fg); line-height:1.5; }
  header { padding:20px 24px; border-bottom:1px solid var(--border); }
  header a { color:var(--fg); text-decoration:none; font-weight:700; font-size:1.25rem; }
  main { max-width:1200px; margin:0 auto; padding:24px 16px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px;
          padding:18px 20px; margin-bottom:20px; overflow-x:auto; }
  h2 { margin:0 0 12px; font-size:1.05rem; color:var(--accent); }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:20px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .stat { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
  .stat .k { color:var(--muted); font-size:.8rem; } .stat .v { font-size:1.15rem; font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:.9rem; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; }
  th.num, td.num { text-align:right; font-variant-numeric:tabular-nums; }
  code, .mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.85rem; word-break:break-all; }
  .bar { height:8px; background:var(--accent); border-radius:4px; }
  .alert { padding:10px 12px; border-left:4px solid; border-radius:4px; margin-bottom:8px; background:var(--bg); }
  .alert.high { border-color:var(--high); } .alert.medium { border-color:var(--med); }
  .alert.info { border-color:var(--info); }
  .flash { background:#7f1d1d; border:1px solid var(--high); padding:10px 12px; border-radius:6px; margin-bottom:16px; }
  form { display:flex; flex-wrap:wrap; gap:12px; align-items:center; }
  input[type=file] { color:var(--fg); }
  button, .btn { background:var(--accent); color:#0f172a; border:0; padding:9px 18px; border-radius:6px;
                 font-weight:600; cursor:pointer; text-decoration:none; display:inline-block; }
  .muted { color:var(--muted); }

  /* ---- Dashboard ---- */
  :root { --grid:#2a3649; --border-strong:#64748b;
          /* categorical series (slot order = MIX_ORDER), checked for adjacent-pair CVD
             separation and >=3:1 contrast on the dark card surface; slot 8 "Other" is neutral */
          --series-1:#3987e5; --series-2:#d95926; --series-3:#199e70; --series-4:#c98500;
          --series-5:#d55181; --series-6:#9085e9; --series-7:#e66767; --series-8:#8a94a6;
          --series-1-fill:rgba(57,135,229,.15); }
  main { max-width:1280px; }
  .nav { display:flex; flex-wrap:wrap; gap:6px; margin:-4px 0 20px; }
  .nav a { color:var(--muted); text-decoration:none; font-size:.85rem; padding:4px 10px;
           border:1px solid var(--border); border-radius:999px; }
  .nav a:hover { color:var(--fg); border-color:var(--border-strong); }
  .sub { color:var(--muted); font-size:.85rem; margin:-6px 0 12px; }
  .card-head { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:10px; }
  .card-head h2 { margin-bottom:12px; }
  .chart-box { position:relative; height:280px; }
  .chart-box.tall { height:320px; }
  .mix-wrap { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:16px; align-items:center; }
  .mix-wrap .chart-box { height:240px; }
  @media (max-width:640px) { .mix-wrap { grid-template-columns:1fr; } }
  .swatch { display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:8px; vertical-align:middle; }
  table.compact td, table.compact th { padding:4px 6px; }
  .seg { display:inline-flex; border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-bottom:12px; }
  .seg button { background:transparent; color:var(--muted); border-radius:0; padding:5px 14px; font-weight:500; }
  .seg button[aria-pressed="true"] { background:var(--bg); color:var(--fg); }
  .gloss { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:12px; }
  .term { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
  .term.seen { border-color:var(--border-strong); }
  .term p { margin:6px 0 0; font-size:.88rem; color:var(--muted); }
  .term-head { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
  .layer { font-size:.72rem; color:var(--muted); border:1px solid var(--border); border-radius:999px; padding:0 8px; }
  .badge { font-size:.72rem; color:#0f172a; background:var(--accent); border-radius:999px; padding:0 8px; font-weight:600; }
  .gloss.only-seen .term:not(.seen) { display:none; }
  .toggle { display:inline-flex; align-items:center; gap:6px; font-size:.85rem; color:var(--muted); margin-bottom:12px; cursor:pointer; }
</style>
</head>
<body>
<header><a href="{{ url_for('index') }}">PCAP Analyzer</a></header>
<main>
  {% with msgs = get_flashed_messages() %}
    {% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
  {% endwith %}
  {{ body|safe }}
</main>
</body>
</html>
"""

INDEX = """
<div class="card">
  <h2>Upload a capture</h2>
  <p class="muted">Accepted: .pcap, .pcapng, .cap &middot; Max {{ max_mb }} MB &middot;
     up to {{ "{:,}".format(max_pkts) }} packets analyzed.</p>
  <form method="post" action="{{ url_for('analyze') }}" enctype="multipart/form-data">
    <input type="file" name="pcap" accept=".pcap,.pcapng,.cap" required>
    <button type="submit">Analyze</button>
  </form>
</div>
"""

RESULTS = """
<nav class="nav" aria-label="Dashboard sections">
  <a href="#overview">Overview</a><a href="#charts">Charts</a><a href="#hosts">Hosts &amp; ports</a>
  <a href="#conversations">Conversations</a><a href="#content">DNS / TLS / HTTP</a>
  <a href="#definitions">Protocol definitions</a>
</nav>

{% if damage %}<div class="flash" role="alert"><strong>Warning:</strong> {{ damage }}</div>{% endif %}

<div class="card" id="overview">
  <h2>Summary &mdash; <span class="mono">{{ filename }}</span></h2>
  <div class="stats">
    <div class="stat"><div class="k">Packets</div><div class="v">{{ "{:,}".format(r.total_packets) }}</div></div>
    <div class="stat"><div class="k">Total size</div><div class="v">{{ r.total_bytes }}</div></div>
    <div class="stat"><div class="k">Avg packet</div><div class="v">{{ r.avg_size }}</div></div>
    <div class="stat"><div class="k">Duration</div><div class="v">{{ r.duration }}</div></div>
    <div class="stat"><div class="k">Packets/sec</div><div class="v">{{ r.pps }}</div></div>
    <div class="stat"><div class="k">Unique IPs</div><div class="v">{{ r.unique_ips }}</div></div>
    <div class="stat"><div class="k">Unique MACs</div><div class="v">{{ r.unique_macs }}</div></div>
  </div>
  <p class="muted" style="margin-bottom:0">{{ r.start }} &rarr; {{ r.end }}</p>
</div>

<div class="card">
  <h2>Security indicators</h2>
  {% for level, msg in r.alerts %}
    <div class="alert {{ level }}"><strong>{{ level|upper }}</strong> &mdash; {{ msg }}</div>
  {% else %}
    <p class="muted">No suspicious patterns detected by the built-in heuristics.</p>
  {% endfor %}
</div>

<div class="grid" id="charts">
  <div class="card">
    <h2>Traffic mix by protocol</h2>
    <p class="sub">Each packet counted once, under its highest identified protocol.</p>
    <div class="mix-wrap">
      <div class="chart-box"><canvas id="mixChart" role="img"
           aria-label="Pie chart of packets by protocol; values in the adjacent table"></canvas></div>
      <table class="compact">
        <tr><th>Protocol</th><th class="num">Packets</th><th class="num">Share</th></tr>
        {% for m in r.mix_table %}
        <tr><td><span class="swatch" style="background:var(--series-{{ m.slot }})"></span>{{ m.label }}</td>
            <td class="num">{{ "{:,}".format(m.value) }}</td><td class="num">{{ m.pct }}</td></tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <div class="card">
    <h2>Top services</h2>
    <p class="sub">Client&rarr;server packets by destination port and service.</p>
    {% if r.chart.services %}
    <div class="chart-box"><canvas id="svcChart" role="img"
         aria-label="Bar chart of top services by packets; values in the Top 10 destination ports table"></canvas></div>
    {% else %}<p class="muted">No TCP/UDP services found.</p>{% endif %}
  </div>
</div>

<div class="card">
  <div class="card-head">
    <h2>Traffic over time</h2>
    <div class="seg" role="group" aria-label="Metric">
      <button type="button" data-metric="packets" aria-pressed="true">Packets</button>
      <button type="button" data-metric="bytes" aria-pressed="false">Bytes</button>
    </div>
  </div>
  <p class="sub">Per {{ r.chart.timeline.bin_label }} interval &middot; times in UTC</p>
  <div class="chart-box tall"><canvas id="timeChart" role="img"
       aria-label="Line chart of traffic volume over the capture duration"></canvas></div>
</div>

<div class="grid" id="hosts">
  <div class="card">
    <h2>Protocol layers</h2>
    <p class="sub">A packet counts once per layer it contains (e.g. IPv4 + TCP + HTTP).</p>
    <table>
      <tr><th>Protocol</th><th class="num">Packets</th><th style="width:40%"></th></tr>
      {% for name, n in r.protocols %}
      <tr><td>{{ name }}</td><td class="num">{{ "{:,}".format(n) }}</td>
          <td><div class="bar" style="width:{{ (100 * n / r.max_proto)|round(1) }}%"></div></td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Top 10 destination ports</h2>
    <table>
      <tr><th>Port</th><th>Proto</th><th>Service</th><th class="num">Packets</th></tr>
      {% for p in r.dst_ports %}
      <tr><td>{{ p.port }}</td><td>{{ p.proto }}</td><td>{{ p.service }}</td>
          <td class="num">{{ "{:,}".format(p.packets) }}</td></tr>
      {% else %}<tr><td colspan="4" class="muted">No TCP/UDP traffic</td></tr>{% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Busiest computers by packets</h2>
    <table>
      <tr><th>#</th><th>IP</th><th class="num">Packets</th><th class="num">Bytes</th></tr>
      {% for h in r.busiest_by_packets %}
      <tr><td class="muted">{{ loop.index }}</td><td class="mono">{{ h.ip }}</td>
          <td class="num"><strong>{{ "{:,}".format(h.packets) }}</strong></td><td class="num">{{ h.bytes }}</td></tr>
      {% else %}<tr><td colspan="4" class="muted">No IP traffic</td></tr>{% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Busiest computers by bytes</h2>
    <table>
      <tr><th>#</th><th>IP</th><th class="num">Packets</th><th class="num">Bytes</th></tr>
      {% for h in r.busiest_by_bytes %}
      <tr><td class="muted">{{ loop.index }}</td><td class="mono">{{ h.ip }}</td>
          <td class="num">{{ "{:,}".format(h.packets) }}</td><td class="num"><strong>{{ h.bytes }}</strong></td></tr>
      {% else %}<tr><td colspan="4" class="muted">No IP traffic</td></tr>{% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Top source IPs</h2>
    <table>
      <tr><th>IP</th><th class="num">Packets</th></tr>
      {% for ip, n in r.top_src %}<tr><td class="mono">{{ ip }}</td><td class="num">{{ n }}</td></tr>
      {% else %}<tr><td colspan="2" class="muted">None</td></tr>{% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Top destination IPs</h2>
    <table>
      <tr><th>IP</th><th class="num">Packets</th></tr>
      {% for ip, n in r.top_dst %}<tr><td class="mono">{{ ip }}</td><td class="num">{{ n }}</td></tr>
      {% else %}<tr><td colspan="2" class="muted">None</td></tr>{% endfor %}
    </table>
  </div>

</div>

<div class="card" id="conversations">
  <h2>Top 10 conversations between two computers</h2>
  <table>
    <tr><th>Computer A</th><th>Computer B</th><th>Protocols</th>
        <th class="num">A &rarr; B</th><th class="num">B &rarr; A</th>
        <th class="num">Total packets</th><th class="num">Total bytes</th></tr>
    {% for c in r.conversations %}
    <tr><td class="mono">{{ c.a }}</td><td class="mono">{{ c.b }}</td><td>{{ c.protos }}</td>
        <td class="num">{{ "{:,}".format(c.a_to_b) }}</td><td class="num">{{ "{:,}".format(c.b_to_a) }}</td>
        <td class="num"><strong>{{ "{:,}".format(c.packets) }}</strong></td><td class="num"><strong>{{ c.bytes }}</strong></td></tr>
    {% else %}<tr><td colspan="7" class="muted">None</td></tr>{% endfor %}
  </table>
</div>

<div class="grid" id="content">
  <div class="card">
    <h2>DNS queries</h2>
    <table>
      <tr><th>Name</th><th class="num">Count</th></tr>
      {% for q, n in r.dns_queries %}<tr><td class="mono">{{ q }}</td><td class="num">{{ n }}</td></tr>
      {% else %}<tr><td colspan="2" class="muted">No DNS queries</td></tr>{% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>TLS server names (SNI)</h2>
    <table>
      <tr><th>Server name</th><th class="num">Count</th></tr>
      {% for s, n in r.tls_sni %}<tr><td class="mono">{{ s }}</td><td class="num">{{ n }}</td></tr>
      {% else %}<tr><td colspan="2" class="muted">No TLS ClientHellos found</td></tr>{% endfor %}
    </table>
  </div>
</div>

<div class="card">
  <h2>HTTP requests</h2>
  <table>
    <tr><th>Source</th><th>Method</th><th>Host</th><th>Path</th><th>User-Agent</th></tr>
    {% for h in r.http_requests %}
    <tr><td class="mono">{{ h.src }}</td><td>{{ h.method }}</td><td class="mono">{{ h.host }}</td>
        <td class="mono">{{ h.path }}</td><td class="muted">{{ h.user_agent }}</td></tr>
    {% else %}<tr><td colspan="5" class="muted">No plaintext HTTP requests</td></tr>{% endfor %}
  </table>
</div>

{% if r.cleartext_creds %}
<div class="card">
  <h2>Cleartext credential exchanges</h2>
  <table>
    <tr><th>Protocol</th><th>Source</th><th>Destination</th><th>Detail (secrets masked)</th></tr>
    {% for c in r.cleartext_creds %}
    <tr><td>{{ c.proto }}</td><td class="mono">{{ c.src }}</td><td class="mono">{{ c.dst }}</td>
        <td class="mono">{{ c.detail }}</td></tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<div class="card" id="definitions">
  <h2>Protocol definitions</h2>
  <p class="sub">What each protocol is and why it matters. Entries tagged
     <span class="badge">In this capture</span> were seen in this file and are listed first.</p>
  <label class="toggle"><input type="checkbox" id="onlySeen"> Show only protocols in this capture</label>
  <div class="gloss" id="gloss">
    {% for g in r.glossary %}
    <div class="term{% if g.seen %} seen{% endif %}">
      <div class="term-head"><strong>{{ g.name }}</strong><span class="layer">{{ g.layer }}</span>
        {% if g.seen %}<span class="badge">In this capture</span>{% endif %}</div>
      <p>{{ g.text }}</p>
    </div>
    {% endfor %}
  </div>
</div>

<a class="btn" href="{{ url_for('index') }}">Analyze another file</a>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
const DATA = {{ r.chart|tojson }};

document.getElementById("onlySeen").addEventListener("change", e => {
  document.getElementById("gloss").classList.toggle("only-seen", e.target.checked);
});

(function () {
  if (typeof Chart === "undefined") {
    document.querySelectorAll(".chart-box").forEach(b => {
      b.innerHTML = '<p class="muted">Charts could not load (Chart.js needs internet access). ' +
                    'The tables on this page show the same data.</p>';
    });
    return;
  }
  const css = getComputedStyle(document.documentElement);
  const v = name => css.getPropertyValue(name).trim();
  const fmt = n => Number(n).toLocaleString();
  const human = b => {
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(1) : Math.round(b)) + " " + u[i];
  };

  Chart.defaults.color = v("--muted");
  Chart.defaults.font.family = "system-ui,-apple-system,Segoe UI,Roboto,sans-serif";
  Chart.defaults.borderColor = v("--grid");
  Object.assign(Chart.defaults.plugins.tooltip, {
    backgroundColor: v("--bg"), titleColor: v("--fg"), bodyColor: v("--fg"),
    borderColor: v("--border-strong"), borderWidth: 1, padding: 10, cornerRadius: 6,
    displayColors: false,
  });

  // --- Pie: traffic mix ------------------------------------------------------
  new Chart(document.getElementById("mixChart"), {
    type: "pie",
    data: {
      labels: DATA.mix.map(d => d.label),
      datasets: [{
        data: DATA.mix.map(d => d.value),
        backgroundColor: DATA.mix.map(d => v("--series-" + d.slot)),
        borderColor: v("--card"), borderWidth: 2, hoverOffset: 6,
      }],
    },
    options: {
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },  // the adjacent table is the legend
        tooltip: { callbacks: {
          label: c => `${fmt(c.parsed)} packets (${DATA.mix[c.dataIndex].pct})`,
        } },
      },
    },
  });

  // --- Horizontal bar: top services ------------------------------------------
  const svcEl = document.getElementById("svcChart");
  if (svcEl) {
    new Chart(svcEl, {
      type: "bar",
      data: {
        labels: DATA.services.map(d => d.label),
        datasets: [{
          data: DATA.services.map(d => d.value),
          backgroundColor: v("--series-1"), hoverBackgroundColor: "#5598e7",
          borderRadius: 4, barPercentage: 0.7, categoryPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: "y", maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: c => `${fmt(c.parsed.x)} packets` } },
        },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: v("--grid") } },
          y: { grid: { display: false }, ticks: { color: v("--fg") } },
        },
      },
    });
  }

  // --- Line: traffic over time -----------------------------------------------
  const tl = DATA.timeline;
  let metric = "packets";
  const crosshair = {
    id: "crosshair",
    afterDatasetsDraw(chart) {
      const active = chart.tooltip && chart.tooltip.getActiveElements();
      if (!active || !active.length) return;
      const x = active[0].element.x, { top, bottom } = chart.chartArea, ctx = chart.ctx;
      ctx.save();
      ctx.strokeStyle = v("--border-strong"); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke();
      ctx.restore();
    },
  };
  const timeChart = new Chart(document.getElementById("timeChart"), {
    type: "line",
    data: {
      labels: tl.labels,
      datasets: [{
        data: tl.packets, borderColor: v("--series-1"), backgroundColor: v("--series-1-fill"),
        fill: true, borderWidth: 2, tension: 0.25,
        pointRadius: tl.labels.length < 2 ? 4 : 0, pointHoverRadius: 5,
        pointBackgroundColor: v("--series-1"), pointHoverBorderColor: v("--card"),
        pointHoverBorderWidth: 2,
      }],
    },
    options: {
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          label: c => metric === "bytes" ? human(c.parsed.y) : `${fmt(c.parsed.y)} packets`,
        } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 8, maxRotation: 0 } },
        y: { beginAtZero: true, grid: { color: v("--grid") },
             ticks: { precision: 0, callback: val => metric === "bytes" ? human(val) : fmt(val) } },
      },
    },
    plugins: [crosshair],
  });

  document.querySelectorAll(".seg button").forEach(btn => {
    btn.addEventListener("click", () => {
      metric = btn.dataset.metric;
      document.querySelectorAll(".seg button").forEach(b =>
        b.setAttribute("aria-pressed", String(b === btn)));
      timeChart.data.datasets[0].data = tl[metric];
      timeChart.update();
    });
  });
})();
</script>
"""


def page(template: str, **ctx) -> str:
    body = render_template_string(template, **ctx)
    return render_template_string(BASE, body=body)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/", methods=["GET"])
def index():
    return page(INDEX, max_mb=MAX_UPLOAD_MB, max_pkts=MAX_PACKETS)


def fail(message: str):
    """Show an error banner on the upload page."""
    flash(message)
    return redirect(url_for("index"))


@app.route("/analyze", methods=["POST"])
def analyze():
    f = request.files.get("pcap")
    if f is None or not f.filename:
        return fail("Please choose a file to upload.")

    # 1. Clean the client-supplied name: strips directories ("../../etc/x"),
    #    path separators, spaces and non-ASCII characters.
    safe_name = secure_filename(f.filename)[-100:]
    # 2. Allow-list the extension, checked on the *cleaned* name.
    if not safe_name or not allowed_file(safe_name):
        return fail("Unsupported file type. Only .pcap, .pcapng and .cap files are allowed.")

    # 3. Each upload gets its own private temp folder (mode 0700), which is
    #    deleted with everything in it as soon as the request finishes, even on error.
    with tempfile.TemporaryDirectory(prefix="pcap_upload_") as tmp_dir:
        tmp_path = os.path.join(tmp_dir, safe_name)
        f.save(tmp_path)

        size = os.path.getsize(tmp_path)
        if size == 0:
            return fail("The uploaded file is empty.")

        # 4. Content check: the extension can lie, the magic bytes can't.
        with open(tmp_path, "rb") as fh:
            magic = fh.read(4)
        if len(magic) < 4 or magic not in PCAP_MAGICS:
            return fail("That file is not a valid pcap/pcapng capture "
                        "(its contents don't match the file type).")

        # 5. Structure check: reject a corrupt header outright; if the damage is
        #    later in the file, analyze only the intact packets before it.
        try:
            intact, problem = check_capture(tmp_path)
        except CaptureError as exc:
            return fail(f"Could not read the capture file: {exc}")
        except (OSError, struct.error):
            app.logger.warning("Integrity check failed for %s", safe_name, exc_info=True)
            return fail("Could not read the capture file. It appears to be broken.")
        if problem and intact == 0:
            return fail(f"The capture file is broken: {problem}. No packets could be read.")

        # 6. Parse. Any exception from a malformed file becomes a friendly error
        #    instead of a crash; the details go only to the server log.
        try:
            results = analyze_pcap(tmp_path, intact_packets=intact)
        except MemoryError:
            app.logger.warning("Out of memory parsing %s", safe_name)
            return fail("The capture is too large to analyze.")
        except Exception:  # noqa: BLE001 - scapy raises many types on bad input
            app.logger.warning("Failed to parse %s", safe_name, exc_info=True)
            return fail("Could not read the capture file. It appears to be "
                        "broken, truncated or in an unsupported format.")

    if results["total_packets"] == 0:
        return fail("The capture file contains no packets.")

    damage = None
    if problem:
        damage = (f"This capture file is damaged: {problem}. Only the first "
                  f"{results['total_packets']:,} intact packets were analyzed.")
    return page(RESULTS, r=results, filename=safe_name, damage=damage)


@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return fail(f"File too large. Maximum upload size is {MAX_UPLOAD_MB} MB.")


@app.errorhandler(BadRequest)
def bad_request(_e):
    return fail("The upload could not be read. Please try again.")


@app.errorhandler(InternalServerError)
def server_error(_e):
    # Last-resort safety net: never show a stack trace to the user.
    return fail("Something went wrong while processing that file.")


if __name__ == "__main__":
    # Debug mode is always off: the Werkzeug debugger allows arbitrary code
    # execution from the browser and leaks stack traces.
    app.run(host="127.0.0.1", port=5000, debug=False)
