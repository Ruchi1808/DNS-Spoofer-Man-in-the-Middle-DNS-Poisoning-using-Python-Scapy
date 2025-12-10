# DNS Spoofer – Man-in-the-Middle DNS Poisoning (Educational & Lab Use Only)

A Python-based DNS spoofing tool that demonstrates how Domain Name System (DNS) responses can be manipulated in a Man-in-the-Middle (MITM) attack scenario using **Scapy** and **Linux NetfilterQueue (NFQUEUE)**.

> ⚠️ **Disclaimer:** This project is strictly for educational use in a controlled lab environment.  
> Do NOT use this tool on networks you do not own or have explicit permission to test.

---

## 📌 Project Overview

DNS spoofing (also known as DNS poisoning) is an attack where a victim is redirected to a malicious IP address by manipulating DNS responses.

This project demonstrates:
- Interception of DNS traffic using Linux **iptables**
- Packet redirection to **Netfilter Queue (NFQUEUE)**
- DNS response modification using **Scapy**
- Redirection of victims to attacker-controlled IP addresses

---

## 🧠 Architecture / Working Flow

1. Victim sends a DNS request for a domain (e.g., `www.example.com`).
2. The attacker system is placed in a MITM position within the network.
3. DNS response packets are redirected to **NFQUEUE** using iptables.
4. The Python script analyzes each packet:
   - Verifies DNS response packets
   - Matches the target domain
5. If a match is found:
   - The DNS answer IP is replaced with a spoofed IP
   - Packet checksums and lengths are recalculated
6. The modified packet is forwarded to the victim.

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- NetfilterQueue
- Linux (iptables & IP forwarding)

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/Ruchi1808/DNS-Spoofer-Man-in-the-Middle-DNS-Poisoning-using-Python-Scapy.git
cd DNS-Spoofer-Man-in-the-Middle-DNS-Poisoning-using-Python-Scapy
```

Install required dependencies:

```bash
pip install -r requirements.txt
```

If NetfilterQueue installation fails:

```bash
sudo apt-get install python3-dev libnetfilter-queue-dev build-essential
pip install netfilterqueue
```

## ⚙️ Configuration

Modify the following values inside dns_spoofer.py:

```python
TARGET_DOMAIN = b"www.example.com."
FAKE_IP = "192.168.1.100"
```

## 🚀 Usage (Lab Environment Only)

   ⚠️ All commands require root privileges.

## ✅ Step 1: Enable IP Forwarding

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## ✅ Step 2: Redirect Packets to NFQUEUE

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

To capture only DNS traffic:

```bash
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
```

## ✅ Step 3: Run the DNS Spoofer

```bash
sudo python3 dns_spoofer.py
```

## 🧹 Cleanup (Important)

   Always restore system settings after testing.

## Disable IP Forwarding

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

## Remove iptables Rules

```bash
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
```

or (if DNS-only rule was used):

```bash
sudo iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
```

## ⚠️ Limitations

   -Works only with unencrypted DNS traffic (no DoH/DoT).

   -Requires MITM position (e.g., ARP spoofing).

   -Intended for controlled lab environments.

   -Linux-only implementation.

## 🎓 Academic & Interview Relevance

   -This project demonstrates:

   -Practical understanding of DNS protocol vulnerabilities

   -Network packet interception using iptables and NFQUEUE

   -Real-time packet modification using Scapy

   -Ethical hacking and network security concepts   
