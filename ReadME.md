# DNS Spoofer (Educational & Lab Use Only)

A Python-based DNS spoofing tool that demonstrates how Domain Name System (DNS) responses can be manipulated in a Man-in-the-Middle (MITM) attack scenario using **Scapy** and **Linux Netfilter Queue (NFQUEUE)**.

This project is developed strictly for **educational purposes**, cybersecurity learning, and testing within a **controlled lab environment**.

---

## 📌 Project Description

DNS spoofing (also known as DNS poisoning) is a cyberattack where a malicious DNS response is sent to a victim, redirecting them to an attacker-controlled IP address instead of the legitimate one.

This project captures live network packets, inspects DNS response traffic, and modifies the response for a specific target domain before forwarding it back to the victim.

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- NetfilterQueue
- Linux (iptables & packet forwarding)

---

## ⚙️ Working Mechanism

1. Network packets are redirected to a Netfilter Queue using `iptables`
2. The Python script fetches packets from the queue
3. DNS response packets are inspected
4. If the DNS query matches the target domain:
   - A fake DNS response is crafted
   - The IP address is replaced with an attacker-defined IP
5. Packet length and checksums are recalculated
6. The modified packet is forwarded to the target system

---

## 🚀 Installation & Usage (Lab Setup Only)

### ✅ Step 1: Enable IP Forwarding
```bash
iptables -I FORWARD -j NFQUEUE --queue-num 0
```

### ✅ Step 2: Add iptables Rule
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### ✅ Step 3: Run the DNS Spoofer Script
```bash
python3 dns_spoofer.py
```


