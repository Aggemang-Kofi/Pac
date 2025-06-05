
# Packet Sniffing Attack – Educational Overview

##  What is Packet Sniffing?

Packet sniffing is a technique used to monitor and capture data packets flowing across a network. While it's a valuable tool for network diagnostics and performance monitoring, it can be exploited by attackers to intercept sensitive information like:

- Login credentials  
- Session cookies  
- Unencrypted communications  
- Network protocols in use

---

##  How Packet Sniffing Works

![Packet Sniffing Diagram](./Packet%20Sniffer.png)

### Attack Flow:
1. **Traffic Interception** – Malicious actor gains access to the network.
2. **Packet Capture** – NIC is set to promiscuous mode to capture all traffic.
3. **Traffic Analysis** – Sniffed packets are parsed for useful data.
4. **Exploitation** – Extracted information is used for attacks like credential theft or session hijacking.

---

## How to Prevent Packet Sniffing Attacks

| Technique                  | Description |
|---------------------------|-------------|
| **HTTPS Everywhere**      | Encrypts web communication. |
| **VPN**                   | Encrypts all network traffic. |
| **WPA3/WPA2 Wi-Fi**       | Secures wireless communication. |
| **Network Segmentation**  | Isolates sensitive subnets. |
| **Switches vs. Hubs**     | Use switches to limit traffic visibility. |
| **Port Security**         | Limits MAC addresses per port. |

---

## Lab: Packet Sniffing with Wireshark & tcpdump

### Prerequisites:
- Virtual lab environment (e.g. VirtualBox, VMware, or Docker)
- Two or more VMs/containers (e.g., Kali Linux & Ubuntu)
- `tcpdump`, `wireshark`, or both

---

###  Lab Setup:

#### **Install Tools**
On Kali or Ubuntu:
```bash
sudo apt update
sudo apt install wireshark tcpdump -y
````

#### **Set Interface to Promiscuous Mode**

```bash
sudo ip link set eth0 promisc on
```

#### **Start Packet Capture**

**Using tcpdump**:

```bash
sudo tcpdump -i eth0 -w capture.pcap
```

**Using Wireshark** (GUI):

```bash
wireshark &
```

#### **Generate Traffic**

From another machine on the same network:

```bash
curl http://example.com
ssh user@target-ip
```

Observe the traffic in real-time on Wireshark or review `capture.pcap` using:

```bash
wireshark capture.pcap
```

## References

* [Wireshark Documentation](https://www.wireshark.org/docs/)
* [OWASP Sniffing Guide](https://owasp.org/www-community/attacks/Network_sniffing)
* [MITRE ATT\&CK – Network Sniffing](https://attack.mitre.org/techniques/T1040/)

---

> **Disclaimer:** This lab is for educational and ethical training purposes only. Always test in isolated environments.

