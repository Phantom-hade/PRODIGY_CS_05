# PRODIGY_CS_05 – Packet Sniffer Tool

This project was developed for **Task 5** of the **Prodigy InfoTech Cyber Security Internship**.

##Description

A simple network packet sniffer written in **Python** using the **Scapy** library.  
It captures live packets and displays key information including:

- Source IP address
- Destination IP address
- Protocol (TCP, UDP, ICMP)
- Raw payload data (preview)
- 
> ⚠️Ethical Use Only:  
> This tool is for **educational purposes only**.  
> Use it only on networks you own or are authorized to test.

---

##Features

- Real-time packet capture
- Layer 3 (IP-level) filtering
- Displays protocol and payload content
- Stops gracefully with `Ctrl + C`

---

##Requirements

- Python 3.x
- Scapy library:
  ```bash
  pip install scapy

  
Windows Users Must Install Npcap
To enable packet sniffing on Windows:

Download and install Npcap from:
 https://npcap.com

During installation:

Check: “Install Npcap in WinPcap API-compatible mode”

Run the script:
  ```bash
  python network_packet_analyzer.py
