🌐 Simple Local Network Scanner

This project is a lightweight Python script designed for educational and network troubleshooting purposes. It scans a specified local subnet using ARP requests to discover active hosts and their corresponding MAC addresses and hostnames.

Key Features

ARP-Based Scanning: Uses the Address Resolution Protocol (ARP) for rapid discovery of devices on the local subnet.

Local Network Only: Due to the use of ARP, this tool is strictly limited to scanning the Local Area Network (LAN) and cannot reach external or remote networks.

Threaded Performance: Employs Python's threading and a Queue to perform parallel scanning, speeding up discovery for larger subnets.

Information Display: Collects and displays IP addresses, MAC addresses, and resolved hostnames for all active clients.

🛠️ Prerequisites

This script requires the scapy library, which handles packet manipulation, as well as the standard Python modules socket, threading, and ipaddress.

Install Python 3 (if not already installed).

Install Dependencies:

pip install scapy

Note: On Linux/macOS, running scapy may require elevated permissions (e.g., using sudo).

🚀 How to Run

The script requires the network range to be specified in CIDR notation (e.g., 192.168.1.0/24).

Save the Code: Save the network scanner code as a Python file (e.g., net_scan.py).

Execute the Script:

python .\netscan.py

Enter CIDR Notation: The script will prompt you to enter the network range:

Enter the CIDR notation: 192.168.1.0/24

IP                   |           MAC                          |   Hostname
---------------------|----------------------------------------|-------------------
192.168.1.1          |           00:1a:2b:3c:4d:5e            |   Router-Gateway
192.168.1.10         |           a1:b2:c3:d4:e5:f6            |   My-Laptop
192.168.1.150        |           ff:ee:dd:cc:bb:aa            |   Smart-TV
192.168.1.200        |           00:00:00:11:22:33            |   Unknown


Example Output
The script will output a formatted list of all discovered active clients on the specified local network.
