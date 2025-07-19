import dpkt
import socket
import re
from collections import Counter

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return None

def extract_regex_patterns(text):
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
    urls = re.findall(r'https?://[^\s"\'<>]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    usernames = re.findall(r'username[:=]\s?([^\s&]+)', text, re.I)
    passwords = re.findall(r'password[:=]\s?([^\s&]+)', text, re.I)
    credit_cards = re.findall(r'\b(?:\d[ -]*?){13,16}\b', text)
    return emails, urls, ips, usernames, passwords, credit_cards

def parse_pcap(file_path):
    try:
        f = open(file_path, 'rb')
    except IOError as e:
        print(f"Could not open file: {e}")
        return

    try:
        pcap = dpkt.pcap.Reader(f)
    except (dpkt.dpkt.NeedData, ValueError):
        f.seek(0)
        try:
            pcap = dpkt.pcapng.Reader(f)
        except Exception as e:
            print(f"Not a valid pcap or pcapng file: {e}")
            f.close()
            return

    total_packets = 0
    src_ips = Counter()
    dst_ips = Counter()
    dst_ports = Counter()
    protocols = Counter()
    found_emails = set()
    found_urls = set()
    found_ips = set()
    found_usernames = set()
    found_passwords = set()
    found_creditcards = set()

    for ts, buf in pcap:
        total_packets += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            continue

        ip = None
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip = eth.data
        else:
            continue

        src_ip_str = inet_to_str(ip.src)
        dst_ip_str = inet_to_str(ip.dst)

        if src_ip_str:
            src_ips[src_ip_str] += 1
        if dst_ip_str:
            dst_ips[dst_ip_str] += 1

        proto_num = ip.p
        protocols[proto_num] += 1

        src_port = None
        dst_port = None
        payload = b""

        try:
            if proto_num == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                if isinstance(tcp, dpkt.tcp.TCP):
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    payload = tcp.data
            elif proto_num == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                if isinstance(udp, dpkt.udp.UDP):
                    src_port = udp.sport
                    dst_port = udp.dport
                    payload = udp.data
            elif proto_num == dpkt.ip.IP_PROTO_ICMP:
                payload = ip.data.data
            else:
                payload = ip.data.data if hasattr(ip.data, 'data') else b""
        except Exception:
            payload = b""

        if dst_port:
            dst_ports[dst_port] += 1

        try:
            decoded_payload = payload.decode('utf-8', errors='ignore')
        except Exception:
            decoded_payload = ""

        try:
            emails, urls, ips_found, usernames, passwords, creditcards = extract_regex_patterns(decoded_payload)
            found_emails.update(emails)
            found_urls.update(urls)
            found_ips.update(ips_found)
            found_usernames.update(usernames)
            found_passwords.update(passwords)
            found_creditcards.update(creditcards)
        except Exception:
            pass

    f.close()

    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        2: 'IGMP',
        89: 'OSPF',
        132: 'SCTP'
    }

    print(f"[+] Total Packets: {total_packets}\n")

    print("[+] Top 10 Source IPs:")
    for ip_addr, count in src_ips.most_common(10):
        print(f"{ip_addr}: {count}")

    print("\n[+] Top 10 Destination IPs:")
    for ip_addr, count in dst_ips.most_common(10):
        print(f"{ip_addr}: {count}")

    print("\n[+] Top 10 Destination Ports:")
    for port, count in dst_ports.most_common(10):
        print(f"{port}: {count}")

    print("\n[+] Protocol Usage:")
    for proto_num, count in protocols.most_common():
        proto_name = protocol_map.get(proto_num, str(proto_num))
        print(f"{proto_name}: {count}")

    print("\n[+] Extracted Emails:")
    for email in sorted(found_emails):
        print(email)

    print("\n[+] Extracted URLs:")
    for url in sorted(found_urls):
        print(url)

    print("\n[+] Extracted IPs:")
    for ip_addr in sorted(found_ips):
        print(ip_addr)

    print("\n[+] Extracted Usernames:")
    for user in sorted(found_usernames):
        print(user)

    print("\n[+] Extracted Passwords:")
    for pwd in sorted(found_passwords):
        print(pwd)

    print("\n[+] Extracted Credit Card Numbers:")
    for cc in sorted(found_creditcards):
        print(cc)


# === RUN ===
#PCAP_FILE ="/sdcard/sample.pcap" # <== Change this to your actual PCAP file name
pcap_file =  "/sdcard/nitroba.pcap"   # << Set your pcap file path here
parse_pcap(pcap_file)