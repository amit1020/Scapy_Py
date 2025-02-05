#!/usr/bin/env python3
"""
Title: Scapy Enhanced Packet Script
Author: Your Name
Description:
    A Python script that builds and sends custom network packets using Scapy.
    Features:
    - Custom Ethernet, IP, TCP layers
    - Random source port option
    - Custom RAW payload attachment
    - ARP layer example
    - Sniffing for responses
    - Basic rate limiting
    - Command-line arguments for flexible usage
    - Logging for debugging

Requirements:
    - Python 3.x
    - scapy (pip install scapy)

Usage:
    sudo python3 Packet_build.py --mac aa:bb:cc:dd:ee:ff --src_ip 192.168.50.10 \
    --dst_ip 192.168.50.20 --sport 135 --dport 135 --count 5 --payload "Hello"

    (Note: Running as root/administrator privileges is often required for Scapy.)

License:
    MIT License

Repository:
    GitHub: https://github.com/yourusername/scapy-packet-script
    LinkedIn: https://www.linkedin.com/in/yourprofile
"""

import logging
import os
import sys
import time
import argparse
import netifaces
import random
from scapy.all import Ether, IP, TCP, ARP, Raw, sniff, send, sendp, srp

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_default_gateway_ip():
    """ Get the IP address of the default gateway."""
    try:
        return netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None])[0] or "192.168.1.1"
    except Exception:
        return "192.168.1.1"

def get_mac(ip):
    """ Resolve the MAC address for a given IP address using ARP."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
    for sent, received in ans:
        return received.hwsrc
    return None

def get_gateway_mac():
    """ Get the MAC address of the default gateway."""
    gateway_ip = get_default_gateway_ip()
    return get_mac(gateway_ip)

class Packet:
    """A class to build and send custom network packets using Scapy."""

    def __init__(self, mac: str, dst_ip: str):
        resolved_mac = get_mac(dst_ip) or get_gateway_mac() or "ff:ff:ff:ff:ff:ff"
        self.my_packet = Ether(src=mac, dst=resolved_mac)
        logging.info(f"Initialized Ethernet layer with source MAC: {mac}, destination MAC: {resolved_mac}")

    def add_ip_layer(self, ip_src: str, ip_dst: str, ttl: int = 64):
        self.my_packet /= IP(src=ip_src, dst=ip_dst, ttl=ttl)
        logging.info(f"Added IP layer: src={ip_src}, dst={ip_dst}, ttl={ttl}")

    def add_tcp_layer(self, sport: int, dport: int):
        self.my_packet /= TCP(sport=sport, dport=dport)
        logging.info(f"Added TCP layer: sport={sport}, dport={dport}")

    def add_tcp_layer_random_sport(self, dport: int):
        sport = random.randint(1024, 65535)
        self.add_tcp_layer(sport, dport)
        logging.info(f"Added TCP layer with random source port: sport={sport}, dport={dport}")

    def add_raw_payload(self, payload_data: str):
        self.my_packet /= Raw(load=payload_data)
        logging.info(f"Added custom payload: {payload_data}")

    def add_arp_layer(self, hwsrc: str, psrc: str, hwdst: str = "ff:ff:ff:ff:ff:ff", pdst: str = None, op: int = 1):
        pdst = pdst or get_default_gateway_ip()
        self.my_packet /= ARP(hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst, op=op)
        logging.info(f"Added ARP layer: hwsrc={hwsrc}, psrc={psrc}, hwdst={hwdst}, pdst={pdst}, op={op}")

    def show_packet(self):
        self.my_packet.show()

    def send_packet(self, count: int = 1, verbose: bool = False):
        send(self.my_packet, count=count, verbose=verbose)
        logging.info(f"Sent {count} packet(s) at Layer 3.")

    def sendp_packet(self, count: int = 1, verbose: bool = False):
        sendp(self.my_packet, count=count, verbose=verbose)
        logging.info(f"Sent {count} packet(s) at Layer 2.")

    def sniff_responses(self, filter_str: str, timeout: int = 5):
        logging.info(f"Sniffing for packets with filter: {filter_str}, timeout: {timeout}s")
        packets = sniff(filter=filter_str, timeout=timeout)
        logging.info(f"Sniffed {len(packets)} packet(s).")
        for pkt in packets:
            logging.info(pkt.summary())
        return packets

def check_root():
    """Check if running as root/administrator."""
    if os.name != 'nt' and os.geteuid() != 0:
        logging.warning("[!] You are not running as root. Scapy may not function properly.")

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Scapy Enhanced Packet Script")
    parser.add_argument("--mac", default="aa:bb:cc:dd:ee:ff", help="Source MAC address")
    parser.add_argument("--src_ip", default="y.y.y.y", help="Source IP address")#! Change the default IP address
    parser.add_argument("--dst_ip", default="x.x.x.x", help="Destination IP address")#! Change the default IP address
    parser.add_argument("--sport", type=int, default=135, help="Source TCP port")
    parser.add_argument("--dport", type=int, default=135, help="Destination TCP port")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--payload", default="", help="Custom payload to include")
    parser.add_argument("--random_sport", action="store_true", help="Use a random source port")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def main():
    check_root()
    args = parse_args()
    pkt = Packet(mac=args.mac, dst_ip=args.dst_ip)
    pkt.add_ip_layer(ip_src=args.src_ip, ip_dst=args.dst_ip)
    pkt.add_tcp_layer_random_sport(args.dport) if args.random_sport else pkt.add_tcp_layer(args.sport, args.dport)
    if args.payload:
        pkt.add_raw_payload(args.payload)
    pkt.send_packet(count=args.count, verbose=args.verbose)

if __name__ == "__main__":
    main()
