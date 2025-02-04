#!/usr/bin/env python3
"""
Title: Scapy Enhanced Packet Script
Author: Your Name
Description:
    A Python script that builds and sends custom network packets using Scapy.
    Features included:
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
    sudo python3 scapy_enhanced.py --mac aa:bb:cc:dd:ee:ff --src_ip 192.168.50.10 \
    --dst_ip 192.168.50.20 --sport 135 --dport 135 --count 5 --payload "Hello"
    
    (Note: Running as root or administrator privileges is often required for Scapy.)
"""

import logging,os,sys,time,argparse,netifaces




from scapy.all import (
    Ether, IP, TCP, ARP, Raw,
    sniff, send, sendp
)



def get_ip():
    """
    Get the IP address of the default network interface.

    Returns:
        -ip: The IP address of the default network interface
    """
    ip = netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])
    
    return ip[2][0]['broadcast'].replace('255', '1') #Return router IP address




class Packet:
    """
    A class to build and send custom network packets using Scapy.
    """

    def __init__(self, mac: str):
        """
        Initialize the Packet object with a specified source MAC address.

            -mac: MAC address string (e.g., "aa:bb:cc:dd:ee:ff")
        """
        self.my_packet = None
        try:
            # Build the Ether layer with a custom source MAC
            self.my_packet = Ether(src=mac)
            logging.info(f"Initialized Ethernet layer with source MAC: {mac}")
        except Exception as e:
            logging.error(f"[!] Failed to build the Ethernet layer: {e}")
            self.my_packet = None



    def add_ip_layer(self, ip_src: str, ip_dst: str, ttl: int = 64) -> None:
        """
        Add an IP layer to the packet.

            -ip_src: Source IP address
            -ip_dst: Destination IP address
            -ttl: Time to Live (default 64)
        """
        
        if self.my_packet:#*Check my_packet is not None
            self.my_packet /= IP(src=ip_src, dst=ip_dst, ttl=ttl)
            logging.info(f"Added IP layer: src={ip_src}, dst={ip_dst}, ttl={ttl}")



    def add_tcp_layer(self, sport: int, dport: int) -> None:
        """
        Add a TCP layer to the packet.

            -sport: Source port
            -dport: Destination port
        """
        if self.my_packet:
            self.my_packet /= TCP(sport=sport, dport=dport)
            logging.info(f"Added TCP layer: sport={sport}, dport={dport}")




    def add_raw_payload(self, payload_data: str) -> None:
        """
        Attach a Raw payload (custom data) to the packet.

            -payload_data: The custom data to be included in the payload
        """
        if self.my_packet:
            self.my_packet /= Raw(load=payload_data)
            logging.info(f"Added custom payload: {payload_data}")



    def add_arp_layer(self, hwsrc: str, psrc: str, hwdst: str = "ff:ff:ff:ff:ff:ff",
                      pdst: str = get_ip(), op: int = 1) -> None:
        """
        Add an ARP layer to the packet (e.g., ARP request).

            -hwsrc: Source hardware address
            -psrc: Source protocol (IP) address
            -hwdst: Destination hardware address
            -pdst: Destination protocol (IP) address
            -op: Operation (1 = request, 2 = reply)
        """
        if self.my_packet:
            self.my_packet /= ARP(hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst, op=op)
            logging.info("Added ARP layer to the packet.")


    def show_packet(self) -> None:
        """
        Print a human-readable breakdown of the packet layers.
        """
        if self.my_packet:
            print(self.my_packet.show())



    def send_packet(self, count: int = 1, verbose: bool = False) -> None:
        """
        Send the packet at Layer 3.

            -count: Number of packets to send
            -verbose: Whether scapy sends verbose output
        """
        if self.my_packet:
            try:
                send(self.my_packet, count=count, verbose=verbose)
                logging.info(f"Sent {count} packet(s) at Layer 3.")
            except Exception as e:
                logging.error(f"[!] Error sending at Layer 3: {e}")



    def sendp_packet(self, count: int = 1, verbose: bool = False) -> None:
        """
        Send the packet at Layer 2.

            -count: Number of packets to send
            -verbose: Whether scapy sends verbose output
        """
        if self.my_packet:
            try:
                sendp(self.my_packet, count=count, verbose=verbose)
                logging.info(f"Sent {count} packet(s) at Layer 2.")
            except Exception as e:
                logging.error(f"[!] Error sending at Layer 2: {e}")


    def send_packet_with_delay(self, count: int = 1, delay: float = 0.1) -> None:
        """
        Send the packet at Layer 3 with a delay (rate limit).

        :param count: Number of packets to send
        :param delay: Seconds to wait between sends
        """
        if self.my_packet:
            for i in range(count):
                try:
                    send(self.my_packet, verbose=False)
                    logging.info(f"Sent packet {i+1}/{count} at Layer 3.")
                    time.sleep(delay)
                except Exception as e:
                    logging.error(f"[!] Error sending at Layer 3: {e}")
                    break



    def sniff_responses(self, filter_str: str, timeout: int = 5):
        """
        Sniff network traffic for a given time or until a condition is met.

        :param filter_str: BPF filter string (e.g., "tcp and host 192.168.50.20")
        :param timeout: Seconds to sniff
        :return: A list of sniffed packets
        """
        logging.info(f"Sniffing for packets with filter: {filter_str}, timeout: {timeout}s")
        packets = sniff(filter=filter_str, timeout=timeout)
        logging.info(f"Sniffed {len(packets)} packet(s).")
        for pkt in packets:
            logging.info(pkt.summary())
        return packets



def check_root() -> None:
    """
    Check if running as root/administrator.
    Warn if not, since Scapy often needs elevated privileges.
    """
    if os.name != 'nt':  # If not Windows
        if os.geteuid() != 0:
            logging.warning("[!] It looks like you're not running as root. "
                            "Scapy may not function properly without root privileges.")
            # Uncomment this if you want to force exit when not root:
            # sys.exit(1)


"""
def parse_args():
    
    Parse command-line arguments for flexible use.
    
    parser = argparse.ArgumentParser(description="Scapy Enhanced Packet Script")
    parser.add_argument("--mac", default="aa:bb:cc:dd:ee:ff", help="Source MAC address")
    parser.add_argument("--src_ip", default="192.168.x.x, help="Source IP address")
    parser.add_argument("--dst_ip", default="192.168.x.x", help="Destination IP address")
    parser.add_argument("--sport", type=int, default=135, help="Source TCP port")
    parser.add_argument("--dport", type=int, default=135, help="Destination TCP port")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--payload", default="", help="Custom payload to include in the packet")
    parser.add_argument("--random_sport", action="store_true", help="Use a random source port")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between sends (in seconds)")
    parser.add_argument("--sniff_filter", default="", help="BPF filter string for sniffing responses")
    parser.add_argument("--sniff_timeout", type=int, default=5, help="Timeout for sniffing (in seconds)")
    parser.add_argument("--layer2", action="store_true", help="Send packet at Layer 2 (sendp) instead of Layer 3 (send)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output from scapy")
    return parser.parse_args()




def main():
    \"""
    Main function to demonstrate building and sending a packet with various options.
    \"""
    check_root()
    args = parse_args()

    # Create the packet with the specified source MAC
    pkt = Packet(mac=args.mac)

    # Add IP layer
    pkt.add_ip_layer(ip_src=args.src_ip, ip_dst=args.dst_ip)

    # Add TCP layer (either random or specified source port)
    if args.random_sport:
        pkt.add_tcp_layer_random_sport(dport=args.dport)
    else:
        pkt.add_tcp_layer(sport=args.sport, dport=args.dport)

    # Optionally add a raw payload
    if args.payload:
        pkt.add_raw_payload(args.payload)

    # Show packet (uncomment if you want a terminal breakdown)
    # pkt.show_packet()

    # Send the packet either at Layer 2 or Layer 3, with optional delay
    if args.delay > 0:
        logging.info("Sending packet(s) with a delay between sends...")
        pkt.send_packet_with_delay(count=args.count, delay=args.delay)
    else:
        logging.info("Sending packet(s) without delay...")
        if args.layer2:
            pkt.sendp_packet(count=args.count, verbose=args.verbose)
        else:
            pkt.send_packet(count=args.count, verbose=args.verbose)

    # Optionally sniff for responses using a BPF filter
    if args.sniff_filter:
        pkt.sniff_responses(filter_str=args.sniff_filter, timeout=args.sniff_timeout)


if __name__ == "__main__":
    main()
"""