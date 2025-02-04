
#!/usr/bin/env python3
"""
A simple packet-sniffing utility using Scapy. 

Functions:
- save_sniffed_packets: Saves captured packets to a .pcap file.
- sniff_packets: Sniffs a limited count of packets using a lambda for summary.
- sniff_on_interface: Sniffs packets on a specific interface.
- sniff_protocol: Sniffs packets matching a specific protocol filter.

Dependencies:
- scapy (pip install scapy)
"""

from scapy.all import sniff, wrpcap

def save_sniffed_packets(capture, filename="sniffed.pcap"):
    """
    Saves sniffed packets to a specified PCAP file.

    :param capture: A list (PacketList) of packets captured by Scapy.
    :param filename: The name of the PCAP file to write to (defaults to 'sniffed.pcap').
    """
    if not capture:
        print("[!] No packets to save.")
        return

    try:
        wrpcap(filename, capture)
        print(f"[+] Packets saved to {filename}.")
    except PermissionError:
        print("[!] Permission denied. Try running with elevated privileges (sudo).")
    except Exception as e:
        print(f"[!] An error occurred while saving packets: {e}")


def sniff_packets(packet_count=10):
    """
    Sniffs a specified number of packets and returns the captured list.

    :param packet_count: Number of packets to capture (defaults to 10).
    :return: List (PacketList) of captured packets.
    """
    print(f"[*] Sniffing {packet_count} packets (no filter, any interface)...")
    capture = sniff(prn=lambda x: x.summary(), count=packet_count)
    return capture


def sniff_on_interface(interface, packet_count=10):
    """
    Sniffs packets on a specified interface.

    :param interface: The name of the network interface to sniff from.
    :param packet_count: Number of packets to capture (defaults to 10).
    :return: List (PacketList) of captured packets.
    """
    print(f"[*] Sniffing {packet_count} packets on interface '{interface}'...")
    capture = sniff(iface=interface, count=packet_count)
    
    # Print details of a single packet (e.g., second captured packet if available)
    if len(capture) > 1:
        print("[*] Showing details for packet #2:")
        capture[1].show()
    
    # Print the summary of all captured packets
    print("\n[*] Summary of all captured packets:")
    capture.show()
    
    return capture


def sniff_protocol(protocol_filter="tcp", packet_count=10):
    """
    Sniffs packets matching a specific protocol filter (e.g., 'tcp', 'udp', 'icmp').

    :param protocol_filter: BPF-like filter string for protocol (defaults to 'tcp').
    :param packet_count: Number of packets to capture (defaults to 10).
    :return: List (PacketList) of captured packets.
    """
    print(f"[*] Sniffing {packet_count} packets with protocol filter '{protocol_filter}'...")
    capture = sniff(filter=protocol_filter, count=packet_count)
    
    # Print details of a single packet (e.g., second captured packet if available)
    if len(capture) > 1:
        print("[*] Showing details for packet #2:")
        capture[1].show()
    
    # Print the summary of all captured packets
    print("\n[*] Summary of all captured packets:")
    capture.show()
    
    return capture


def main():
    """
    Main function to demonstrate usage of the sniffing functions.
    Modify this as needed for your workflow or script requirements.
    """
    print("[*] Starting main demonstration...")

    # Example usage of sniff_packets
    packets = sniff_packets(packet_count=5)
    save_sniffed_packets(packets, filename="demo_sniffed.pcap")

    # Example usage of sniff_on_interface
    # Replace 'eth0' with the appropriate interface on your system
    # interface_capture = sniff_on_interface('eth0', packet_count=5)

    # Example usage of sniff_protocol
    # protocol_capture = sniff_protocol('udp', packet_count=5)

    print("[*] Demonstration complete.")


if __name__ == "__main__":
    main()



