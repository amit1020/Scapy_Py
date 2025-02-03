from scapy.all import *

#!https://scapy.readthedocs.io/en/latest/usage.html
#!https://www.geeksforgeeks.org/packet-sniffing-using-scapy/



#To sniffing the packets
capture = sniff(filter="tcp",count=10)#!Filter options -> README.md

#To save the sniffed packets
wrpcap("sniffed.pcap",capture)