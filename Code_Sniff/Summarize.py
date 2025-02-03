from scapy.all import *

#!https://scapy.readthedocs.io/en/latest/usage.html
#!https://www.geeksforgeeks.org/packet-sniffing-using-scapy/



#?To save the sniffed packets as a file
def Saving_sniff_as_file(capture) :
    wrpcap("sniffed.pcap",capture)
    return 


def Sniff_interface(interface) :
    #?To choose the interface to sniff from:
    capture = sniff(iface=interface,count=10)#Example for iface 

    #In order to print specific packet:
    capture[1].show()
    #In order to print the packets:
    capture.show()
    return capture

def Sniff_protocol(protocol) :
    #?To choose protocol packet type :
    capture = sniff(filter=protocol,count=10)#!Filter options -> README.md

    #In order to print specific packet:
    capture[1].show()
    #In order to print the packets:
    capture.show()
    return capture