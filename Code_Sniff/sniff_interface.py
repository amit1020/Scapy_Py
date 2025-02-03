from scapy.all import *

#!https://scapy.readthedocs.io/en/latest/usage.html
#!https://www.geeksforgeeks.org/packet-sniffing-using-scapy/



#?To choose the interface to sniff from:
capture = sniff(iface="en0",count=10)#Example for iface 

#In order to print specific packet:
capture[1].show()
#In order to print the packets:
capture.show()
