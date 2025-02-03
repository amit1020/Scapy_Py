from scapy.all import *

#!https://scapy.readthedocs.io/en/latest/usage.html
#!https://www.geeksforgeeks.org/packet-sniffing-using-scapy/



#?To choose protocol packet type :
capture = sniff(filter="",count=10)#!Filter options -> README.md

#In order to print specific packet:
capture[1].show()
#In order to print the packets:
capture.show()
