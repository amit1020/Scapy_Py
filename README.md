# Scapy_py




  sniff(filter="<?>",count="10")#10 will be example

## Layer-2(Data Link Layer)

| Protocol                                   | Description                                   | Filter Example   |
| :--------                                  | :-------------------------                    | :------------    |
| Ethernet                                 | Basic Layer 2 frame                           | 
sniff(filter="ether")```|


| `ARP`                                      | Resolve IP to MAC addr                        | ```sniff(filter="arp")
  |
| RARP(Reverse ARP)                       | Resolve MAC to IP                             | ```sniff(filter="rarp")`` |
| VLAN(802.1Q)                             | Virtual LAN tagging                           | 
shell

sniff(filter="vlan")
 |
| LLDP(Link Layer Discovery Protocol)      | Used by network devices to discover neighbors | 
shell

sniff(filter="lldp")
 |
| CDP                                      | Cisco version of LLDP                       | 
shell

sniff(filter="cdp")
  |
| STP(Spanning Tree Protocol)              | Prevents network loops                        | 
shell

sniff(filter="stp")
  |
| `PPPoE(Point-to-Point Protocol over Ethernet)`| Required. Your API key                 | 
sniff(filter="pppoe")```|



### Wireless Sniffing - can be only used by Monitor mode

| Protocol                    | Description                      | Filter Example                                     |
| :--------                   | :-------------------------       | :------------                                      |
| 802.11(WIFI)                | Standard wireless frames         | ```sniff(iface="wlan0mon")
                      |
| Beacon Frames               | Wireless network advertisements  | 
sniff(filter="wlan type mgt subtype beacon")
 |
| Probe Requests/Responses    | Devices looking for networks     | 
sniff(filter="wlan type mgt subtype probe-req")```|

| Deauthentication Frames     | Disconnects devices from WI-FI   | ```sniff(filter="wlan type mgt subtype deauth")
 |
