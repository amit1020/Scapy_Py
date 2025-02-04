# Layer-2(Data Link Layer)

| Protocol                                   | Description                                   | Filter Example   |
| :--------                                  | :-------------------------                    | :------------    |
| `Ethernet`                                 | Basic Layer 2 frame                           | ```sniff(filter="ether")```|
| `ARP`                                      | Resolve IP to MAC addr                        | ```sniff(filter="arp")```  |
| `RARP(Reverse ARP)`                   `    | Resolve MAC to IP                             | ```sniff(filter="rarp")``` |
| `VLAN(802.1Q)`                             | Virtual LAN tagging                           | ```sniff(filter="vlan")``` |
| `LLDP(Link Layer Discovery Protocol)`      | Used by network devices to discover neighbors | ```sniff(filter="lldp")``` |
| `CDP`                                      | Cisco version of `LLDP`                       | ```sniff(filter="cdp")```  |
| `STP(Spanning Tree Protocol)`              | Prevents network loops                        | ```sniff(filter="stp")```  |
| `PPPoE(Point-to-Point Protocol over Ethernet)`| **Required**. Your API key                 | ```sniff(filter="pppoe")```|


> __⚠️ Wireless Sniffing - can be only used by monitor-mood__ 



| Protocol                    | Description                      | Filter Example                                     |
| :--------                   | :-------------------------       | :------------                                      |
| `802.11(WIFI)`                | Standard wireless frames         | ```sniff(iface="wlan0mon")```                      |
| `Beacon Frames`               | Wireless network advertisements  | ```sniff(filter="wlan type mgt subtype beacon")``` |
| `Probe Requests/Responses`    | Devices looking for networks     | ```sniff(filter="wlan type mgt subtype probe-req")```|
| `Deauthentication Frames`     | Disconnects devices from WI-FI   | ```sniff(filter="wlan type mgt subtype deauth")``` |



# Layer-3(Network Layer)

| Protocol           | Description                            | Filter Example   |
| :--------          | :-------------------------             | :------------    |
| `IPv4`             | Internet Protocol v4	                  | ```sniff(filter="ip")```|
| `IPv6`             | Internet Protocol v6                   | ```sniff(filter="ip6")```  |
| `ICMP(ping)`       | Used for network diagnostics,for IPv4  | ```sniff(filter="icmp")``` |
| `ICMPv6`           | Ping for IPv6	                        | ```sniff(filter="icmp6")``` |
| `IGMP (Multicast)` | Used for multicast streaming	          | ```sniff(filter="igmp")``` |




# Layer-4(Transport Layer)

| Protocol                                   | Description                                   | Filter Example   |
| :--------                                  | :-------------------------                    | :------------    |
| `TCP (Transmission Control Protocol)`      | Reliable, connection-oriented protocol        | ```sniff(filter="tcp")```|
| `UDP (User Datagram Protocol)	`            | Faster but connectionless protocol	           | ```sniff(filter="udp)```  |
| `SCTP (Stream Control Transmission Protocol)`| Used for telecom signaling	                 | ```sniff(filter="sctp")``` |


# Layer-7(Application Layer)

| Protocol                                    | Description                                   | Filter Example   |
| :--------                                   | :-------------------------                    | :------------    |
| `HTTP (Web Traffic)	`                       | Unencrypted web browsing	                    | ```sniff(filter="tcp port 80")```|
| `HTTP (Web Traffic)	`                       | Secure web traffic (TLS/SSL)	                | ```sniff(filter="tcp port 443")```  |
| `FTP (File Transfer Protocol)	`             | File transfer                                 | ```sniff(filter="tcp port 21")``` |
| `SSH (Secure Shell)`                        | Secure Shell (Encrypted Remote Login)	        | ```sniff(filter="tcp port 22")```|
| `DNS (Domain Name System)`                  | Resolves domain names	                        | ```sniff(filter="udp port 53")``` |
| `DHCP (Dynamic Host Configuration Protocol)`| Assigns IP addresses	                        | ```sniff(filter="udp port 67 or port 68")``` |
| `SMTP (Email Sending)`                      | Outgoing email	                              | ```sniff(filter="tcp port 25")``` |
| `POP3 (Email Retrieval)`                    | Incoming email	                              | ```sniff(filter="tcp port 110")```  |
| `IMAP (Email Retrieval)`                    | Incoming email	                              | ```sniff(filter="tcp port 143")```  |
| `Telnet`                                    | Remote login (insecure)	                       | ```sniff(filter="tcp port 23")```  |


