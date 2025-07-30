# arp-mapper
map all IPs and MACs addresses in the connected LAN
## Remaining Tasks:

#### Part 4

Check what devices appear at what time  
Basic bandwidth sniffing - who consumes the most packets.  
Graphs - device uptime bars, IP/MAC heatmaps  

## Done till now:  

#### PArt 3

getting device manufacturer name from the MAC  
get TTL value and MAC to guess OS  
last seen table to see when each device was last observed  
log the warnings + timestamps alerts in CSV  

#### Part 2

Keep a history of known IP-MAC mappings  
For every new ARP reply, check if a known IP has a different MAC  
If known IP has different MAC, log it, and show it  

#### Part 1

Sniff and intercept all ARP packets and identify active devices in network  
Extract IP and MAC pairs  
Store unique pairs in a Python dictionary  
Display the updated table every few seconds  





