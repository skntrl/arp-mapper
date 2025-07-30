# arp-mapper
map all IPs and MACs addresses in the connected LAN

Done till now:

#### Part 1

done - Sniff and intercept all ARP packets and identify active devices in network
done - Extract IP and MAC pairs
done - Store unique pairs in a Python dictionary
done - Display the updated table every few seconds

## Remaining Tasks:

#### Part 2

Keep a history of known IP-MAC mappings
For every new ARP reply, check if a known IP has a different MAC
If known IP has different MAC, log it, and show it




