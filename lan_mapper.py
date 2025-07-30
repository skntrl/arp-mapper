from scapy.all import sniff, ARP
from tabulate import tabulate
import threading
import time

# Global table of devices
devices = {}

def handle_arp(packet):
  if packet.haslayer(ARP):
    arp = packet[ARP]
    ip = arp.psrc
    mac = arp.hwsrc
    if ip not in devices:
      devices[ip] = mac
    
def print_table():
  while True:
    if devices:
      table = [(ip, mac) for ip, mac in devices.items()]
      print("\nActive Devices on Local Network:")
      print(tabulate(table, headers=["IP Address", "MAC Address"], tablefmt="fancy_grid"))
    time.sleep(5)

if __name__ == "__main__":
  print("Sniffing ARP packets... Press Ctrl+C to stop.\n")

  # Start table printer in background
  printer_thread = threading.Thread(target=print_table, daemon=True)
  printer_thread.start()

  # Start sniffing (Requires root)
  sniff(filter="arp", prn=handle_arp, store=0)
