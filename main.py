from scapy.all import sniff, ARP
from tabulate import tabulate
import threading
import time

ip_mac_history = {} # Tracks original MAC as seen per IP
devices = {} # Global table of devices
alerts = {} # Stores spoof warnings

def handle_arp(packet):
  if packet.haslayer(ARP):
    arp = packet[ARP]
    ip = arp.psrc
    mac = arp.hwsrc

    # Record the device if it is new
    if ip not in devices:
      devices[ip] = mac

    # Detection: if IP is known, but MAC changed
    if ip in ip_mac_history:
      original_mac = ip_mac_history[ip]
      if mac != original_mac:
        alert = f"Possible ARP Spoofing Detected! IP {ip} changed from {original_mac} to {mac} (lol)"
        if alert not in alerts: # To avoid duplicates
          alerts.append(alert)
          print(alert)
    else:
      ip_mac_history[ip] = mac # Store the original MAC

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
