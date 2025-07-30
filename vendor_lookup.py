# Plan: This script will use first 3 bytes of each MAC address, called the OUI - Organizationally Unique Identifier to
# look up the device vendor. Will try implementing both online and offline ways

# Online
import requests

mac_vendors_cache = {}

def lookup_vendor_online(mac):
  """Try looking up from macvendors.com API"""
  try:
    response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
    if response.status_code == 200:
      return response.text.strip()
  except Exception:
    pass
  return "Unknown"


# Offline Method
def load_oui_file(filepath="oui.txt"):
  """Load OUI file into memory as dict: prefix -> vendor"""
  oui_dict = {}
  try:
    with open(filepath, 'r') as f:
      for line in f:
        if "(hex)" in line:
          parts = line.split("(hex)")
          prefix = parts[0].strip().replace("-", ":").lower()
          vendor = parts[1].strip()
          oui_dict[prefix] = vendor
  except FileNotFoundError:
    print("OUI file not found. Offline lookup disabled")
  return oui_dict

def lookup_vendor_offline(mac, oui_dict):
  """Lookup MAC vendor from OUI data"""
  prefix = ":".join(mac.lower().split(":")[:3])
  return oui_dict.get(prefix, "Unknown Vendor")

def get_vendor(mac, oui_dict=None):
  """To unify everything. First cache -> then Offline -> then Online"""

  if mac in mac_vendors_cache:
    return mac_vendors_cache[mac]

  vendor = "Unknown"
  if oui_dict:
    vendor = lookup_vendor_offline(mac, oui_dict)

  # Offline failed
  if vendor == "Unknown Vendor":
    vendor = lookup_vendor_online(mac)
  
  mac_vendors_cache[mac] = vendor
  return vendor