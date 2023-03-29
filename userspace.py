#!/usr/bin/env python3

# Import the bcc module
from bcc import BPF

# Define the map names and sizes
IP4_MAP = "ip4_map"
IP4_KEY_SIZE = 4
IP4_VALUE_SIZE = 4
IP6_MAP = "ip6_map"
IP6_KEY_SIZE = 16
IP6_VALUE_SIZE = 4

# Define some helper functions to convert IP addresses to bytes and vice versa
def ip4_to_bytes(ip):
    return bytes(map(int, ip.split(".")))

def ip6_to_bytes(ip):
    return bytes(int(h, 16) for h in ip.split(":"))

def bytes_to_ip4(b):
    return ".".join(map(str, b))

def bytes_to_ip6(b):
    return ":".join("{:02x}".format(h) for h in b)

# Load the object file containing the maps
bpf = BPF(src_file="map.o")

# Get references to the maps
ip4_map = bpf.get_table(IP4_MAP)
ip6_map = bpf.get_table(IP6_MAP)

# Print some information about the maps
print(f"IPv4 map: {len(ip4_map)} entries")
print(f"IPv6 map: {len(ip6_map)} entries")

# Print all the entries in the IPv4 map
print("IPv4 entries:")
for k, v in ip4_map.items():
    print(f"{bytes_to_ip4(k.value)}: {v.value}")

# Print all the entries in the IPv6 map
print("IPv6 entries:")
for k, v in ip6_map.items():
    print(f"{bytes_to_ip6(k.value)}: {v.value}")

# Add or remove some IP addresses from the maps as an example
ip4_map[ip4_to_bytes("192.168.123.1")] = IP4_VALUE_SIZE(1)
ip6_map[ip6_to_bytes("2001:db8::1")] = IP6_VALUE_SIZE(1)
del ip4_map[ip4_to_bytes("10.0.0.1")]
del ip6_map[ip6_to_bytes("fe80::1")]

# Print some information about the maps after modification
print(f"IPv4 map: {len(ip4_map)} entries")
print(f"IPv6 map: {len(ip6_map)} entries")

# Print all the entries in the IPv4 map after modification
print("IPv4 entries:")
for k, v in ip4_map.items():
    print(f"{bytes_to_ip4(k.value)}: {v.value}")

# Print all the entries in the IPv6 map after modification
print("IPv6 entries:")
for k, v in ip6_map.items():
    print(f"{bytes_to_ip6(k.value)}: {v.value}")