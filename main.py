import subprocess
import scapy.all as scapy
import os
from scapy.layers.inet import IP


count = 0

ip_time_map = {}
max_threshold = 5
min_threshold = 5
interface = "wlp1s0" # change to any network interface. lo is the loopback interface

blocked = False
def block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unblock_ip(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

# handle a DOS attack by blacklisting an IP address if it sends too many requests
# return the ip address as string
def handle_dos(packet) -> str:
    global count
    ip_layer = packet[0].getlayer(IP)
    if(ip_layer.src not in ip_time_map):
        ip_time_map[ip_layer.src] = [0,0]       # [count,previous time]
    if(count%2==0):
            print(1.0/(packet[0].time - ip_time_map[ip_layer.src][1]))

            if((1.0/(packet[0].time - ip_time_map[ip_layer.src][1]) > max_threshold) and blocked == False):
                #pass    #this is the ip to drop(?)
                block_ip(ip_layer.src)
                print("Dropping this, the pps is"+ str(1.0/(packet[0].time - ip_time_map[ip_layer.src][1])))
                print("\n")
                # print(type(ip_layer.src))
            elif((1.0/(packet[0].time - ip_time_map[ip_layer.src][1]) < max_threshold) and blocked == True):
                 unblock_ip(ip_layer.src)
                 print("Unblocking this, the pps is"+ str(1.0/(packet[0].time - ip_time_map[ip_layer.src][1])))
                 print("\n")
            
            ip_time_map[ip_layer.src] = [ ip_time_map[ip_layer.src][0]+1, packet[0].time, max_threshold,min_threshold ] 
            print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))
            print(packet[0].time)   
    count += 1
    #print(count)


print("[*] Start sniffing...")
scapy.sniff(iface=interface, filter="icmp", prn=handle_dos)
print(ip_time_map)
print("[*] Stop sniffing")

