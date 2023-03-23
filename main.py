import subprocess

def block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unblock_ip(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

# handle a DOS attack by blacklisting an IP address if it sends too many requests
def handle_dos():
    pass