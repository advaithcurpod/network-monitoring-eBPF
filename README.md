# network-monitoring-eBPF

Change the network interface to your interface in ```start.sh``` and ```stop.sh```

### Commands to run

```chmod +x start.sh```

```chmod +x stop.sh```

The IP to be blocked is in the [xdp_ipv6_filter.c](./xdp_ipv6_filter.c) file. You can change it based on whuch IP you are blocking.

Open wireshark and see if all packets from the blocked IP are actually being dropped after loading the XDP program.

PS: **Currently program is failing** :? :/

To load the XDP program, run ```./start.sh```

To unload the XDP program, run ```./stop.sh```
