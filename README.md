# Network Monitoring with eBPF

## Commands to run

Change the network interface to your interface in the [Makefile](./Makefile).

```make``` to compile the program.

To load the XDP program, run
```sudo make load```

To unload the XDP program, run
```sudo make unload```

[userspace.py](./userspace.py) updates the eBPF map from the userspace. Run it with
```sudo python3 userspace.py```