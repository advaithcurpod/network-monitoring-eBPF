from bcc import BPF 
from time import sleep


prog = """
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("prog")
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <linux/in.h>

int dropall(struct CTXTYPE *ctx) 
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data  = (void *)(long)ctx->data;
    struct ethaddr *eth = data;
    if(eth + 1 > data_end){
        return XDP_PASS;
    }
    return XDP_DROP;
}

"""

device = "wlp1s0"

b =BPF(text=prog)
fn = b.load_func("dropall",BPF.XDP)
b.attach_xdp(device,0)

while True:
    sleep(1.5)
    try:
        b.trace_print()
    except KeyboardInterrupt:
        b.remove_xdp(device,0)
        exit()

