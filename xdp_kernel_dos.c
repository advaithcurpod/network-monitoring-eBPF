/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



struct packet_times {
    __u64 arr[10];
    __u64 count;
    __u64 prev_arrival;
    __u64 max_threshold;
    __u64 min_threshold;

};



struct bpf_map_def SEC("maps") ip_time_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(struct packet_times),
    .max_entries = 1024,
};


SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    __u32 key = ip->saddr;
    struct packet_times *val;
    __u64 cur_time = bpf_ktime_get_ns();
    //let the packet through if IP header size greater than packet
    if (ip + 1 > (struct iphdr *)data_end) {
        return XDP_PASS;
    }
    val = bpf_map_lookup_elem(&ip_time_map, &key);
    if (val) {
        if (cur_time - val->prev_arrival < val->max_threshold) {
            return XDP_DROP;
        }
        else{
            //now we need to update the threshold value looking at the previous arrival times
            if(val->count < 10){
                // we can wait for more packets before we shift the threshold
                val->arr[++val->count] = cur_time;
            }
            else{
                //remove the 1st packet in the array and shift all others by 1 unit to the left 
                for(int i = 1;i<10;++i){
                    val->arr[i] = val->arr[i-1];
                }
                val->arr[9] = cur_time;
                //find the sum of time_intervals between all consecutive packets
                __u64 total_interval = 0;
                for(int i = 1;i<10;++i){
                    total_interval += (val->arr[i] - val->arr[i-1]);
                }
                // get the average time_gap
                __u64 avg_gap = total_interval/10;
                __u64 factor = 2;
                //multiply it by factor=2 to get a new threshold
                __u64 new_threshold = avg_gap * 2;
                if(new_threshold< val->max_threshold && new_threshold > val->min_threshold){
                    val->max_threshold = new_threshold;
                }
            }
        }
    }
    else{
        //if the IP address hasnt been recorded the map, set the default threshold to 10 seconds
        val->prev_arrival = cur_time;
        //threshold in nanoseconds
        val->max_threshold = 10000000000;
        val->min_threshold = 5000000000;
        val->count = -1;
        val->arr[++val->count] = cur_time;
    }
    bpf_map_update_elem(&ip_time_map, &key, val, BPF_ANY);

    return XDP_PASS;
}



char _license[] SEC("license") = "GPL";
