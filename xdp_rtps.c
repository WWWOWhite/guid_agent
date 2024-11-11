#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <netinet/in.h>

#define RTPS_HEADER_SIZE 20
#define INFO_TS_SIZE 12
#define GUID_PREFIX_OFFSET 8
#define GUID_PREFIX_SIZE 12
#define WRITER_ENTITY_ID_OFFSET 12
#define WRITER_ENTITY_ID_SIZE 4
#define KEY_SIZE (GUID_PREFIX_SIZE + WRITER_ENTITY_ID_SIZE)  // 16 字节的 key
#define INFO_TS_SUBMESSAGE_ID 0x09
#define DATA_SUBMESSAGE_ID 0x15

struct bpf_map_def SEC("maps") ip_map = 
{
    .type = BPF_MAP_TYPE_HASH,
    .key_size = KEY_SIZE,
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) 
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    __u32 *stored_value;
    __u8 key[KEY_SIZE];  // 用于存储 GuidPrefix + WriterEntityID 的组合 key

    // 检查以太网头边界
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 检查以太网协议类型
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 获取 IP 头，并检查边界
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 检查是否为 UDP 协议
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 获取 UDP 头，并检查边界
    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 解析 RTPS 数据包
    void *rtps_data = (void *)udp + sizeof(*udp);
    if ((void *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE) > data_end)
        return XDP_PASS;

    // 检查是否为 RTPS 数据包
    __u8 *rtps_header = (__u8 *)rtps_data;
    if ((void *)(rtps_header + 4) > data_end)
        return XDP_PASS;

    if (rtps_header[0] != 'R' || rtps_header[1] != 'T' || rtps_header[2] != 'P' || rtps_header[3] != 'S')
        return XDP_PASS;

    // 提取 GuidPrefix（第 9 到第 20 字节）
    if ((void *)(rtps_header + GUID_PREFIX_OFFSET + GUID_PREFIX_SIZE) > data_end)
        return XDP_PASS;
    
    // 将 GuidPrefix 拷贝到 key 的前 12 字节
    __builtin_memcpy(key, rtps_header + GUID_PREFIX_OFFSET, GUID_PREFIX_SIZE);

    // 提取 WriterEntityID（DATA 字段的第 13 到 16 字节
    if ((void *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE + WRITER_ENTITY_ID_OFFSET + WRITER_ENTITY_ID_SIZE) > data_end)
        return XDP_PASS;

    // 将 WriterEntityID 拷贝到 key 的最后 4 字节
    __u32 writer_entity_id = *((__u32 *)(rtps_data + RTPS_HEADER_SIZE + INFO_TS_SIZE + WRITER_ENTITY_ID_OFFSET));
    __builtin_memcpy(key + GUID_PREFIX_SIZE, &writer_entity_id, WRITER_ENTITY_ID_SIZE);

    // 检查第一个 submessage 类型是否为 INFO_TS_SUBMESSAGE_ID
    __u8 *submessage = (__u8 *)(rtps_data + RTPS_HEADER_SIZE);
    if ((void *)(submessage + 1) > data_end)
        return XDP_PASS;
    
    if (*submessage != INFO_TS_SUBMESSAGE_ID)
        return XDP_PASS;

    // 检查第二个 submessage 类型是否为 DATA_SUBMESSAGE_ID
    submessage += INFO_TS_SIZE;
    if ((void *)(submessage + 1) > data_end)
        return XDP_PASS;
    
    if (*submessage != DATA_SUBMESSAGE_ID)
        return XDP_PASS;

    // 检查 WriterEntityID 是否是特殊情况
    if (writer_entity_id == htonl(0x000100C2)) {
        // 特殊情况，直接 PASS
        return XDP_PASS;
    }

    // 在 ip_map 中查找对应的 value
    stored_value = bpf_map_lookup_elem(&ip_map, key);
    if (stored_value) {
        // 如果 value 存在，则 PASS 这个数据包
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
