#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#define GUID_PREFIX_SIZE 12
#define WRITER_ENTITY_ID_SIZE 4
#define KEY_SIZE (GUID_PREFIX_SIZE + WRITER_ENTITY_ID_SIZE)

int main() 
{
    const char *ifname = "ens33";

    __u32 value=1;

    // 加载 BPF 对象文件
    struct bpf_object *obj;
    int prog_fd;
    obj = bpf_object__open_file("xdp_rtps.o", NULL);
    if (libbpf_get_error(obj)) 
    {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }
    if (bpf_object__load(obj)) 
    {
        fprintf(stderr, "Error loading BPF object file\n");
        return 1;
    }
    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "xdp"));
    if (prog_fd < 0) 
    {
        fprintf(stderr, "Error finding BPF program\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) 
    {
        perror("if_nametoindex");
        return 1;
    }
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) 
    {
        perror("bpf_set_link_xdp_fd");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "ip_map");
    if (map_fd < 0) 
    {
        fprintf(stderr, "Error finding BPF map\n");
        return 1;
    }

    // 设置 key 为 GuidPrefix + WriterEntityID 的组合（随便存的一个key）
    __u8 guid_prefix[GUID_PREFIX_SIZE] = {0x0a, 0xd0, 0x64, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x22, 0x11, 0x00, 0x00};
    __u32 writer_entity_id = htonl(0x00040103);  // WriterEntityID 需要转换为网络字节序

    __u8 key[KEY_SIZE];
    memcpy(key, guid_prefix, GUID_PREFIX_SIZE); // 拷贝 GuidPrefix
    memcpy(key + GUID_PREFIX_SIZE, &writer_entity_id, WRITER_ENTITY_ID_SIZE); // 拷贝 WriterEntityID

    if (bpf_map_update_elem(map_fd, key, &value, BPF_ANY) < 0) 
    {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("XDP program successfully loaded and key set in BPF map.\n");
    // 将 BPF map 固定到文件系统中
    if (bpf_obj_pin(map_fd, "/sys/fs/bpf/ip_map") < 0) {
    perror("bpf_obj_pin");
    return 1;
}

    return 0;
}
