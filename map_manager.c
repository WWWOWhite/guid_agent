#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <string.h>

#define GUID_PREFIX_SIZE 12
#define WRITER_ENTITY_ID_SIZE 4
#define KEY_SIZE (GUID_PREFIX_SIZE + WRITER_ENTITY_ID_SIZE)

// 从 eBPF map 中删除数据的函数
void delete_map_entry(int map_fd, __u8 *key) {
    int ret = bpf_map_delete_elem(map_fd, key);
    if (ret != 0) {
        perror("bpf_map_delete_elem");
        exit(1);
    }
    printf("Successfully deleted map entry with key (GuidPrefix + WriterEntityID)\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);  // 输出key的十六进制值
    }
    printf("\n");
}

void print_key(__u8 *key) {
    printf("Guid:");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);  // 输出key的十六进制值
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <map_path> <add|del> <guid_prefix_writer_entity_id> <value>\n", argv[0]);
        return 1;
    }

    const char *map_path = argv[1];
    const char *operation = argv[2];

    __u8 key[KEY_SIZE];
    __u32 value;
    int map_fd = bpf_obj_get(map_path);

    if (map_fd < 0) {
        perror("Failed to open BPF map");
        return 1;
    }

    // 提取 guid_prefix_writer_entity_id
    if (argc >= 4) {
        if (strlen(argv[3]) != KEY_SIZE * 2) {
            fprintf(stderr, "Invalid key length. Expected %d hexadecimal characters.\n", KEY_SIZE * 2);
            return 1;
        }

        // 解析 key
        for (int i = 0; i < KEY_SIZE; i++) {
            sscanf(argv[3] + 2 * i, "%2hhx", &key[i]);
        }
    }

    if (strcmp(operation, "add") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage for add: %s <map_path> add <guid_prefix_writer_entity_id> <value>\n", argv[0]);
            return 1;
        }

        // 解析 value
        value = atoi(argv[4]);

        // 添加键值对到 map
        int ret = bpf_map_update_elem(map_fd, key, &value, BPF_ANY);
        if (ret != 0) {
            perror("bpf_map_update_elem");
            exit(1);
        }
        printf("Successfully load white ");
        print_key(key);  // 再次输出 key

    } else if (strcmp(operation, "del") == 0) {
        // 删除 map 中的键值对
        delete_map_entry(map_fd, key);

    } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return 1;
    }

    close(map_fd);
    return 0;
}

