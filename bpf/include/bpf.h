#ifndef _BPF_H
#define _BPF_H 1
#include <linux/bpf.h>
#include <stdint.h>
#include <endian.h>

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif

#define __section(s) __attribute__((section(s)))

#define bpf_htons(x) htobe16(x)

#define bpf_htonl(x) htobe32(x)

#define bpf_ntohs(x) be16toh(x)

#define bpf_ntohl(x) be32toh(x)

struct bpf_elf_map;

struct sk_buff;

struct bpf_sock_ops;

struct sk_msg_md;

static void *(*bpf_map_lookup_elem) (struct bpf_elf_map *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;

static int (*bpf_map_update_elem) (struct bpf_elf_map *map, const void *key, const void *value, __u64 flags) = (void *) BPF_FUNC_map_update_elem;

static int (*bpf_skb_load_bytes) (const struct sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *) BPF_FUNC_skb_load_bytes;

static int (*bpf_sock_hash_update) (struct bpf_sock_ops *skops, struct bpf_elf_map *map, void *key, __u64 flags) = (void *) BPF_FUNC_sock_hash_update;

static int (*bpf_msg_redirect_hash) (struct sk_msg_md *msg, struct bpf_elf_map *map, void *key, __u64 flags) = (void *) BPF_FUNC_msg_redirect_hash;

#endif
