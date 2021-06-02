#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))

// Copied from: include/netdb.h
struct addrinfo
{
	int ai_flags;         		/* Input flags.  */
	int ai_family;        		/* Protocol family for socket.  */
	int ai_socktype;      		/* Socket type.  */
	int ai_protocol;      		/* Protocol for socket.  */
	u32 ai_addrlen;       		/* Length of socket address.  */ // CHANGED from socklen_t
	struct sockaddr *ai_addr; 	/* Socket address for socket.  */
	char *ai_canonname;       	/* Canonical name for service location.  */
	struct addrinfo *ai_next; 	/* Pointer to next in list.  */
};

struct lookup_T {
	char c[84];
	struct addrinfo **results;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct lookup_T);
} lookups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct lookup_T);
} hostnames SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

enum tag_T { IP = 0, HOSTNAME = 1};

struct event_T {
	u32 tag;
	u32 ip;
	char hostname[84];
};

SEC("uprobe/getaddrinfo")
int BPF_KPROBE(getaddrinfo_enter, const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
{
	struct lookup_T lookup = {};
	u32 tid = bpf_get_current_pid_tgid();
	bpf_probe_read_user_str(&lookup.c, sizeof(lookup.c), node);
	lookup.results = res;
	bpf_map_update_elem(&lookups, &tid, &lookup, 0);
	return 0;
}

SEC("uretprobe/getaddrinfo")
int BPF_KRETPROBE(getaddrinfo_exit, int ret)
{
	u32 tid = bpf_get_current_pid_tgid();
	struct lookup_T *lookup = bpf_map_lookup_elem(&lookups, &tid);
	if (lookup == 0) {
        	return 0;
        }
	if (ret == 0) {
		struct addrinfo *result;
		struct sockaddr *aa;
		struct in_addr ia;
		u32 ip;
		bpf_probe_read_user(&result, sizeof(result), lookup->results);
		bpf_probe_read_user(&aa, sizeof(aa), &result->ai_addr);
		bpf_probe_read_user(&ia, sizeof(ia), &((struct sockaddr_in *) aa)->sin_addr);
		ip = ia.s_addr;
		bpf_map_update_elem(&hostnames, &ip, lookup, 0);
        }
	bpf_map_delete_elem(&lookups, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
};

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
	u32 tid = bpf_get_current_pid_tgid();
	struct sock **sockpp = bpf_map_lookup_elem(&sockets, &tid);
	if (sockpp == 0) {
		return 0;
	}
  	if (ret == 0) {
		struct event_T event = {};
		struct sock *sockp = *sockpp;
		struct sock_common sock;
		bpf_probe_read_kernel(&sockp, sizeof(sockp), sockpp);
		bpf_probe_read_kernel(&sock, sizeof(sockp), &sockp->__sk_common);
		u32 daddr = sock.skc_daddr;
		struct lookup_T *lookup = bpf_map_lookup_elem(&hostnames, &daddr);
		if (lookup == 0) {
			event.tag = IP;
			event.ip = daddr;
		}
		else {
			event.tag = HOSTNAME;
			memcpy(&event.hostname, &lookup->c, sizeof(lookup->c));
			bpf_map_delete_elem(&hostnames, &daddr);
		}
		// ctx is implied in the signature macro
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  	}
 	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
