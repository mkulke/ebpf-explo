use bcc::perf_event::PerfMapBuilder;
use bcc::{Kprobe, Kretprobe, Uprobe, Uretprobe, BPF};
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn init_bpf() -> BPF {
    let code = r#"
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    // Copied from: include/netdb.h
    struct addrinfo
    {
        int ai_flags;         /* Input flags.  */
        int ai_family;        /* Protocol family for socket.  */
        int ai_socktype;      /* Socket type.  */
        int ai_protocol;      /* Protocol for socket.  */
        u32 ai_addrlen;       /* Length of socket address.  */ // CHANGED from socklen_t
        struct sockaddr *ai_addr; /* Socket address for socket.  */
        char *ai_canonname;       /* Canonical name for service location.  */
        struct addrinfo *ai_next; /* Pointer to next in list.  */
    };

    struct lookup_T {
        char c[84];
        struct addrinfo **results;
    };

    BPF_HASH(lookups, u32, struct lookup_T);
    BPF_HASH(hostnames, u32, struct lookup_T);
    BPF_PERF_OUTPUT(lookup_events);
    int lookup_uprobe(struct pt_regs *ctx) {
        if (!PT_REGS_PARM1(ctx)) {
            return 0;
        }
        struct lookup_T lookup = {};
        u32 tid = bpf_get_current_pid_tgid();
        bpf_probe_read_user_str(&lookup.c, sizeof(lookup.c), (void *) PT_REGS_PARM1(ctx));
        bpf_probe_read_user(&lookup.results, sizeof(lookup.results), &PT_REGS_PARM4(ctx));
        lookups.update(&tid, &lookup);
        return 0;
    }
    int lookup_uretprobe(struct pt_regs *ctx) {
        int ret = PT_REGS_RC(ctx);
        u32 tid = bpf_get_current_pid_tgid();
        struct lookup_T *lookup;
        lookup = lookups.lookup(&tid);
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
            hostnames.update(&ip, lookup);
        }
        lookups.delete(&tid);
        return 0;
    }
    BPF_HASH(sockets, u32, struct sock *);
    BPF_PERF_OUTPUT(host_connect_events);
    BPF_PERF_OUTPUT(ip_connect_events);
    int connect_kprobe(struct pt_regs *ctx, struct sock *sk)
    {
        u32 tid = bpf_get_current_pid_tgid();
        // stash the sock ptr for lookup on return
        sockets.update(&tid, &sk);
        return 0;
    };
    int connect_kretprobe(struct pt_regs *ctx)
    {
        int ret = PT_REGS_RC(ctx);
        u32 tid = bpf_get_current_pid_tgid();
        struct sock **skpp;
        skpp = sockets.lookup(&tid);
        if (skpp == 0) {
            return 0;
        }
        if (ret == 0) {
            struct sock *skp = *skpp;
            u32 daddr = skp->__sk_common.skc_daddr;

            struct lookup_T *lookup;
            lookup = hostnames.lookup(&daddr);
            if (lookup == 0) {
                ip_connect_events.perf_submit(ctx, &daddr, sizeof(daddr));
                return 0;
            }
            host_connect_events.perf_submit(ctx, &lookup->c, sizeof(lookup->c));
            hostnames.delete(&daddr);
        }
        sockets.delete(&tid);
        return 0;
    }
    "#;
    let mut bpf = BPF::new(code).expect("could not load bpf code");
    Kprobe::new()
        .handler("connect_kprobe")
        .function("tcp_v4_connect")
        .attach(&mut bpf)
        .expect("failed to attach kprobe");
    Kretprobe::new()
        .handler("connect_kretprobe")
        .function("tcp_v4_connect")
        .attach(&mut bpf)
        .expect("failed to attach kretprobe");
    Uprobe::new()
        .handler("lookup_uprobe")
        .binary("/lib/x86_64-linux-gnu/libc.so.6")
        .symbol("getaddrinfo")
        .attach(&mut bpf)
        .expect("failed to attach uprobe");
    Uretprobe::new()
        .handler("lookup_uretprobe")
        .binary("/lib/x86_64-linux-gnu/libc.so.6")
        .symbol("getaddrinfo")
        .attach(&mut bpf)
        .expect("failed to attach uprobe");
    bpf
}

fn ip_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|bytes| {
        let data: [u8; 4] = bytes.try_into().expect("expected 4 bytes");
        let addr: Ipv4Addr = data.into();
        println!("connect to {}", addr);
    })
}

fn host_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|bytes| {
        let data: [u8; 84] = bytes
            .try_into()
            .expect(&format!("expected 84 bytes, got {} bytes", bytes.len()));
        let host = String::from_utf8_lossy(&data);
        println!("connect to {}", host);
    })
}

fn main() {
    let runable = Arc::new(AtomicBool::new(true));
    let ctrlc_runable = runable.clone();

    ctrlc::set_handler(move || {
        println!("Aborting");
        ctrlc_runable.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let bpf = init_bpf();
    let mut table = bpf.table("host_connect_events").expect("cannot get table");
    println!("key_size: {}", &mut table.key_size());
    let mut host_map = PerfMapBuilder::new(table, host_callback)
        .build()
        .expect("cannot build perf map");
    let mut table = bpf.table("ip_connect_events").expect("cannot get table");
    println!("key_size: {}", &mut table.key_size());
    let mut ip_map = PerfMapBuilder::new(table, ip_callback)
        .build()
        .expect("cannot build perf map");

    while runable.load(Ordering::SeqCst) {
        host_map.poll(200);
        ip_map.poll(200);
    }
}
