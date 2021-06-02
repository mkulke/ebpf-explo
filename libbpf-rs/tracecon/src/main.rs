use anyhow::{bail, Result};
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;

#[path = "bpf/.output/tracecon.skel.rs"]
mod tracecon;
use tracecon::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    // payload: 4 bytes tag + 4 bytes ip + 84 bytes hostname
    let tag = data[0];
    if tag == 0 {
        let ip_bytes: [u8; 4] = data[4..8].try_into().unwrap();
        let ip: Ipv4Addr = ip_bytes.into();
        println!("received ip event: {:?}", ip);
    } else {
        let host_bytes: [u8; 84] = data[8..].try_into().unwrap();
        let host = String::from_utf8_lossy(&host_bytes);
        println!("received host event: {}", host);
    }
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = MgnsSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let _uprobe = skel.progs_mut().getaddrinfo_enter().attach_uprobe(
        false,
        -1,
        "/lib/x86_64-linux-gnu/libc.so.6",
        0x100930,
    )?;

    let _uretprobe = skel.progs_mut().getaddrinfo_exit().attach_uprobe(
        true,
        -1,
        "/lib/x86_64-linux-gnu/libc.so.6",
        0x100930,
    )?;

    let _kprobe = skel
        .progs_mut()
        .tcp_v4_connect_enter()
        .attach_kprobe(false, "tcp_v4_connect")?;

    let _kretprobe = skel
        .progs_mut()
        .tcp_v4_connect_exit()
        .attach_kprobe(true, "tcp_v4_connect")?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}
