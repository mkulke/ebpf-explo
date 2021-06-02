# tracecon

A eBPF sample application, written in C & Rust using [libbpf-rs](https://github.com/libbpf/libbpf-rs). It will output all TCP connections that have been established on the host as ips and hostnames.

## Requirements

### Kernel

The project is built on technology like `CO-RE` and `BTF`, which is only available in more recent kernels (5.0-ish). Ubuntu 20.10 has configured and packaged all the required dependencies.

### Compilers

The project has been tested with LLVM v11 and Rust v1.52.1.

### Generate `vmlinux.h`

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

You can verify whether your kernel was built with BTF enabled:

```bash
cat /boot/config-$(uname -a) | grep CONFIG_DEBUG_INFO_BTF
```

## Build

```bash
cargo build
```

## Run

Start the program to instrument the eBPF probe and listen to events:

```bash
./target/debug/tracecon
```

In another shell perform some http calls:

```bash
curl -s www.jsonplaceholder.com > /dev/null
# Do not use a dns lookup
curl -s -H "Host: www.jsonplaceholder.com" 172.67.201.157 > /dev/null
```

The other shell should show the respective events:

```bash
received host event: www.jsonplaceholder.com
received ip event: 172.67.201.157
```
