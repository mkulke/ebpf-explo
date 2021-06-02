# Redbpf Sample

Probe and userland code in Rust.

## Prepare

### Docker

eBPF is a low-level technology on the Linux kernel. Docker is not a good fit to build eBPF code on MacOS or Windows environments. Docker ships its own kernel (linuxkit) and the kernel headers of the image might not match the running kernel.

It's not impossible, though. eBPF bytecode is supposed to be forward compatible. If we build an eBPF program on `debian:buster` with 4.19 kernel headers, the program should load on 5.10 kernel running in Docker's VM. Check the included `Dockerfile` for reference.

```
docker build -t ebpf-explo .
# remember to use `bash -l` to source the required env variables
docker run -it -v "$PWD:/ebpf-explo" ebpf-explo bash -l
```

### Vagrant

In the following steps we use Vagrant to provision a debian:buster vm with a VirtualBox backend. On a MacOS host machine run:

```
brew cask install virtualbox
brew cask install vagrant
vagrant up
```

## Build

Login to the provisioned vm using `vagrant ssh`.

```
sudo su -
cd /vagrant/ebpf-program
cargo bpf build block_http
```

## Load

```
cargo bpf load -i eth0 target/bpf/programs/block_http/block_http.elf
```
