#!/bin/bash
set -euo pipefail

if [ $EUID != 0 ]
then
  echo "$(basename "$0") must be run as root"
  exit 1
fi

# Install llvm + kernel source
apt-get update
apt-get -y install \
  ca-certificates \
  gnupg \
  curl
echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main" \
  >> /etc/apt/sources.list
echo "deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main" \
  >> /etc/apt/sources.list
curl -s https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
apt-get update
apt-get -y install \
  build-essential \
  zlib1g-dev \
  llvm-11-dev \
  libclang-11-dev \
  linux-source-4.19 \
  libelf-dev

# Prepare kernel headers
cd /usr/src
tar xaf linux-source-4.19.tar.xz
cd linux-source-4.19
make defconfig
make prepare
echo "export KERNEL_SOURCE=/usr/src/linux-source-4.19" >> /root/.profile

# Install rust + cargo-bpf
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
echo "export CMAKE_C_COMPILER=clang-11" >> /root/.profile
echo "export CMAKE_CXX_COMPILER=clang++-11" >> /root/.profile
source ~/.profile
cargo install cargo-bpf
