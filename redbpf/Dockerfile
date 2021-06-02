FROM debian:buster

COPY prepare.sh /prepare.sh
RUN /prepare.sh
# RUN apt-get update
# RUN apt-get install -y ca-certificates gnupg curl
# RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main" >> /etc/apt/sources.list
# RUN echo "deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-11 main" >> /etc/apt/sources.list
# RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
# RUN apt-get update
# RUN apt-get -y install build-essential zlib1g-dev llvm-11-dev libclang-11-dev linux-source-4.19 libelf-dev
# RUN mkdir /src
# WORKDIR /src
# RUN tar xavf /usr/src/linux-source-4.19.tar.xz
# WORKDIR /src/linux-source-4.19
# RUN make defconfig
# RUN make prepare
# ENV CMAKE_C_COMPILER=clang-11
# ENV CMAKE_CXX_COMPILER=clang++-11
# RUN cargo install cargo-bpf
# WORKDIR /src
# RUN cargo bpf new hello-bpf
# WORKDIR /src/hello-bpf
# RUN cargo bpf add block_http
# COPY src/block_http/main.rs src/block_http/main.rs
# ENV KERNEL_SOURCE=/src/linux-source-4.19
# RUN cargo bpf build block_http
