FROM registry.redhat.io/ubi8:8.4-211 AS builder

RUN INSTALL_PKGS=" \
      rust-toolset \
      cmake \
      make \
      git \
      openssl-devel \
      llvm-toolset \
      cyrus-sasl \
      python36 \
      llvm \
      cyrus-sasl-devel \
      libtool \
      " && \
    yum install -y $INSTALL_PKGS && \
    rpm -V $INSTALL_PKGS && \
    yum clean all

RUN mkdir -p /src

WORKDIR /src
COPY . /src

RUN make build

# Copying to /usr/bin because copying from /src/target/release/vector to next stage doesnt seem to work in OSBS with imagebuilder
RUN cp /src/target/release/vector /usr/bin


FROM registry.redhat.io/ubi8:8.4-211

COPY --from=builder /usr/bin/vector /usr/bin/

WORKDIR /usr/bin
CMD ["/usr/bin/vector"]
