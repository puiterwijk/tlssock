FROM fedora

RUN dnf install -y gnutls-devel meson ninja-build gcc

RUN mkdir /root/builddir
WORKDIR /root/builddir

VOLUME /mnt

RUN dnf install -y iproute
CMD ip a l && ip r l && meson /mnt && ninja && ninja test
