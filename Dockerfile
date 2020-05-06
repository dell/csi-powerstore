# Dockerfile to build PowerStore CSI Driver
FROM centos:7.6.1810

# dependencies, following by cleaning the cache
RUN yum install -y e2fsprogs xfsprogs which \
    && \
    yum clean all \
    && \
    rm -rf /var/cache/run

# validate some cli utilities are found
RUN which mkfs.ext4
RUN which mkfs.xfs
RUN echo "export PATH=$PATH:/sbin:/bin" > /etc/profile.d/ubuntu_path.sh

COPY "csi-powerstore" .
ENTRYPOINT ["/csi-powerstore"]