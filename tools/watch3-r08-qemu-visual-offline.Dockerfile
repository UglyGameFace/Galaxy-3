# Offline capture runtime. Built on CI with network, EXECUTED with --network none.
# Never contains watch firmware; read-only guest rootfs is bind mounted by workflow.
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends   python3 python3-pil qemu-user ca-certificates &&   rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /tmp
