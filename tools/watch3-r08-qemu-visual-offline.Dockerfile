# Offline capture runtime. Built on CI with network, EXECUTED with --network none.
# Never contains watch firmware; read-only guest rootfs is bind mounted by workflow.
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends   python3 python3-pil qemu-user ca-certificates dbus-daemon dbus-bin passwd &&   rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /tmp

# The GitHub runner's numeric UID may not exist inside ubuntu:24.04.
# D-Bus refuses startup with 'User ??? unknown' unless NSS resolves it.
# Match the host's exact non-root identity without granting new privileges.
ARG OFFLINE_UID=1001
ARG OFFLINE_GID=1001
RUN (getent group "$OFFLINE_GID" >/dev/null || groupadd -g "$OFFLINE_GID" uglyos_runner) && \
    (getent passwd "$OFFLINE_UID" >/dev/null || useradd -u "$OFFLINE_UID" -g "$OFFLINE_GID" -M -s /usr/sbin/nologin uglyos_runner)
