# syntax=docker/dockerfile:1
#
# Percona Distribution for PostgreSQL 18 on Docker Hardened Images (Debian 13).
#
# Build (from the repository root):
#   docker buildx build --build-context dhi-common=dhi-common \
#       -t percona-distribution-postgresql:18-dhi percona-distribution-postgresql-18-dhi
ARG DHI_RUNTIME=dhi.io/debian-base:trixie@sha256:c12f6059a81c93b872dfbc6042d8c045256db32b7e23ed5765a90b89726eac93
ARG DHI_BUILDER=dhi.io/debian-base:trixie-dev@sha256:94571f3dc07fbc7166f6f1cbf1fe068a7647198ee2554e6b90d59a68cc8b053c

FROM ${DHI_RUNTIME} AS runtime-base

FROM ${DHI_BUILDER} AS builder
USER root
ARG PPG_REPO=release
ARG PG_MAJOR=18
ENV PPG_REPO_NAME=ppg-${PG_MAJOR} PPG_REPO=${PPG_REPO} DEBIAN_FRONTEND=noninteractive

COPY --from=dhi-common setup-apt.sh build-rootfs.sh apt-preferences /opt/dhi-common/
RUN /opt/dhi-common/setup-apt.sh

COPY --from=runtime-base / /rootfs
COPY packages.txt allowlist.txt /opt/image/
RUN /opt/dhi-common/build-rootfs.sh \
        --packages /opt/image/packages.txt \
        --allowlist /opt/image/allowlist.txt \
        --rootfs /rootfs \
        --report /rootfs/usr/share/percona/package-origins.tsv

# en_US.UTF-8 locale (maintainer scripts are not run, so it is compiled here)
RUN set -eux; \
    apt-get install -y -qq --no-install-recommends locales >/dev/null; \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8; \
    install -D -m 0644 /usr/lib/locale/locale-archive /rootfs/usr/lib/locale/locale-archive

# postgres user/group (uid/gid 70, as in dhi.io/postgres) and runtime directories
RUN set -eux; \
    echo 'postgres:x:70:70:PostgreSQL administrator:/var/lib/postgresql:/bin/bash' >> /rootfs/etc/passwd; \
    echo 'postgres:x:70:' >> /rootfs/etc/group; \
    if [ -f /rootfs/etc/shadow ]; then echo 'postgres:!:20000::::::' >> /rootfs/etc/shadow; fi; \
    install -d -o 70 -g 70 -m 0700 /rootfs/var/lib/postgresql/${PG_MAJOR}/data; \
    install -d -o 70 -g 70 -m 0755 /rootfs/var/lib/postgresql; \
    install -d -o 70 -g 70 -m 2775 /rootfs/run/postgresql; \
    install -d -o 70 -g 70 -m 0755 /rootfs/docker-entrypoint-initdb.d; \
    install -d -o 70 -g 70 -m 0750 /rootfs/var/lib/pgbackrest /rootfs/var/log/pgbackrest /rootfs/var/spool/pgbackrest; \
    rm -f /rootfs/etc/pgbackrest.conf; \
    sample=/rootfs/usr/share/postgresql/${PG_MAJOR}/postgresql.conf.sample; \
    sed -ri "s!^#?(listen_addresses)\s*=\s*\S+.*!\1 = '*'!" "$sample"; \
    grep -F "listen_addresses = '*'" "$sample"; \
    for f in /rootfs/usr/lib/*-linux-gnu/libnss_wrapper.so; do ln -sf "${f#/rootfs}" /rootfs/usr/lib/libnss_wrapper.so; done

COPY LICENSE /rootfs/licenses/LICENSE.Dockerfile
RUN cp /rootfs/usr/share/doc/percona-postgresql-${PG_MAJOR}/copyright /rootfs/licenses/COPYRIGHT.PostgreSQL

FROM ${DHI_RUNTIME}
ARG PG_MAJOR=18
LABEL org.opencontainers.image.title="Percona Distribution for PostgreSQL ${PG_MAJOR} (DHI)" \
      org.opencontainers.image.description="Percona Distribution for PostgreSQL ${PG_MAJOR} on Docker Hardened Images Debian 13" \
      org.opencontainers.image.vendor="Percona" \
      org.opencontainers.image.authors="info@percona.com" \
      org.opencontainers.image.base.name="dhi.io/debian-base:trixie"

COPY --from=builder /rootfs/ /

ENV LANG=en_US.UTF-8 \
    PG_MAJOR=${PG_MAJOR} \
    PGDATA=/var/lib/postgresql/${PG_MAJOR}/data \
    PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

VOLUME ["/var/lib/postgresql"]
EXPOSE 5432
USER 70
STOPSIGNAL SIGINT
CMD ["postgres"]
