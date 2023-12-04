FROM debian:bookworm

MAINTAINER Colin Stubbs <cstubbs@gmail.com>

ARG MAXMIND_LICENSE_KEY

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY zkg-config.cfg /root/zkg-config.cfg
COPY profile_d_corelight.sh /etc/profile.d/corelight.sh

RUN echo "### Installing required packages" && \
  apt update && \
  apt -y install geoip-database git gnupg2 lsb-release file python3-pip iproute2 procps curl net-tools && \
  echo "### Setting up corelight apt repository" && \
  curl -fsSL https://packagecloud.io/corelight/stable/gpgkey | gpg --dearmor > /etc/apt/trusted.gpg.d/corelight_stable.gpg && \
  echo "deb [arch=arm64 signed-by=/etc/apt/trusted.gpg.d/corelight_stable.gpg] https://packagecloud.io/corelight/stable/debian bullseye main" > /etc/apt/sources.list.d/corelight-softsensor.list && \
  cat /etc/apt/sources.list.d/corelight-softsensor.list && \
  echo "### Updating / upgrading packages" && \
  apt -y update && \
  apt -y upgrade &&  \
  echo "### Installing corelight-softsensor and corelight-update" && \
  apt -y install corelight-softsensor corelight-update && \
  tar -v -z -c -f /root/corelight-softsensor-original.tar.gz /etc/corelight /var/corelight && \
  tar -v -z -c -f /root/corelight-update-original.tar.gz /etc/corelight-update /opt/corelight-update /var/corelight-update && \
  cp /etc/corelight-softsensor.conf.example /etc/corelight-softsensor.conf && \
  echo "### Installing zkg" && \
  python3 -m pip install "zkg" && \
  mkdir /root/.zkg && \
  cp /root/zkg-config.cfg /root/.zkg/config && \
  echo "### Installing suricata-update" && \
  pip3 install suricata-update && \
  echo "### Cleanup" && \
  apt clean cache ; \
  rm -rf /var/lib/apt/lists/*

ENTRYPOINT /usr/local/bin/docker-entrypoint
