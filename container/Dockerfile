FROM debian:bullseye

MAINTAINER Colin Stubbs <cstubbs@gmail.com>

ARG MAXMIND_LICENSE_KEY

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY zkg-config.cfg /root/zkg-config.cfg
COPY profile_d_corelight.sh /etc/profile.d/corelight.sh

RUN echo "### Updating packages" && \
  apt update && \
  apt -y install git gnupg2 lsb-release file python3-pip iproute2 procps curl net-tools && \
  echo "### Setting up CoreLight apt repository" && \
  curl -fsSL https://packagecloud.io/corelight/stable/gpgkey | gpg --dearmor > /etc/apt/trusted.gpg.d/corelight_stable.gpg && \
  echo "deb [arch=arm64 signed-by=/etc/apt/trusted.gpg.d/corelight_stable.gpg] https://packagecloud.io/corelight/stable/debian bullseye main" > /etc/apt/sources.list.d/corelight-softsensor.list && \
  cat /etc/apt/sources.list.d/corelight-softsensor.list && \
  apt -y update && \
  echo "### Updating O/S" && \
  apt -y upgrade &&  \
  echo "### Installing CoreLight" && \
  apt -y install corelight-softsensor corelight-update && \
  cp /etc/corelight-softsensor.conf.example /etc/corelight-softsensor.conf && \
  echo "### Installing zkg" && \
  python3 -m pip install "zkg" && \
  mkdir /root/.zkg && \
  cp /root/zkg-config.cfg /root/.zkg/config && \
  echo "### Installing Suricata" && \
  pip3 install suricata-update && \
  echo "### Cleanup" && \
  apt clean cache ; \
  rm -rf /var/lib/apt/lists/*

ENTRYPOINT /usr/local/bin/docker-entrypoint
