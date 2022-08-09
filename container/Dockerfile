FROM debian:bullseye

MAINTAINER Colin Stubbs <cstubbs@gmail.com>

ARG MAXMIND_LICENSE_KEY
ARG IDAPTIVE_USERNAME
ARG IDAPTIVE_PASSWORD

COPY geoipupdate.sh /usr/bin/geoipupdate
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint

RUN echo "### Update GeoIP databases ( license key $MAXMIND_LICENSE_KEY )" && \
  apt update && apt -y install wget && \
  chmod 0755 /usr/bin/geoipupdate && \
  /usr/bin/geoipupdate $MAXMIND_LICENSE_KEY && \
  apt -y install git gnupg2 lsb-release file python3-pip iproute2 procps curl net-tools && \
  echo "### Setting up CoreLight apt repository ( $IDAPTIVE_USERNAME $IDAPTIVE_PASSWORD ) " && \
  wget -qO - https://pkgs.corelight.com/signing.pub | apt-key add - && \
  echo "machine pkgs.corelight.com/deb/stable\n login $IDAPTIVE_USERNAME\n password $IDAPTIVE_PASSWORD" > /etc/apt/auth.conf.d/corelight-softsensor.conf && \
  cat /etc/apt/auth.conf.d/corelight-softsensor.conf && \
  echo "deb [arch=arm64] https://pkgs.corelight.com/deb/stable bullseye main" > /etc/apt/sources.list.d/corelight-softsensor.list && \
  cat /etc/apt/sources.list.d/corelight-softsensor.list && \
  apt -y update && \
  echo "### Updating O/S" && \
  apt -y upgrade &&  \
  echo "### Installing CoreLight" && \
  apt -y install corelight-softsensor && \
  cp /etc/corelight-softsensor.conf.example /etc/corelight-softsensor.conf && \
  touch /etc/corelight/input_files/rdp-inference-server-wl.txt /etc/corelight/input_files/stepping-stone-server-wl.txt /etc/corelight/input_files/ssh-inference-server-wl.txt && \
  echo "### Installing Suricata" && \
  pip3 install suricata-update && \
  suricata-update update-sources --suricata-conf=/var/corelight/suricata/.suricata.yaml --suricata=/opt/corelight/bin/suricata -D /etc/corelight/suricata-update && \
  touch /etc/corelight/suricata-update/enable.conf /etc/corelight/suricata-update/disable.conf /etc/corelight/suricata-update/modify.conf /etc/corelight/suricata-update/custom_rules && \
  suricata-update \
    --disable-conf=/etc/corelight/suricata-update/disable.conf \
    --modify-conf=/etc/corelight/suricata-update/modify.conf \
    --enable-conf=/etc/corelight/suricata-update/enable.conf \
    --suricata-conf=/var/corelight/suricata/.suricata.yaml \
    --suricata=/opt/corelight/bin/suricata -D \
    /etc/corelight/suricata-update -o \
    /etc/corelight/rules \
    --local=/etc/corelight/suricata-update/custom_rules --no-test && \
  apt clean cache ; \
  rm -rf /var/lib/apt/lists/*

ENTRYPOINT /usr/local/bin/docker-entrypoint
