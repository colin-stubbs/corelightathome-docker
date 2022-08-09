#!/bin/bash

set -euo pipefail

LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/opt/corelight/lib}"
ZEEK_DISABLE_ZEEKYGEN_WARNINGS="${ZEEK_DISABLE_ZEEKYGEN_WARNINGS:-1}"
CORELIGHT_LICENSE="${CORELIGHT_LICENSE:-}"
IDAPTIVE_USERNAME="${IDAPTIVE_USERNAME:-}"
IDAPTIVE_PASSWORD="${IDAPTIVE_PASSWORD:-}"

# add auth credentials to package repository if provided
if [ "${IDAPTIVE_USERNAME}x" != "x" ] && [ "${IDAPTIVE_PASSWORD}x" != "x" ] ; then
  echo "machine pkgs.corelight.com/deb/stable
 login ${IDAPTIVE_USERNAME}
 password ${IDAPTIVE_PASSWORD}" > /etc/apt/auth.conf.d/corelight-softsensor.conf
fi

# add license if provided
if [ "${CORELIGHT_LICENSE}x" != "x" ] ; then
  echo -n "${CORELIGHT_LICENSE}" > /etc/corelight-license.txt
fi

# install corelight-softsensor if not already installed, exit with error if that fails
dpkg -s corelight-softsensor 1>/dev/null 2>&1

if [ "${?}x" != "0x" ] ; then
  apt -y install corelight-softsensor || exit 1
fi

# NOTE: this script assumes that /etc/corelight-softsensor.conf exists and is correctly configured,
# you should overwrite the default using a volume based import

# variables used by corelight-softsensor
export LD_LIBRARY_PATH ZEEK_DISABLE_ZEEKYGEN_WARNINGS

# start corelight
/opt/corelight/bin/corelight-softsensor start

# EOF

