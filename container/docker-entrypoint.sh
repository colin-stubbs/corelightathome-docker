#!/bin/bash -l

set -euo pipefail

LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/opt/corelight/lib}"
ZEEK_DISABLE_ZEEKYGEN_WARNINGS="${ZEEK_DISABLE_ZEEKYGEN_WARNINGS:-1}"
CORELIGHT_LICENSE="${CORELIGHT_LICENSE:-}"

# add license if provided
if [ "${CORELIGHT_LICENSE}x" != "x" ] ; then
  echo -n "${CORELIGHT_LICENSE}" > /etc/corelight-license.txt
fi

# configure corelight-update global settings from bind mounted file, edit as needed outside of the container
corelight-update update -global -path /etc/corelight-update/global.yaml

# run corelight-update once before starting to ensure all necessary files will exist and content is updated/available
corelight-update -o

# run corelight-update continuously in the background after one hour from now
nohup /bin/bash -l -c "sleep 3600 ; corelight-update 1>/var/log/corelight-update.log 2>&1;" 1>/dev/null 2>&1 &

# NOTE: this script assumes that /etc/corelight-softsensor.conf exists and is correctly configured,
# you should overwrite the default using a volume based import

# variables used by corelight-softsensor
export LD_LIBRARY_PATH ZEEK_DISABLE_ZEEKYGEN_WARNINGS

# start corelight
echo "Starting corelight-softsensor..."
/opt/corelight/bin/corelight-softsensor start

# EOF

