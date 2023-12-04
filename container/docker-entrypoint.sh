#!/bin/bash -l

set -euo pipefail

LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/opt/corelight/lib}"
ZEEK_DISABLE_ZEEKYGEN_WARNINGS="${ZEEK_DISABLE_ZEEKYGEN_WARNINGS:-1}"
CORELIGHT_LICENSE="${CORELIGHT_LICENSE:-}"

# first start with missing file content due to docker volumes?
if [ ! -f /etc/corelight/EULA ] ; then
  echo "Unpacking original corelight-softsensor config files..."
  tar -C / -z -x -v -k -f /root/corelight-softsensor-original.tar.gz
fi

if [ ! -f /etc/corelight-update/global/cert.crt ] ; then
  echo "Unpacking original corelight-update config files..."
  tar -C / -z -x -v -k -f /root/corelight-update-original.tar.gz
fi

if [ ! -f /usr/share/GeoIP/GeoIP.dat ] ; then
  echo "Unpacking original GeoIP data files..."
  tar -C / -z -x -v -k -f /root/geoip-database-original.tar.gz
fi

# ensure lowercase for simplified boolean type comparison
CORELIGHT_UPDATE=`echo $CORELIGHT_UPDATE | tr [:upper:] [:lower:]`

if [ "${CORELIGHT_UPDATE}x" == "1x" ] || [ "${CORELIGHT_UPDATE}x" == "truex" ] || [ "${CORELIGHT_UPDATE}x" == "yesx" ] ; then
  # modify maxmind account # and license key if provided via env variables
  # NOTE: both must be set.
  if [ "${MAXMIND_ACCOUNT_ID}x" != "x" ] && [ "${MAXMIND_LICENSE_KEY}x" != "x" ] ; then
    sed -r \
      -e "s/^    account_id: .*$/    account_id: ${MAXMIND_ACCOUNT_ID}/" \
      -e "s/^    license_key: .*$/    license_key: \"${MAXMIND_LICENSE_KEY}\"/" \
      /etc/corelight-update/global.yaml > /etc/corelight-update/global.yaml.tmp
    test -f /etc/corelight-update/global.yaml.tmp && cat /etc/corelight-update/global.yaml.tmp > /etc/corelight-update/global.yaml
  fi

  # configure corelight-update global settings from bind mounted file, edit as needed outside of the container
  if [ -f /etc/corelight-update/global.yaml ] ; then
    echo "Updating corelight-update global config based on /etc/corelight-update/global.yaml"
    corelight-update update -global -path /etc/corelight-update/global.yaml
  fi

  # run corelight-update once before starting to ensure all necessary files will exist and content is updated/available
  if [ ! -f /var/corelight-update/files/defaultPolicy/suricata-rulesets/suricata.rules ] ; then
    echo "Starting corelight-update for the first time to initialise files..."
    corelight-update -o
  fi

  # run corelight-update continuously in the background after one minute from now
  nohup /bin/bash -l -c "sleep 60 ; corelight-update 1>/var/log/corelight-update.log 2>&1;" 1>/dev/null 2>&1 &
fi

# NOTE: this script assumes that /etc/corelight-softsensor.conf exists and is correctly configured,
# you should overwrite the default using a volume based import

# variables used by corelight-softsensor
export LD_LIBRARY_PATH ZEEK_DISABLE_ZEEKYGEN_WARNINGS

# start corelight
echo "Starting corelight-softsensor..."
/opt/corelight/bin/corelight-softsensor start

# EOF

