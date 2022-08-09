#!/bin/bash

if [ "${1}x" == "x" ] ; then exit 1 ; fi

LICENSE_KEY=${1}

mkdir -p /etc/geoip && \
    ln -sf /etc/geoip /usr/share/GeoIP && \
    cd /etc/geoip && \
    wget -O GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${LICENSE_KEY}&suffix=tar.gz" && \
    wget -O GeoLite2-City.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz" && \
    wget -O GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz" && \
    tar --strip-components=1 -z -x -v -f GeoLite2-ASN.tar.gz && \
    tar --strip-components=1 -z -x -v -f GeoLite2-City.tar.gz && \
    tar --strip-components=1 -z -x -v -f GeoLite2-Country.tar.gz && \
    rm -fv *.tar.gz *.txt

# EOF

