# corelightathome-docker

Corelight@Home in a docker container on a Raspberry Pi

Refer to: https://corelight.com/blog/corelight-at-home

Running Corelight@Home this way basically makes https://github.com/corelight/raspi-corelight unnecessary, though the install script in that repo is what the container build process has originally been based upon.

Running Corelight in a container is my preferred option. It is great because it's kind of a mess to install and run Corelight direct on the O/S and means you'll also wind up in a feature quagmire of support issues between O/S and Corelight packages.

NOTE: This container now optionally uses the `corelight-update` package to manage updates to the following,
1. GeoIP database content, assuming that you have a Maxmind GeoIP license to use, refer to https://www.maxmind.com/en/geolite2/signup
2. Suricata rules,
  a. From whatever sources you configure in ./corelight-update/configs/defaultPolicy/db-config.yaml, e.g. CrowdStrike Intelligence (if you have an appropriate subscription!)
  b. From custom content under ./corelight-update/configs/defaultPolicy/local-suricata
3. Zeek Threat Intelligence indicators,
  a. From whatever sources you configure in ./corelight-update/configs/defaultPolicy/db-config.yaml, e.g. CrowdStrike Intelligence (if you have an appropriate subscription!)
  b. From custom content under ./corelight-update/configs/defaultPolicy/local-intel
4. Corelight/Zeek packages,
  a. NOTE: I have not tested this capability as yet so results may vary.

The default is currently still to run `corelight-update` inside the container.

Though I now strongly recommend you run `corelight-update` separately even if it's from the same Raspberry Pi.

Refer to the documentation about environment variables that can be passed to the container.

The new container spec for running `corelight-update` separately is available here: https://github.com/colin-stubbs/corelight-update-docker

# Setup

## Get Docker

Install the latest Raspberry Pi OS 64-bit on your Pi. That's the whole point of this container at this point. The Corelight@Home docs and script assume you've installed an older 32-bit version, and it installs a 64-bit kernel, and some 64-bit packages, but still assumes the rest of the O/S is the default Raspberry Pi 32-bit version.

Installing the latest docker community edition is what you want, and it's trivial,

```
apt-get remove docker docker-engine docker.io containerd runc
apt-get update

apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable docker.service
docker ps
```

Make sure eth0 offloading features are disabled outside of the container, as even with host based networking it doesn't appear to be able to do it?

e.g. something like this in /etc/rc.local to configure eth0 appropriately.

```
root@corelight:/opt/docker/compose/corelightathome-docker# cat /etc/rc.local
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

# Print the IP address
_IP=$(hostname -I) || true
if [ "$_IP" ]; then
  printf "My IP address is %s\n" "$_IP"
fi

ifconfig eth0 inet 0.0.0.0 up

ethtool -K eth0 tx-checksum-ip-generic off
ethtool -K eth0 generic-segmentation-offload off
ethtool -K eth0 generic-receive-offload off

exit 0
root@corelight:/opt/docker/compose/corelightathome-docker#
```

## Get repo & Build

The `build.sh` helper script exists to show you how to build and rebuild reliably.

```
root@corelight:~# mkdir -p /opt/docker/compose
root@corelight:~# cd /opt/docker/compose/
root@corelight:/opt/docker/compose# git clone https://github.com/colin-stubbs/corelightathome-docker.git
Cloning into 'corelightathome-docker'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 18 (delta 1), reused 15 (delta 1), pack-reused 0
Receiving objects: 100% (18/18), 2.70 MiB | 5.30 MiB/s, done.
Resolving deltas: 100% (1/1), done.
root@corelight:/opt/docker/compose# cd corelightathome-docker/
root@corelight:/opt/docker/compose/corelightathome-docker#

root@corelight:/opt/docker/compose/corelightathome-docker# cat build.sh 
#!/bin/bash

# remove any existing container if something has changed
docker compose -f ./docker-compose.yml rm

# build the container
# fix perms on custom entrypoint as these may have been lost...
chmod 0755 container/docker-entrypoint.sh

# build a new container if necessary
# NOTE: cached layers may be used if there's no modifications in container/Dockerfile and related files
docker compose -f ./docker-compose.yml build

# EOF

root@corelight:/opt/docker/compose/corelightathome-docker# sh build.sh 
No stopped containers
[+] Building 169.8s (10/10) FINISHED                                                                                                                                                                  docker:default
 => [corelight internal] load build definition from Dockerfile                                                                                                                                                  0.1s
 => => transferring dockerfile: 1.47kB                                                                                                                                                                          0.0s
 => [corelight internal] load .dockerignore                                                                                                                                                                     0.0s
 => => transferring context: 2B                                                                                                                                                                                 0.0s
 => [corelight internal] load metadata for docker.io/library/debian:bullseye                                                                                                                                    3.2s
 => [corelight 1/5] FROM docker.io/library/debian:bullseye@sha256:54d33aaad0bc936a9a40d856764c7bc35c0afaa9cab51f88bb95f6cd8004438d                                                                             16.3s
 => => resolve docker.io/library/debian:bullseye@sha256:54d33aaad0bc936a9a40d856764c7bc35c0afaa9cab51f88bb95f6cd8004438d                                                                                        0.0s
 => => sha256:54d33aaad0bc936a9a40d856764c7bc35c0afaa9cab51f88bb95f6cd8004438d 1.85kB / 1.85kB                                                                                                                  0.0s
 => => sha256:eefb45317844a131035d89384dbbe3858a0c22f6b7884e56648bd6b22d206a8a 529B / 529B                                                                                                                      0.0s
 => => sha256:3a30687df9b732bb88601b6c6c7866d632d5c9d4260cc7ec0fd575abffbbee32 1.48kB / 1.48kB                                                                                                                  0.0s
 => => sha256:31f5dc1f52c865588c43d8ec718f14d430e149b28f0b28232da825da7ae28f76 53.70MB / 53.70MB                                                                                                                9.6s
 => => extracting sha256:31f5dc1f52c865588c43d8ec718f14d430e149b28f0b28232da825da7ae28f76                                                                                                                       6.4s
 => [corelight internal] load build context                                                                                                                                                                     0.0s
 => => transferring context: 2.11kB                                                                                                                                                                             0.0s
 => [corelight 2/5] COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint                                                                                                                                  0.6s
 => [corelight 3/5] COPY zkg-config.cfg /root/zkg-config.cfg                                                                                                                                                    0.1s
 => [corelight 4/5] COPY profile_d_corelight.sh /etc/profile.d/corelight.sh                                                                                                                                     0.1s
 => [corelight 5/5] RUN echo "### Updating packages" &&   apt update &&   apt -y install git gnupg2 lsb-release file python3-pip iproute2 procps curl net-tools &&   echo "### Setting up CoreLight apt repo  130.9s
 => [corelight] exporting to image                                                                                                                                                                             18.6s
 => => exporting layers                                                                                                                                                                                        18.6s
 => => writing image sha256:84c7001a184a1204dd00db37b68b0f1d3113a66054acc7c0e91ca8b296d2c86e                                                                                                                    0.0s 
 => => naming to docker.io/library/corelight:latest                                                                                                                                                             0.0s 
root@corelight:/opt/docker/compose/corelightathome-docker# 
```

## Configure

### Environment Variables

This will inject the Corelight license that will be needed for the sensor to actually run.

Copy the .env example file and edit, there's only three variables to configure, e.g.

```
root@corelight:/opt/docker/compose/corelightathome-docker# cp dot-env-example .env
root@corelight:/opt/docker/compose/corelightathome-docker# vim .env
root@corelight:/opt/docker/compose/corelightathome-docker# cat .env
CORELIGHT_LICENSE="LICENSEGOHERE"
CORELIGHT_UPDATE="1"
MAXMIND_ACCOUNT_ID="ACCOUNT_ID_GOES_HERE"
MAXMIND_LICENSE_KEY="LICENSE_KEY_GOES_HERE"
root@corelight:/opt/docker/compose/corelightathome-docker#
```

#### CORELIGHT_LICENSE

This is the raw content from the `corelight-license.txt` that you received.

#### CORELIGHT_UPDATE

Indicates whether `corelight-update` should be run inside the container alongside the sensor.

The default is to run `corelight-update` so you need to set this to a negative (1, false or no) if you want to continue running this here. You can alternatively run it as a seperate container on the same Raspberry Pi you're using for Corelight@Home, or somewhere else. The new container spec is available here: https://github.com/colin-stubbs/corelight-update-docker

Values of `1`, `0`, `yes`, `no`, `true` or `false` will work.

A case insenstive comparison is actually used so `Yes`, `YES`, `TRUE`, `True` will also be acknowledged.

#### MAXMIND_ACCOUNT_ID & MAXMIND_LICENSE_KEY

These are obtained after signing up for a free MaxMind GeoLite2 license here: https://www.maxmind.com/en/geolite2/signup

Set as appropriate once you have a license.

### copy .example files

Use the setup.sh script, it will prompt you to overwrite files if they already exist for some reason.

```
root@corelight:/opt/docker/compose/corelightathome-docker# sh setup.sh 
'corelight-softsensor.conf.example' -> 'corelight-softsensor.conf'
cp: overwrite 'local.zeek'? n
cp: overwrite 'corelight-update/global.yaml'? n
cp: overwrite 'corelight-update/configs/defaultPolicy/db-config.yaml'? n
root@corelight:/opt/docker/compose/corelightathome-docker# 
```

### corelight-update globals

You'll need to edit `./corelight-update/global.yaml` to:
1. Enable and configure GeoIP database updates from Maxmind
2. Configure remote global conf files, e.g. Suricata rules from URL's
3. Other features such as verbosity, update intervals etc

```
root@corelight:/opt/docker/compose/corelightathome-docker# cat ./corelight-update/global.yaml
verbose: false
exp_features: false
webserver:
    enable: false
    tls: true
    tls_cert: /etc/corelight-update/global/cert.crt
    tls_key: /etc/corelight-update/global/cert.key
    port: 8443
process_feeds: true
interval_minutes: 60
geoip:
    enabled: true
    interval_hours: 4
    account_id: 123456
    license_key: "LICENSEKEYGOHERE"
    database_directory: /var/corelight-update/files/all/geoip
remote_global_conf_files: []
parallel_push_limit: 10
auto_update_policies:
    enable: true
    filename: db-config.yaml
root@corelight:/opt/docker/compose/corelightathome-docker# 
```

### corelight-update defaultPolicy

If you want to customise the configuration of corelight-update you'll need to copy the example file as below,

```
root@corelight:/opt/docker/compose/corelightathome-docker# cp ./corelight-update/configs/defaultPolicy/db-config.yaml.example ./corelight-update/configs/defaultPolicy/db-config.yaml
root@corelight:/opt/docker/compose/corelightathome-docker# vim ./corelight-update/configs/defaultPolicy/db-config.yaml
```

For example, you may want to utilise CrowdStrike Threat Intelligence indicators,

```
root@corelight:/opt/docker/compose/corelightathome-docker# diff -u ./corelight-update/configs/defaultPolicy/db-config.yaml.example ./corelight-update/configs/defaultPolicy/db-config.yaml   
--- ./corelight-update/configs/defaultPolicy/db-config.yaml.example     2023-09-28 14:57:56.585139366 +1000
+++ ./corelight-update/configs/defaultPolicy/db-config.yaml     2023-09-28 15:11:17.256964907 +1000
@@ -6,15 +6,15 @@
 input_management:
     default_input: true
 crowdstrike_config:
-    id: ""
-    secret: ""
+    id: "API_CLIENT_ID"
+    secret: "API_CLIENT_SECRET"
     member_cid: ""
-    cloud: us-1
+    cloud: us-2
     host_override: ""
     base_path_override: ""
     debug: false
 crowdstrike_indicators:
-    enabled: false
+    enabled: true
     interval_hours: 1
     request_limit: 10000
     enable_do_notice: true
root@corelight:/opt/docker/compose/corelightathome-docker# 
```

NOTE: There does not appear to be a reason to set member_cid
NOTE: If using `crowdstrike_indicators.targets` or `crowdstrike_indicators.threat_types` you will likely need to single quote encapsulate strings. e.g. 'Technology' for threat_types. You'll get an error otherwise.

# Run

You should be using `docker compose up` or similar, e.g. with `-d` to detach unless you really want the container to output to your terminal immediately.

View the container logs using `docker logs %{CONTAINER_ID}%` in preference to not detaching simply to view logs.

The docker entrypoint script performs the following, so you may see output related to:
1. Output of the env var $CORELIGHT_LICENSE to /etc/corelight-license.txt
2. `corelight-update` modifications to global settings, including setting Maxmind GeoIP from env variables
3. `corelight-update -o` running and completing successfully (hopefully!) first before anything else happens
4. A forked nohup'ed instance of `corelight-update` being started
5. `/opt/corelight/bin/corelight-softsensor start` running and remaining attached

```
root@corelight:/opt/docker/compose/corelightathome-docker# docker compose up -d                                                                                                                                      
[+] Running 1/1                                                                                                                                                                                                      
 ✔ Container corelightathome-docker-corelight-1  Started                                                                                                                                                        0.0s 
root@corelight:/opt/docker/compose/corelightathome-docker# docker ps
CONTAINER ID   IMAGE              COMMAND                  CREATED         STATUS         PORTS     NAMES
d1833b6acd29   corelight:latest   "/bin/sh -c /usr/loc…"   4 seconds ago   Up 3 seconds             corelightathome-docker-corelight-1
root@corelight:/opt/docker/compose/corelightathome-docker# 
root@corelight:/opt/docker/compose/corelightathome-docker# docker logs d1833b6acd29
2023/09/28 05:50:56 ** Starting Global Tasks **
2023/09/28 05:50:57 Downloaded: /var/corelight-update/working/all/suricata-sources/corelight.rules
2023/09/28 05:50:57 Downloaded source: Corelight
2023/09/28 05:50:57 ** Finished Global Tasks **
2023/09/28 05:50:57 Auto Policy Update enabled, auto-updating policies
2023/09/28 05:50:57 Successfully updated policy defaultPolicy
2023/09/28 05:50:57 ** Starting Process and Deploy for policy: defaultPolicy **
2023/09/28 05:50:57 ** Starting processing policy: defaultPolicy **
2023/09/28 05:50:57 Using global suricata source for Corelight
2023/09/28 05:51:31 Downloaded: /var/corelight-update/working/defaultPolicy/suricata-sources/emerging.rules.tar.gz
2023/09/28 05:51:31 Downloaded source: ET/Open
2023/09/28 05:51:33 Downloaded: /var/corelight-update/working/defaultPolicy/suricata-sources/sslblacklist.rules
2023/09/28 05:51:33 Downloaded source: SSLBL
2023/09/28 05:51:33 ** Start Processing CrowdStrike Indicators for defaultPolicy **
Downloading CrowdStrike Intel for Indicator Type ip_address for policy: defaultPolicy
2023/09/28 05:51:33 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'ip_address'
Downloading Indicators 100% [] (7244/7244, 4104 indicators/s) [1s]
Downloading CrowdStrike Intel for Indicator Type ip_address_block for policy: defaultPolicy
2023/09/28 05:51:35 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'ip_address_block'
    No new indicators to download
Downloading CrowdStrike Intel for Indicator Type url for policy: defaultPolicy
2023/09/28 05:51:35 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'url'
Downloading Indicators 100% [] (209405/209405, 3115 indicators/s) [1m7s]   
Downloading CrowdStrike Intel for Indicator Type email_address for policy: defaultPolicy
2023/09/28 05:52:42 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'email_address'
Downloading Indicators 100% [] (125/125, 500 indicators/s) [0s]
Downloading CrowdStrike Intel for Indicator Type domain for policy: defaultPolicy
2023/09/28 05:52:43 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'domain'
Downloading Indicators 100% [] (187848/187848, 3327 indicators/s) [56s]    
Downloading CrowdStrike Intel for Indicator Type x509_subject for policy: defaultPolicy
2023/09/28 05:53:39 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'x509_subject'
    No new indicators to download
Downloading CrowdStrike Intel for Indicator Type username for policy: defaultPolicy
2023/09/28 05:53:39 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'username'
Downloading Indicators 100% [] (54/54, 245 indicators/s) [0s] 
Downloading CrowdStrike Intel for Indicator Type hash_md5 for policy: defaultPolicy
2023/09/28 05:53:40 with filter: malicious_confidence:'high' + last_updated:>='2023-09-25' + type:'hash_md5'
Downloading Indicators  99% [] (125463/125464, 2784 indicators/s) [41s:0s]
Downloading CrowdStrike Intel for Indicator Type hash_sha256 for policy: defaultPolicy
2023/09/28 05:54:21 with filter: malicious_confidence:'high' + last_updated:>='2023-09-25' + type:'hash_sha256'
Downloading Indicators  99% [] (128002/128005, 2751 indicators/s) [43s:0s] 
Downloading CrowdStrike Intel for Indicator Type file_name for policy: defaultPolicy
2023/09/28 05:55:05 with filter: malicious_confidence:'high' + last_updated:>='2023-08-29' + type:'file_name'
Downloading Indicators 100% [] (55/55, 228 indicators/s) [0s] 
2023/09/28 05:55:06 ** Finished Processing CrowdStrike Indicators for defaultPolicy **
2023/09/28 05:55:06 Downloaded: /var/corelight-update/working/defaultPolicy/icannTLD/effective_tld_names.dat
2023/09/28 05:55:10 179 changed rules from /opt/corelight-update/corelight-recommended/disable.conf
2023/09/28 05:55:10 903 changed rules from /opt/corelight-update/corelight-recommended/enable.conf
2023/09/28 05:55:10 Extracted IP rules from the Suricata ruleset:
 disabled 211 Suricata rules
 created 8633 Intel rules
2023/09/28 05:55:10 Extracted JA3 rules from the Suricata ruleset:
 disabled 107 Suricata rules
 created 107 Intel rules
2023/09/28 05:55:10 53654 total rules
2023/09/28 05:55:10 40670 enabled rules
2023/09/28 05:55:10 12984 disabled rules
2023/09/28 05:55:11 Suricata Corelight RELEASE is installed
2023/09/28 05:55:11 Suricata is testing ruleset: /var/corelight-update/working/defaultPolicy/suricata-output/suricata.rules
2023/09/28 05:55:11 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/suricata.yaml
2023/09/28 05:55:11 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/classification.config
2023/09/28 05:55:11 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/reference.config
2023/09/28 05:55:11 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/threshold.config
28/9/2023 -- 05:55:11 - <Info> - Running suricata under test mode
28/9/2023 -- 05:55:11 - <Notice> - This is Suricata version 6.0.14-corelight RELEASE running in SYSTEM mode
28/9/2023 -- 05:55:11 - <Info> - CPUs/cores online: 4
28/9/2023 -- 05:55:11 - <Info> - Setting engine mode to IDS mode by default
28/9/2023 -- 05:55:11 - <Info> - HTTP memcap: 0
28/9/2023 -- 05:55:11 - <Info> - FTP memcap: 67108864
28/9/2023 -- 05:55:11 - <Info> - Preparing unexpected signal handling
28/9/2023 -- 05:55:11 - <Info> - Max dump is 0
28/9/2023 -- 05:55:11 - <Info> - Core dump setting attempted is 0
28/9/2023 -- 05:55:11 - <Info> - Core dump size set to 0
28/9/2023 -- 05:55:11 - <Warning> - [ERRCODE: SC_WARN_NO_STATS_LOGGERS(261)] - stats are enabled but no loggers are active
28/9/2023 -- 05:55:14 - <Info> - 1 rule files processed. 40670 rules successfully loaded, 0 rules failed
28/9/2023 -- 05:55:14 - <Info> - Threshold config parsed: 0 rule(s) found
28/9/2023 -- 05:55:16 - <Info> - 40673 signatures processed. 1035 are IP-only rules, 5361 are inspecting packet payload, 34260 inspect application layer, 0 are decoder event only
28/9/2023 -- 05:55:30 - <Notice> - Configuration provided was successfully loaded. Exiting.
28/9/2023 -- 05:55:30 - <Info> - cleaning up signature grouping structure... complete

Suricata-Main: no process found

2023/09/28 05:55:30 error error reloading rules exit status 1
2023/09/28 05:55:30 ** Start processing Intel files **
2023/09/28 05:55:30 no disable.intel file - skipping
2023/09/28 05:55:38 Added 471593 records to intel file
2023/09/28 05:55:38 Removed 0 records from intel file
2023/09/28 05:55:38 ** Finished processing Intel files **
2023/09/28 05:55:39 ** Finished processing policy: defaultPolicy **
2023/09/28 05:55:39 No Fleet details for policy: defaultPolicy
2023/09/28 05:55:39 ** Starting deploying to non-Fleet managed sensors for policy: defaultPolicy **
2023/09/28 05:55:39 ** Start pushing Intel for policy: defaultPolicy **
2023/09/28 05:55:39 Push Intel for sensor: docker
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/intel-files/intel.dat to /etc/corelight/intel/intel.dat
2023/09/28 05:55:39 ** Finished pushing Intel for policy: defaultPolicy **
2023/09/28 05:55:39 ** Starting push Suricata files for policy: defaultPolicy **
2023/09/28 05:55:39 Push Suricata for sensor: docker
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/suricata-rulesets/suricata.rules to /etc/corelight/rules/suricata.rules
2023/09/28 05:55:39 Copying /etc/corelight-update/configs/defaultPolicy/suricata.yaml to /var/corelight/suricata/suricata.yaml
2023/09/28 05:55:39 Copying /etc/corelight-update/configs/defaultPolicy/threshold.config to /var/corelight/suricata/threshold.config
2023/09/28 05:55:39 Copying /etc/corelight-update/configs/defaultPolicy/classification.config to /var/corelight/suricata/classification.config
2023/09/28 05:55:39 Copying /etc/corelight-update/configs/defaultPolicy/reference.config to /var/corelight/suricata/reference.config
2023/09/28 05:55:39 ** Finished push Suricata files to sensors for policy: defaultPolicy **
2023/09/28 05:55:39 No new Package bundle to deploy for policy: defaultPolicy
2023/09/28 05:55:39 ** Starting pushing Input files for policy: defaultPolicy **
2023/09/28 05:55:39 Push Input files for sensor: docker
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/1st_level_public_icann.dat to /etc/corelight/input_files/1st_level_public_icann.dat
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/2nd_level_public_icann.dat to /etc/corelight/input_files/2nd_level_public_icann.dat
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/3rd_level_public_icann.dat to /etc/corelight/input_files/3rd_level_public_icann.dat
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/4th_level_public_icann.dat to /etc/corelight/input_files/4th_level_public_icann.dat
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/cert-hygiene-server-wl.txt to /etc/corelight/input_files/cert-hygiene-server-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/cert-hygiene-sni-wl.txt to /etc/corelight/input_files/cert-hygiene-sni-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/datared-dns-domain-wl.txt to /etc/corelight/input_files/datared-dns-domain-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/datared-files-mime-wl.txt to /etc/corelight/input_files/datared-files-mime-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/datared-http-hostname-wl.txt to /etc/corelight/input_files/datared-http-hostname-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/datared-http-uri-wl.txt to /etc/corelight/input_files/datared-http-uri-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/datared-weird-name-wl.txt to /etc/corelight/input_files/datared-weird-name-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/encryption-detection-server-wl.txt to /etc/corelight/input_files/encryption-detection-server-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/sni-wl.txt to /etc/corelight/input_files/sni-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/ssh-inference-server-wl.txt to /etc/corelight/input_files/ssh-inference-server-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/stepping-stone-server-wl.txt to /etc/corelight/input_files/stepping-stone-server-wl.txt
2023/09/28 05:55:39 Copying /var/corelight-update/files/defaultPolicy/input-files/trusted_domains.dat to /etc/corelight/input_files/trusted_domains.dat
2023/09/28 05:55:39 ** Finished pushing general Input files for policy: defaultPolicy **
2023/09/28 05:55:39 ** Finished deploying for policy: defaultPolicy **
2023/09/28 05:55:39 ** Finished Process and Deploy for policy: defaultPolicy **
Starting corelight-softsensor...
supervisor: Licensed to corelighthome until 2024-06-13 00:00:00 UTC
Starting Corelight Software Sensor...
supervisor: Disabling hardware features on eth0 and bringing up the interface...done
supervisor: Running 4 Zeek workers.
suricata: This is Suricata version 6.0.14-corelight RELEASE running in SYSTEM mode
logger: Rotated/postprocessed leftover log 'conn.log' -> 'conn-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'suricata_zeek_stats.log' -> 'suricata_zeek_stats-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'http.log' -> 'http-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'unknown_mime_type_discovery.log' -> 'unknown_mime_type_discovery-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'files.log' -> 'files-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'weird.log' -> 'weird-23-09-28_05.00.01.log' 
logger: Rotated/postprocessed leftover log 'dns.log' -> 'dns-23-09-28_05.00.02.log' 
logger: Rotated/postprocessed leftover log 'ssl.log' -> 'ssl-23-09-28_05.00.02.log' 
logger: Rotated/postprocessed leftover log 'dhcp.log' -> 'dhcp-23-09-28_05.00.21.log' 
logger: Rotated/postprocessed leftover log 'ssh.log' -> 'ssh-23-09-28_05.00.22.log' 
logger: Rotated/postprocessed leftover log 'ntp.log' -> 'ntp-23-09-28_05.03.13.log' 
logger: Rotated/postprocessed leftover log 'suricata_corelight.log' -> 'suricata_corelight-23-09-28_05.04.17.log' 
logger: Rotated/postprocessed leftover log 'syslog.log' -> 'syslog-23-09-28_05.04.21.log' 
logger: Rotated/postprocessed leftover log 'stats.log' -> 'stats-23-09-28_05.04.33.log' 
logger: Rotated/postprocessed leftover log 'notice.log' -> 'notice-23-09-28_05.04.41.log' 
logger: Rotated/postprocessed leftover log 'conn_long.log' -> 'conn_long-23-09-28_05.04.41.log' 
logger: Rotated/postprocessed leftover log 'dpd.log' -> 'dpd-23-09-28_05.05.09.log' 
logger: Rotated/postprocessed leftover log 'weird_stats.log' -> 'weird_stats-23-09-28_05.05.25.log' 
logger: Rotated/postprocessed leftover log 'corelight_license_capacity.log' -> 'corelight_license_capacity-23-09-28_05.05.25.log' 
logger: Rotated/postprocessed leftover log 'capture_loss.log' -> 'capture_loss-23-09-28_05.05.34.log' 
logger: Rotated/postprocessed leftover log 'reporter.log' -> 'reporter-23-09-28_05.09.26.log' 
logger: Loading license from environment variable
logger: cannot open /etc/corelight/input_files/rdp-inference-server-wl.txt
worker-02: error in /builtin/corelight/conn-decorate.zeek, line 23: Failed to open GeoIP location database (lookup_location(c$id$orig_h))
root@corelight:/opt/docker/compose/corelightathome-docker# 
```

# Optional

## Zeek Intelligence Feeds

If you'd like to incorporate https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds, be sure to clone that repo to a folder under `./zeek-intel/` e.g. `./zeek-intel/Zeek-Intelligence-Feeds`

You can then modify local.zeek similar to the below,

```
## If there are additional scripts you would like to load, they can be defined in
## this script.

##! Load Intel Framework
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += {
        "/etc/corelight/intel/intel.dat",
# This assumes you've cloned https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds to be available via /etc/corelight/intel/Zeek-Intelligence-Feeds/
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/Amnesty_NSO_Domains.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/Cyber_Threat_Coalition_Domain_Blacklist.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-ipblocklist.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-malware.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-threatfox-ip.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-urlhaus.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ja3-fingerprints.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/alienvault.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/atomspam.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/binarydefense.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/censys.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cloudzy.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cobaltstrike_ips.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/compromised-ips.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cps-collected-iocs.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_domain.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_ip.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_ip_unverified.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/ellio.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/fangxiao.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/filetransferportals.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/illuminate.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/illuminate_ja3.intel",
# This one's huge and appears to likely be noise.
##       "/etc/corelight/intel/Zeek-Intelligence-Feeds/inversion.intel",       
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/james-inthe-box.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/lockbit_ip.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/log4j_ip.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/mirai.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/openphish.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/predict_intel.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/ragnar.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/rutgers.intel",
# Some JA3 fingerprints in here are common and useless to perform detection based on
##        "/etc/corelight/intel/Zeek-Intelligence-Feeds/salesforce-ja3-fingerprints.intel",
# This one's huge and appears to likely be noise.
##        "/etc/corelight/intel/Zeek-Intelligence-Feeds/sans.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/scumbots.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/shadowwhisperer-malware.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/sip.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/stalkerware.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/talos.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/tor-exit.intel",
        "/etc/corelight/intel/Zeek-Intelligence-Feeds/tweetfeed.intel",
};

## The Corelight Encrypted Traffic Collection (ETC)
#@load Corelight/cert-hygiene
#@load Corelight/ssh-inference
#@load Corelight/ConnViz

# Load the Community ID plugin to add the community ID hash to your conn log.
#@load Corelight/CommunityID

# Load Open Source Packages
# NOTE: this came from https://github.com/corelight/softsensor-docker-prototype/blob/main/image-files/local.zeek.sh ?
# NOTE: also referenced by corelight-update, however the folder may not exist until after corelight-update is first run?
# Uncomment if it actually has a zeek package to load, if folder is empty corelight-softsensor will crash
# @load /etc/corelight/packages
```

NOTE: You're responsible for scheduling regular `git pull`'s of Zeek-Intelligence-Feeds in order to receive updates.

# Logging

## Elastic

TBC

# Debugging

Mostly you'll want to exec your way into the container using `docker exec -it %{CONTAINER_ID}% /bin/bash` so that you can poke around and work out what's going on.

For example, to test and debug `corelight-update` do something like this where you manually run it with arguments `-o` to run once and if necessary with `-d` to enable debugging.

```
root@corelight:/opt/docker/compose/corelightathome-docker# docker exec -it 5be5ddd51ace /bin/bash
root@corelight:/# corelight-update -o
2023/09/28 05:39:40 ** Starting Global Tasks **
2023/09/28 05:39:41 Resp Code: 304 Not Modified; Using cached /var/corelight-update/working/all/suricata-sources/corelight.rules
2023/09/28 05:39:41 ** Finished Global Tasks **
2023/09/28 05:39:41 Auto Policy Update enabled, auto-updating policies
2023/09/28 05:39:41 Successfully updated policy defaultPolicy
2023/09/28 05:39:41 ** Starting Process and Deploy for policy: defaultPolicy **
2023/09/28 05:39:41 ** Starting processing policy: defaultPolicy **
2023/09/28 05:39:41 Using global suricata source for Corelight
2023/09/28 05:39:56 Downloaded: /var/corelight-update/working/defaultPolicy/suricata-sources/emerging.rules.tar.gz
2023/09/28 05:39:56 Downloaded source: ET/Open
2023/09/28 05:39:57 Resp Code: 304 Not Modified; Using cached /var/corelight-update/working/defaultPolicy/suricata-sources/sslblacklist.rules
2023/09/28 05:39:57 Not processing CrowdStrikeIndicators based on an interval of 1 hours
2023/09/28 05:39:57 Not processing ICANNTLD based on an interval of 24 hours
2023/09/28 05:39:59 179 changed rules from /opt/corelight-update/corelight-recommended/disable.conf
2023/09/28 05:39:59 903 changed rules from /opt/corelight-update/corelight-recommended/enable.conf
2023/09/28 05:39:59 Extracted IP rules from the Suricata ruleset:
 disabled 211 Suricata rules
 created 8633 Intel rules
2023/09/28 05:39:59 Extracted JA3 rules from the Suricata ruleset:
 disabled 107 Suricata rules
 created 107 Intel rules
2023/09/28 05:39:59 53654 total rules
2023/09/28 05:39:59 40670 enabled rules
2023/09/28 05:39:59 12984 disabled rules
2023/09/28 05:40:00 Suricata Corelight RELEASE is installed
2023/09/28 05:40:00 Suricata is testing ruleset: /var/corelight-update/working/defaultPolicy/suricata-output/suricata.rules
2023/09/28 05:40:00 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/suricata.yaml
2023/09/28 05:40:00 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/classification.config
2023/09/28 05:40:00 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/reference.config
2023/09/28 05:40:00 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/threshold.config
28/9/2023 -- 05:40:00 - <Info> - Running suricata under test mode
28/9/2023 -- 05:40:00 - <Notice> - This is Suricata version 6.0.14-corelight RELEASE running in SYSTEM mode
28/9/2023 -- 05:40:00 - <Info> - CPUs/cores online: 4
28/9/2023 -- 05:40:00 - <Info> - Setting engine mode to IDS mode by default
28/9/2023 -- 05:40:00 - <Info> - HTTP memcap: 0
28/9/2023 -- 05:40:00 - <Info> - FTP memcap: 67108864
28/9/2023 -- 05:40:00 - <Info> - Preparing unexpected signal handling
28/9/2023 -- 05:40:00 - <Info> - Max dump is 0
28/9/2023 -- 05:40:00 - <Info> - Core dump setting attempted is 0
28/9/2023 -- 05:40:00 - <Info> - Core dump size set to 0
28/9/2023 -- 05:40:00 - <Warning> - [ERRCODE: SC_WARN_NO_STATS_LOGGERS(261)] - stats are enabled but no loggers are active
28/9/2023 -- 05:40:03 - <Info> - 1 rule files processed. 40670 rules successfully loaded, 0 rules failed
28/9/2023 -- 05:40:03 - <Info> - Threshold config parsed: 0 rule(s) found
28/9/2023 -- 05:40:05 - <Info> - 40673 signatures processed. 1035 are IP-only rules, 5361 are inspecting packet payload, 34260 inspect application layer, 0 are decoder event only
28/9/2023 -- 05:40:19 - <Notice> - Configuration provided was successfully loaded. Exiting.
28/9/2023 -- 05:40:20 - <Info> - cleaning up signature grouping structure... complete


2023/09/28 05:40:20 ** Start processing Intel files **
2023/09/28 05:40:20 no disable.intel file - skipping
2023/09/28 05:40:20 Added 8646 records to intel file
2023/09/28 05:40:20 Removed 0 records from intel file
2023/09/28 05:40:20 ** Finished processing Intel files **
2023/09/28 05:40:20 ** Finished processing policy: defaultPolicy **
2023/09/28 05:40:20 No Fleet details for policy: defaultPolicy
2023/09/28 05:40:20 ** Starting deploying to non-Fleet managed sensors for policy: defaultPolicy **
2023/09/28 05:40:20 ** Start pushing Intel for policy: defaultPolicy **
2023/09/28 05:40:20 Push Intel for sensor: docker
2023/09/28 05:40:20 Copying /var/corelight-update/files/defaultPolicy/intel-files/intel.dat to /etc/corelight/intel/intel.dat
2023/09/28 05:40:20 ** Finished pushing Intel for policy: defaultPolicy **
2023/09/28 05:40:20 ** Starting push Suricata files for policy: defaultPolicy **
2023/09/28 05:40:20 Push Suricata for sensor: docker
2023/09/28 05:40:20 Copying /var/corelight-update/files/defaultPolicy/suricata-rulesets/suricata.rules to /etc/corelight/rules/suricata.rules
2023/09/28 05:40:20 No new suricata.yaml to deploy for policy: defaultPolicy
2023/09/28 05:40:20 No new threshold.config to deploy for policy: defaultPolicy
2023/09/28 05:40:20 No new classification.config to deploy for policy: defaultPolicy
2023/09/28 05:40:20 No new reference.config to deploy for policy: defaultPolicy
2023/09/28 05:40:20 ** Finished push Suricata files to sensors for policy: defaultPolicy **
2023/09/28 05:40:20 No new Package bundle to deploy for policy: defaultPolicy
2023/09/28 05:40:20 No new Input Files to push for policy: defaultPolicy
2023/09/28 05:40:20 ** Finished deploying for policy: defaultPolicy **
2023/09/28 05:40:20 ** Finished Process and Deploy for policy: defaultPolicy **
root@corelight:/# 
```

Debugging example, add `-D` to get even more info, e.g. sqlite queries.

```
root@corelight:/opt/docker/compose/corelightathome-docker# docker exec -it 5be5ddd51ace /bin/bash
root@corelight:/# corelight-update -o -d
2023/09/28 05:34:30 Global Config:
{
  "verbose": false,
  "exp_features": false,
  "webserver": {
    "enable": false,
    "tls": true,
    "tls_cert": "/etc/corelight-update/global/cert.crt",
    "tls_key": "/etc/corelight-update/global/cert.key",
    "port": 8443
  },
  "process_feeds": true,
  "interval_minutes": 60,
  "geoip": {
    "enabled": false,
    "interval_hours": 0,
    "account_id": REMOVED,
    "license_key": "REMOVED",
    "database_directory": "/var/corelight-update/files/all/geoip"
  },
  "remote_global_conf_files": [],
  "parallel_push_limit": 10,
  "auto_update_policies": {
    "enable": true,
    "filename": "db-config.yaml"
  },
  "sensor_timeout_settings": {
    "transport_dialer_seconds": 0,
    "tls_handshake_seconds": 0,
    "idle_conn_seconds": 0,
    "expect_continue_seconds": 0,
    "http_seconds": 0,
    "upload_wait_seconds": 0
  }
}
2023/09/28 05:34:30 ** Starting Global Tasks **
2023/09/28 05:34:30 Checking for new suricata sources to cache
2023/09/28 05:34:30 suricata sources: [{1 0001-01-01 00:00:00 +0000 UTC 2023-09-28 05:32:38.69653612 +0000 UTC Corelight https://feed.corelight.com/corelight.rules suricata true   Authorization   false}]
2023/09/28 05:34:31.258355 DEBUG RESTY 
==============================================================================
~~~ REQUEST ~~~
GET  /corelight.rules  HTTP/1.1
HOST   : feed.corelight.com
HEADERS:
        Accept: */*
        Cache-Control: no-cache
        If-Modified-Since: Thu, 28 Sep 2023 04:03:33 GMT
        User-Agent: (Corelight Inc.; Corelight-update; Build/1.8.1)
BODY   :
***** NO CONTENT *****
------------------------------------------------------------------------------
~~~ RESPONSE ~~~
STATUS       : 304 Not Modified
PROTO        : HTTP/2.0
RECEIVED AT  : 2023-09-28T05:34:31.258197647Z
TIME DURATION: 409.945411ms
HEADERS      :
        Age: 113
        Date: Thu, 28 Sep 2023 05:34:31 GMT
        Etag: "4af19c3d40436b21aab3596fc0881cb5"
        Server: AmazonS3
        Vary: Accept-Encoding
        Via: 1.1 48d8e85703699c2da097b0f28aa75248.cloudfront.net (CloudFront)
        X-Amz-Cf-Id: adcFfykmeGv9bCyoQRCveXuRze6HC_sDrAJmCJW9CjYWgdCqpxy3wQ==
        X-Amz-Cf-Pop: BNE50-P1
        X-Amz-Server-Side-Encryption: AES256
        X-Cache: Hit from cloudfront
BODY         :

==============================================================================
2023/09/28 05:34:31 Resp Code: 304 Not Modified; Using cached /var/corelight-update/working/all/suricata-sources/corelight.rules
2023/09/28 05:34:31 Checking for new intel sources to cache
2023/09/28 05:34:31 No global intel sources configured
2023/09/28 05:34:31 ** Finished Global Tasks **
2023/09/28 05:34:31 Auto Policy Update enabled, auto-updating policies
2023/09/28 05:34:31 Successfully updated policy defaultPolicy
2023/09/28 05:34:31 ** Starting Process and Deploy for policy: defaultPolicy **
2023/09/28 05:34:31 ** Starting processing policy: defaultPolicy **
2023/09/28 05:34:31 Checking for new suricata sources to cache
2023/09/28 05:34:31 suricata sources: [{1 0001-01-01 00:00:00 +0000 UTC 2023-09-28 05:34:31.378716613 +0000 UTC Corelight https://feed.corelight.com/corelight.rules suricata true   Authorization   false} {2 0001-01-01 00:00:00 +0000 UTC 2023-09-28 05:34:31.385144047 +0000 UTC ET/Open https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz suricata false   Authorization   false} {3 0001-01-01 00:00:00 +0000 UTC 2023-09-28 05:34:31.395187155 +0000 UTC SSLBL https://sslbl.abuse.ch/blacklist/sslblacklist.rules suricata false   Authorization   false}]
2023/09/28 05:34:31 Using global suricata source for Corelight

%{BREVITY}%

alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"SSLBL: Malicious SSL certificate detected (AsyncRAT C&C)"; tls.fingerprint:"1c:1a:4f:a6:fe:bd:e8:2d:9b:63:91:e0:f5:4b:77:6d:ea:c7:b8:1c"; reference:url, sslbl.abuse.ch/ssl-certificates/sha1/1c1a4fa6febde82d9b6391e0f54b776deac7b81c/; sid:902205477; rev:1;)
# END (5478) entries
==============================================================================
2023/09/28 05:35:32 Downloaded: /var/corelight-update/working/defaultPolicy/suricata-sources/sslblacklist.rules
2023/09/28 05:35:32 Downloaded source: SSLBL
2023/09/28 05:35:32 Checking for new intel sources to cache
2023/09/28 05:35:32 No policy intel sources configured
2023/09/28 05:35:32 Checking for new input sources to cache
2023/09/28 05:35:32 No policy input sources configured
2023/09/28 05:35:32 Not processing CrowdStrikeIndicators based on an interval of 1 hours
2023/09/28 05:35:32 Not processing ICANNTLD based on an interval of 24 hours

2023/09/28 05:35:32 Old Input File State File: 
[{Filename:cert-hygiene-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:cert-hygiene-sni-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:datared-dns-domain-wl.txt SHA1hash:dec68bbd6cfe7a91c1e246475b3ffc5e722863f0} {Filename:datared-files-mime-wl.txt SHA1hash:9a10938f353e81166adbedc53805d4fd690d4351} {Filename:datared-http-hostname-wl.txt SHA1hash:b3b9de457c64ac435ef6479ae1f3cde453c8cb77} {Filename:datared-http-uri-wl.txt SHA1hash:fd0623bf72863a273ce104c2829f7ed557da4260} {Filename:datared-weird-name-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:encryption-detection-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:sni-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:ssh-inference-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:stepping-stone-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:trusted_domains.dat SHA1hash:94e47c0cb907e1d6322c93525596943ab0da35db}]

2023/09/28 05:35:32 D- New Input File State File: 
[{Filename:cert-hygiene-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:cert-hygiene-sni-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:datared-dns-domain-wl.txt SHA1hash:dec68bbd6cfe7a91c1e246475b3ffc5e722863f0} {Filename:datared-files-mime-wl.txt SHA1hash:9a10938f353e81166adbedc53805d4fd690d4351} {Filename:datared-http-hostname-wl.txt SHA1hash:b3b9de457c64ac435ef6479ae1f3cde453c8cb77} {Filename:datared-http-uri-wl.txt SHA1hash:fd0623bf72863a273ce104c2829f7ed557da4260} {Filename:datared-weird-name-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:encryption-detection-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:sni-wl.txt SHA1hash:95395af1de9916bb0a19032f8add6bc8434d8987} {Filename:ssh-inference-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:stepping-stone-server-wl.txt SHA1hash:a0b7c2ec50de838e7e22306934a9a72f0327c41e} {Filename:trusted_domains.dat SHA1hash:94e47c0cb907e1d6322c93525596943ab0da35db}]
2023/09/28 05:35:32 0 changed rules from /opt/corelight-update/corelight-recommended/disable.conf
2023/09/28 05:35:32 0 changed rules from /opt/corelight-update/corelight-recommended/enable.conf
2023/09/28 05:35:32 Extracted IP rules from the Suricata ruleset:
 disabled 0 Suricata rules
 created 0 Intel rules
2023/09/28 05:35:32 Extracted JA3 rules from the Suricata ruleset:
 disabled 0 Suricata rules
 created 0 Intel rules
2023/09/28 05:35:32 5601 total rules
2023/09/28 05:35:32 5598 enabled rules
2023/09/28 05:35:32 3 disabled rules
2023/09/28 05:35:32 Suricata Corelight RELEASE is installed
2023/09/28 05:35:32 Suricata is testing ruleset: /var/corelight-update/working/defaultPolicy/suricata-output/suricata.rules
2023/09/28 05:35:32 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/suricata.yaml
2023/09/28 05:35:32 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/classification.config
2023/09/28 05:35:32 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/reference.config
2023/09/28 05:35:32 Testing ruleset with /etc/corelight-update/configs/defaultPolicy/threshold.config
28/9/2023 -- 05:35:32 - <Info> - Running suricata under test mode
28/9/2023 -- 05:35:32 - <Notice> - This is Suricata version 6.0.14-corelight RELEASE running in SYSTEM mode
28/9/2023 -- 05:35:32 - <Info> - CPUs/cores online: 4
28/9/2023 -- 05:35:32 - <Info> - Setting engine mode to IDS mode by default
28/9/2023 -- 05:35:32 - <Info> - HTTP memcap: 0
28/9/2023 -- 05:35:32 - <Info> - FTP memcap: 67108864
28/9/2023 -- 05:35:32 - <Info> - Preparing unexpected signal handling
28/9/2023 -- 05:35:32 - <Info> - Max dump is 0
28/9/2023 -- 05:35:32 - <Info> - Core dump setting attempted is 0
28/9/2023 -- 05:35:32 - <Info> - Core dump size set to 0
28/9/2023 -- 05:35:32 - <Warning> - [ERRCODE: SC_WARN_NO_STATS_LOGGERS(261)] - stats are enabled but no loggers are active
28/9/2023 -- 05:35:33 - <Info> - 1 rule files processed. 5598 rules successfully loaded, 0 rules failed
28/9/2023 -- 05:35:33 - <Info> - Threshold config parsed: 0 rule(s) found
28/9/2023 -- 05:35:33 - <Info> - 5598 signatures processed. 0 are IP-only rules, 93 are inspecting packet payload, 5502 inspect application layer, 0 are decoder event only
28/9/2023 -- 05:35:40 - <Notice> - Configuration provided was successfully loaded. Exiting.
28/9/2023 -- 05:35:40 - <Info> - cleaning up signature grouping structure... complete


2023/09/28 05:35:40 ** Start processing Intel files **
2023/09/28 05:35:40 no disable.intel file - skipping
2023/09/28 05:35:40 ----------WARNING: SKIPPING INTEL FILE---------
2023/09/28 05:35:40 Skipping /var/corelight-update/working/defaultPolicy/intel/suricata-ip.dat: too few records
2023/09/28 05:35:40 ----------WARNING: SKIPPING INTEL FILE---------
2023/09/28 05:35:40 Skipping /var/corelight-update/working/defaultPolicy/intel/suricata-ja3.dat: too few records
2023/09/28 05:35:40 Added 0 records to intel file
2023/09/28 05:35:40 Removed 0 records from intel file
2023/09/28 05:35:40 ** Finished processing Intel files **
2023/09/28 05:35:40 ** Finished processing policy: defaultPolicy **
2023/09/28 05:35:40 No Fleet details for policy: defaultPolicy
2023/09/28 05:35:40 ** Starting deploying to non-Fleet managed sensors for policy: defaultPolicy **
2023/09/28 05:35:40 ** Start pushing Intel for policy: defaultPolicy **
2023/09/28 05:35:40 Push Intel for sensor: docker
2023/09/28 05:35:40 Copying /var/corelight-update/files/defaultPolicy/intel-files/intel.dat to /etc/corelight/intel/intel.dat
2023/09/28 05:35:40 ** Finished pushing Intel for policy: defaultPolicy **
2023/09/28 05:35:40 ** Starting push Suricata files for policy: defaultPolicy **
2023/09/28 05:35:40 Push Suricata for sensor: docker
2023/09/28 05:35:40 Copying /var/corelight-update/files/defaultPolicy/suricata-rulesets/suricata.rules to /etc/corelight/rules/suricata.rules
2023/09/28 05:35:40 Copying /etc/corelight-update/configs/defaultPolicy/suricata.yaml to /var/corelight/suricata/suricata.yaml
2023/09/28 05:35:40 Copying /etc/corelight-update/configs/defaultPolicy/threshold.config to /var/corelight/suricata/threshold.config
2023/09/28 05:35:40 Copying /etc/corelight-update/configs/defaultPolicy/classification.config to /var/corelight/suricata/classification.config
2023/09/28 05:35:40 Copying /etc/corelight-update/configs/defaultPolicy/reference.config to /var/corelight/suricata/reference.config
2023/09/28 05:35:40 ** Finished push Suricata files to sensors for policy: defaultPolicy **
2023/09/28 05:35:40 No new Package bundle to deploy for policy: defaultPolicy
2023/09/28 05:35:40 No new Input Files to push for policy: defaultPolicy
2023/09/28 05:35:40 ** Finished deploying for policy: defaultPolicy **
2023/09/28 05:35:40 ** Finished Process and Deploy for policy: defaultPolicy **
root@corelight:/#
```
