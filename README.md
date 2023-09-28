# corelightathome-docker

Corelight@Home (Raspberry Pi) in a docker container

Refer to: https://corelight.com/blog/corelight-at-home

Running Corelight@Home this way basically makes https://github.com/corelight/raspi-corelight unnecessary, though the script in that repo is what the container build process has been based on.

WARNING: Still has bugs/issues, results may vary, please provide feedback and create an issue if you find anything. If you fix it please fork repo and issue a pull request.

# NOTE

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

# Get repo & Build

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

root@corelight:/opt/docker/compose/corelightathome-docker# sh build.sh
No stopped containers
[+] Building 166.4s (9/9) FINISHED
 => [internal] load build definition from Dockerfile                                                                                                                                                                                               0.0s
 => => transferring dockerfile: 2.56kB                                                                                                                                                                                                             0.0s
 => [internal] load .dockerignore                                                                                                                                                                                                                  0.0s
 => => transferring context: 2B                                                                                                                                                                                                                    0.0s
 => [internal] load metadata for docker.io/library/debian:bullseye                                                                                                                                                                                 1.9s
 => [1/4] FROM docker.io/library/debian:bullseye@sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55                                                                                                                          10.8s
 => => resolve docker.io/library/debian:bullseye@sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55                                                                                                                           0.0s
 => => sha256:82bab30ed448b8e2509aabe21f40f0607d905b7fd0dec72802627a20274eba55 1.85kB / 1.85kB                                                                                                                                                     0.0s
 => => sha256:ede74d90543e4dedd6662653de639d72e82640717f99041591dc9f34c186f0f9 529B / 529B                                                                                                                                                         0.0s
 => => sha256:585393df054ae3733a18ba06108b2cee169be81198dde54e073526e856ff9a01 1.48kB / 1.48kB                                                                                                                                                     0.0s
 => => sha256:114ba63dd73a866ac1bb59fe594dfd218f44ac9b4fa4b2c68499da5584fcfa9d 53.68MB / 53.68MB                                                                                                                                                   4.7s
 => => extracting sha256:114ba63dd73a866ac1bb59fe594dfd218f44ac9b4fa4b2c68499da5584fcfa9d                                                                                                                                                          5.7s
 => [internal] load build context                                                                                                                                                                                                                  0.0s
 => => transferring context: 2.23kB                                                                                                                                                                                                                0.0s
 => [2/4] COPY geoipupdate.sh /usr/bin/geoipupdate                                                                                                                                                                                                 0.8s
 => [3/4] COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint                                                                                                                                                                               0.1s
 => [4/4] RUN echo "### Update GeoIP databases" &&   apt update && apt -y install wget &&   chmod 0755 /usr/bin/geoipupdate &&   /usr/bin/geoipupdate &&   apt -y install git gnupg2 lsb-rele  131.8s
 => exporting to image                                                                                                                                                                                                                            20.8s
 => => exporting layers                                                                                                                                                                                                                           20.8s
 => => writing image sha256:403963509724f81efcd071e3cc4ebdc4d42d1fd05f788da4818c771a6a799ae9                                                                                                                                                       0.0s
 => => naming to docker.io/colin-stubbs/corelight:latest                                                                                                                                                                                           0.0s
root@corelight:/opt/docker/compose/corelightathome-docker#
```

# Configure

You should be able to do everything you need simply by using docker environment variables.

Copy the .env example file and edit, e.g.

```
root@corelight:/opt/docker/compose/corelightathome-docker# cp dot-env-example .env
root@corelight:/opt/docker/compose/corelightathome-docker# vim .env
root@corelight:/opt/docker/compose/corelightathome-docker# cat .env
CORELIGHT_LICENSE="CHANGE_ME"
IDAPTIVE_USERNAME="CHANGE_ME"
IDAPTIVE_PASSWORD="CHANGE_ME"
MAXMIND_LICENSE_KEY="CHANGE_ME"
root@corelight:/opt/docker/compose/corelightathome-docker#
```

# Run

```
root@corelight:/opt/docker/compose/corelightathome-docker# sh up.sh --detach
[+] Running 1/1
 ⠿ Container corelight-corelight-1  Started                                                                                                                                                                                                        0.2s
root@corelight:/opt/docker/compose/corelightathome-docker# docker ps
CONTAINER ID   IMAGE                           COMMAND                  CREATED         STATUS         PORTS     NAMES
58977f243939   colin-stubbs/corelight:latest   "/bin/sh -c /usr/loc…"   3 minutes ago   Up 4 seconds             corelight-corelight-1
root@corelight:/opt/docker/compose/corelightathome-docker# docker logs -t 58977f243939
2022-08-09T22:33:56.739582622Z supervisor: Licensed to corelighthome until 2023-06-13 00:00:00 UTC
2022-08-09T22:33:56.759544810Z Starting Corelight Software Sensor...
2022-08-09T22:33:56.856090495Z     Failed to disable offloading
2022-08-09T22:33:56.856453564Z     Failed to bring up interface
2022-08-09T22:33:56.856597211Z supervisor: Disabling hardware features on eth0 and bringing up the interface...done
2022-08-09T22:33:58.672213586Z suricata: This is Suricata version 6.0.5-corelight RELEASE running in SYSTEM mode
2022-08-09T22:33:58.674408445Z suricata: Preparing unexpected signal handling
2022-08-09T22:33:59.671984077Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3 support is not enabled
2022-08-09T22:33:59.755840419Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET JA3 Hash - Suspected Cobalt Strike Malleable C2 M1 (set)"; flow:established,to_server; ja3.hash; content:"eb88d0b3e1961a0562f006e5ce2a0b87"; ja3.string; content:"771,49192-49191-49172-49171"; flowbits:set,ET.cobaltstrike.ja3; flowbits:noalert; classtype:command-and-control; sid:2028831; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_10_15, deployment Perimeter, former_category JA3, malware_family Cobalt_Strike, signature_severity Major, updated_at 2019_10_15, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1001, mitre_technique_name Data_Obfuscation;)" from file /etc/corelight/rules/suricata.rules at line 8602
2022-08-09T22:33:59.757097587Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3(s) support is not enabled
2022-08-09T22:33:59.806356721Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET JA3 HASH - Possible RustyBuer Server Response"; flowbits:isset,ET.rustybuer; ja3s.hash; content:"f6dfdd25d1522e4e1c7cd09bd37ce619"; reference:md5,ea98a9d6ca6f5b2a0820303a1d327593; classtype:bad-unknown; sid:2032960; rev:1; metadata:attack_target Client_Endpoint, created_at 2021_05_13, deployment Perimeter, former_category JA3, malware_family RustyBuer, performance_impact Low, signature_severity Major, updated_at 2021_05_13;)" from file /etc/corelight/rules/suricata.rules at line 8727
2022-08-09T22:33:59.809236089Z supervisor: Running 4 Zeek workers.
2022-08-09T22:34:05.676002116Z suricata: 1 rule files processed. 27271 rules successfully loaded, 131 rules failed
2022-08-09T22:34:05.677005843Z suricata: Threshold config parsed: 0 rule(s) found
2022-08-09T22:34:07.677907627Z suricata: 27274 signatures processed. 1236 are IP-only rules, 5126 are inspecting packet payload, 20885 inspect application layer, 0 are decoder event only
2022-08-09T22:34:11.681345347Z manager: Loading license from environment variable
2022-08-09T22:34:11.685967617Z manager: rdp-inference-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/rdp-inference-server-wl.txt; first line could not be read
2022-08-09T22:34:11.689231183Z manager: ssh-inference-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/ssh-inference-server-wl.txt; first line could not be read
2022-08-09T22:34:11.690187133Z manager: stepping-stone-server-wl.txt/Input::READER_ASCII: Could not read input data file /etc/corelight/input_files/stepping-stone-server-wl.txt; first line could not be read
2022-08-09T22:34:11.692765023Z manager: error in /builtin/base/frameworks/broker/log.zeek, line 83: Broker error (Broker::PEER_UNAVAILABLE): (invalid-node, *127.0.0.1:27762, "unable to connect to remote peer")
2022-08-09T22:34:11.694448277Z manager: /etc/corelight/intel/zeek.intel/Input::READER_ASCII: Did not find requested field indicator in input data file /etc/corelight/intel/zeek.intel.
2022-08-09T22:34:13.702431676Z logger: Rotated/postprocessed leftover log 'broker.log' -> 'broker-22-08-09_00.30.23.log'
2022-08-09T22:34:13.711892101Z logger: Rotated/postprocessed leftover log 'cluster.log' -> 'cluster-22-08-09_00.30.23.log'
2022-08-09T22:34:13.712739015Z logger: Rotated/postprocessed leftover log 'reporter.log' -> 'reporter-22-08-09_00.30.23.log'
2022-08-09T22:34:13.714042238Z logger: Rotated/postprocessed leftover log 'corelight_license_capacity.log' -> 'corelight_license_capacity-22-08-09_00.30.43.log'
2022-08-09T22:34:13.714752043Z logger: Rotated/postprocessed leftover log 'suricata_zeek_stats.log' -> 'suricata_zeek_stats-22-08-09_00.31.23.log'
2022-08-09T22:34:13.715850824Z logger: Rotated/postprocessed leftover log 'conn.log' -> 'conn-22-08-09_00.31.24.log'
2022-08-09T22:34:13.715938063Z logger: Rotated/postprocessed leftover log 'weird.log' -> 'weird-22-08-09_00.31.26.log'
2022-08-09T22:34:13.716463408Z logger: Rotated/postprocessed leftover log 'ssl.log' -> 'ssl-22-08-09_00.31.28.log'
2022-08-09T22:34:13.722959707Z logger: Rotated/postprocessed leftover log 'software.log' -> 'software-22-08-09_00.31.29.log'
2022-08-09T22:34:13.724527871Z logger: Rotated/postprocessed leftover log 'unknown_mime_type_discovery.log' -> 'unknown_mime_type_discovery-22-08-09_00.31.29.log'
2022-08-09T22:34:13.726637897Z logger: Rotated/postprocessed leftover log 'files.log' -> 'files-22-08-09_00.31.29.log'
2022-08-09T22:34:13.727559625Z logger: Rotated/postprocessed leftover log 'dns.log' -> 'dns-22-08-09_00.31.30.log'
2022-08-09T22:34:13.729698484Z logger: Rotated/postprocessed leftover log 'http.log' -> 'http-22-08-09_00.31.34.log'
2022-08-09T22:34:55.727933263Z suricata: [ERRCODE: SC_ERR_SYSCALL(50)] - Failure when trying to set feature via ioctl for 'eth0': Operation not permitted (1)
2022-08-09T22:34:55.730720058Z suricata: all 4 packet processing threads, 5 management threads initialized, engine started.
2022-08-09T22:34:55.732815140Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#01-eth0: Operation not permitted
2022-08-09T22:34:55.734807742Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#02-eth0: Operation not permitted
2022-08-09T22:34:55.736346258Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#03-eth0: Operation not permitted
2022-08-09T22:34:55.737959920Z suricata: [ERRCODE: SC_ERR_THREAD_NICE_PRIO(47)] - Error setting nice value -2 for thread W#04-eth0: Operation not permitted
2022-08-09T22:37:35.848523307Z supervisor: Licensed to corelighthome until 2023-06-13 00:00:00 UTC
2022-08-09T22:37:35.868384548Z Starting Corelight Software Sensor...
2022-08-09T22:37:35.957275160Z     Failed to disable offloading
2022-08-09T22:37:35.957422861Z     Failed to bring up interface
2022-08-09T22:37:35.957435639Z supervisor: Disabling hardware features on eth0 and bringing up the interface...done
2022-08-09T22:37:37.786019101Z suricata: This is Suricata version 6.0.5-corelight RELEASE running in SYSTEM mode
2022-08-09T22:37:37.788324957Z suricata: Preparing unexpected signal handling
2022-08-09T22:37:37.792595639Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3 support is not enabled
2022-08-09T22:37:37.863385114Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET JA3 Hash - Suspected Cobalt Strike Malleable C2 M1 (set)"; flow:established,to_server; ja3.hash; content:"eb88d0b3e1961a0562f006e5ce2a0b87"; ja3.string; content:"771,49192-49191-49172-49171"; flowbits:set,ET.cobaltstrike.ja3; flowbits:noalert; classtype:command-and-control; sid:2028831; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2019_10_15, deployment Perimeter, former_category JA3, malware_family Cobalt_Strike, signature_severity Major, updated_at 2019_10_15, mitre_tactic_id TA0011, mitre_tactic_name Command_And_Control, mitre_technique_id T1001, mitre_technique_name Data_Obfuscation;)" from file /etc/corelight/rules/suricata.rules at line 8602
2022-08-09T22:37:37.864424710Z suricata: [ERRCODE: SC_WARN_JA3_DISABLED(309)] - ja3(s) support is not enabled
2022-08-09T22:37:37.891999492Z suricata: [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET JA3 HASH - Possible RustyBuer Server Response"; flowbits:isset,ET.rustybuer; ja3s.hash; content:"f6dfdd25d1522e4e1c7cd09bd37ce619"; reference:md5,ea98a9d6ca6f5b2a0820303a1d327593; classtype:bad-unknown; sid:2032960; rev:1; metadata:attack_target Client_Endpoint, created_at 2021_05_13, deployment Perimeter, former_category JA3, malware_family RustyBuer, performance_impact Low, signature_severity Major, updated_at 2021_05_13;)" from file /etc/corelight/rules/suricata.rules at line 8727
2022-08-09T22:37:38.892663952Z supervisor: Running 4 Zeek workers.
2022-08-09T22:37:42.786317901Z suricata: 1 rule files processed. 27271 rules successfully loaded, 131 rules failed
2022-08-09T22:37:44.405313689Z suricata: Threshold config parsed: 0 rule(s) found
root@corelight:/opt/docker/compose/corelightathome-docker#
root@corelight:/opt/docker/compose/corelightathome-docker# cat data/logs/2022-08-09/capture_loss_20220809_22\:35\:12-22\:35\:14+0000.log
{"_path":"capture_loss","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.634291Z","_node":"worker-03","ts":"2022-08-09T22:35:12.634291Z","ts_delta":60.00007891654968,"peer":"worker-03","gaps":0,"acks":0,"percent_lost":0.0}
{"_path":"capture_loss","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:13.562008Z","_node":"worker-02","ts":"2022-08-09T22:35:13.562008Z","ts_delta":60.00023794174194,"peer":"worker-02","gaps":0,"acks":0,"percent_lost":0.0}
{"_path":"capture_loss","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:13.578905Z","_node":"worker-04","ts":"2022-08-09T22:35:13.578905Z","ts_delta":60.00014519691467,"peer":"worker-04","gaps":0,"acks":0,"percent_lost":0.0}
{"_path":"capture_loss","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:13.799100Z","_node":"worker-01","ts":"2022-08-09T22:35:13.799100Z","ts_delta":60.000165939331058,"peer":"worker-01","gaps":0,"acks":0,"percent_lost":0.0}
root@corelight:/opt/docker/compose/corelightathome-docker#
root@corelight:/opt/docker/compose/corelightathome-docker# cat data/logs/2022-08-09/cluster_20220809_22\:35\:11-22\:35\:13+0000.log
{"_path":"cluster","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:11.141325Z","_node":"manager","ts":"2022-08-09T22:35:11.141325Z","node":"manager","message":"got hello from logger (2D28DB73859BF318F64B5CA57D4C1F591DE35AF6#37)"}
{"_path":"cluster","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.637562Z","_node":"logger","ts":"2022-08-09T22:35:12.637562Z","node":"logger","message":"got hello from worker-03 (B7F80D04559960FC83ADB8D73DBC11FC7EF509AA#60)"}
{"_path":"cluster","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.631029Z","_node":"worker-03","ts":"2022-08-09T22:35:12.631029Z","node":"worker-03","message":"got hello from logger (2D28DB73859BF318F64B5CA57D4C1F591DE35AF6#37)"}
{"_path":"cluster","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.086711Z","_node":"proxy-1","ts":"2022-08-09T22:35:12.086711Z","node":"proxy-1","message":"got hello from logger (2D28DB73859BF318F64B5CA57D4C1F591DE35AF6#37)"}
root@corelight:/opt/docker/compose/corelightathome-docker#
root@corelight:/opt/docker/compose/corelightathome-docker# cat data/logs/2022-08-09/broker_20220809_22\:34\:14-22\:35\:13+0000.log
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:34:14.715893Z","_node":"worker-02","ts":"2022-08-09T22:34:14.715893Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":30000,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:34:14.709537Z","_node":"worker-04","ts":"2022-08-09T22:34:14.709537Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":30000,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:34:14.891797Z","_node":"worker-01","ts":"2022-08-09T22:34:14.891797Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":30000,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:11.139773Z","_node":"manager","ts":"2022-08-09T22:35:11.139773Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":27762,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.628538Z","_node":"logger","ts":"2022-08-09T22:35:12.628538Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"::ffff:127.0.0.1","peer.bound_port":32920,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.628589Z","_node":"worker-03","ts":"2022-08-09T22:35:12.628589Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":27762,"message":"handshake successful"}
{"_path":"broker","_system_name":"corelight.localdomain","_write_ts":"2022-08-09T22:35:12.084606Z","_node":"proxy-1","ts":"2022-08-09T22:35:12.084606Z","ty":"Broker::STATUS","ev":"peer-added","peer.address":"127.0.0.1","peer.bound_port":27762,"message":"handshake successful"}
root@corelight:/opt/docker/compose/corelightathome-docker#
```

# Optional

## Zeek Intelligence

https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds

