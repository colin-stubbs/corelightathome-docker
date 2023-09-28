## If there are additional scripts you would like to load, they can be defined in
## this script.

##! Load Intel Framework
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += {
        "/etc/corelight/intel/intel.dat",
# This assumes you've cloned https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds to be available via /etc/corelight/intel/Zeek-Intelligence-Feeds/
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/Amnesty_NSO_Domains.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/Cyber_Threat_Coalition_Domain_Blacklist.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-ipblocklist.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-malware.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-threatfox-ip.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ch-urlhaus.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/abuse-ja3-fingerprints.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/alienvault.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/atomspam.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/binarydefense.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/censys.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cloudzy.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cobaltstrike_ips.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/compromised-ips.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/cps-collected-iocs.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_domain.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_ip.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/drb_ra_ip_unverified.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/ellio.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/fangxiao.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/filetransferportals.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/illuminate.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/illuminate_ja3.intel",
# This one's huge and appears to likely be noise.
##       "/etc/corelight/intel/Zeek-Intelligence-Feeds/inversion.intel",       
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/james-inthe-box.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/lockbit_ip.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/log4j_ip.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/mirai.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/openphish.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/predict_intel.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/ragnar.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/rutgers.intel",
# Some JA3 fingerprints in here are common and useless to perform detection based on
##        "/etc/corelight/intel/Zeek-Intelligence-Feeds/salesforce-ja3-fingerprints.intel",
# This one's huge and appears to likely be noise.
##        "/etc/corelight/intel/Zeek-Intelligence-Feeds/sans.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/scumbots.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/shadowwhisperer-malware.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/sip.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/stalkerware.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/talos.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/tor-exit.intel",
#        "/etc/corelight/intel/Zeek-Intelligence-Feeds/tweetfeed.intel",
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