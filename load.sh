# This script is for building and installing xt_OBSF and setting iptables rules
# Please check README if any doubt about requirements and/or crucial things.
# Only modify this script for enabling/disabling encryption, padding and/or ptime modification,
# changing parameters, etc.

# Cleaning up prviously set iptables rules
#iptables -t mangle --flush

# Building the module
make
make all
make modules
make modules_install

# Building the userspace plug-in
make libxt_OBSF.so
cp libxt_OBSF.so /lib/xtables/

# Inserting module
modprobe x_tables
insmod xt_OBSF.ko

# Please insert the Source IPs and Ports of the TDM Gateways as -j ACCEPT for these rules to be executed first
# These rules must be set for both PREROUTING and OUTPUT
# These rules must be stated before loading OBSF via iptables rules

# SET RULES HERE FOR CONVENIENCE

# For the PREROUTING hook
iptables -t mangle -p udp -A PREROUTING -s 203.208.198.32 -j ACCEPT
iptables -t mangle -p udp -A PREROUTING -s 103.12.215.162 -j ACCEPT
# For the OUTPUT hook
iptables -t mangle -p udp -A OUTPUT -d 203.208.198.32 -j ACCEPT
iptables -t mangle -p udp -A OUTPUT -d 103.12.215.162 -j ACCEPT

# The module is to be loaded for RTP and SIP separately.
# For SIP, the module is to be loaded two times for SIP, once for PREROUTING, and also for OUTPUT
# For RTP, the above info is valid as well.

# Adjust source/destination IP/PORT appropriately before these commands
# In the following commands, if any function is disabled, then its related other things will be ignored
# Options:
	# pkt --> sip/rtp

# SIP packet:
	# pkt --> sip
	# encryption --> yes/no
	# sip_key --> The rc4 encryption key for SIP/Signal
	# sip_key_len --> Exact numeric value of the length of the encryption key
	# enc_path --> encrypt/decrypt (encrypt will only work on OUTPUT, decrypt will only work in PREROUTING)

# Rules for loading iptables for SIP packets

iptables -t mangle -A PREROUTING -p udp --dport 7070 -j OBSF --pkt sip --encryption yes --sip_key Zfk0g3zoeid2DIo --sip_key_len 15 --enc_path decrypt

iptables -t mangle -A OUTPUT -p udp --sport 7070 -j OBSF --pkt sip --encryption yes --sip_key Zfk0g3zoeid2DIo --sip_key_len 15 --enc_path encrypt

# RTP packet:
	# pkt --> rtp
	# encryption --> yes/no
	# rtp_key --> The rc4 encryption key for RTP
	# rtp_key_len --> Exact numeric value of the length of the encryption key
	# enc_path --> encrypt/decrypt (encrypt will only work on OUTPUT, decrypt will only work in PREROUTING)
	# pad --> enable/disable
	# pad_path --> apad/rpad (apad is for apply padding, will work only in OUTPUT
	#			  rpad is for remove padding, will work only in PREROUTING)
	# ptime --> enable/disable
	# sptime --> Numeric value of the splitting ptime (Convention is 20, large packets will be splitted to sptime)
	# lptime --> Numeric value of the network ptime (Set ptime value multiples of 10)

# Rules for loading iptables for RTP packetsy

iptables -t mangle -A PREROUTING -p udp --dport 10000:20000 -j OBSF --pkt rtp --encryption yes --rtp_key T5rWzRGD25pbeErt --rtp_key_len 16 --enc_path decrypt --pad enable --pad_path rpad --ptime enable --sptime 20 --lptime 100

iptables -t mangle -A OUTPUT -p udp --sport 10000:20000 -j OBSF --pkt rtp --encryption yes --rtp_key T5rWzRGD25pbeErt --rtp_key_len 16 --enc_path encrypt --pad enable --pad_path apad --ptime enable --sptime 20 --lptime 160

# Showing iptables rules
echo "Showing iptables rules after inserting module"
iptables -t mangle --list

echo "Showing log message after inserting module"
#dmesg
