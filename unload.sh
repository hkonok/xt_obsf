# This script is for unloading xt_OBSF

# Stopping Asterisk
/etc/init.d/asterisk stop

# Flushing out iptables rules, otherwise OBSF cannot be removed
iptables -t mangle --flush

# Removing module xt_OBSF
rmmod xt_OBSF.ko

# Cleaning up directory
make clean
rm libxt_OBSF.so
