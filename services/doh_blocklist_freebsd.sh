#!/bin/sh
#
# PROVIDE: doh_blocklists_server
# REQUIRE: DAEMON
# KEYWORD: shutdown

. /etc/rc.subr

name="doh_blocklists_server"
rcvar=doh_blocklists_server_enable
pidfile="/var/run/${name}.pid"

command="/usr/sbin/daemon"

command_args="-r -t ${name} \
    -u doh_blocklist_server \
    -P ${pidfile} -- \
    /usr/bin/nice -n 19 -- \
    /usr/local/bin/doh_blocklists_server \
        -d \
        -c ./.src/_mini.yml \
        -chdir /opt/DoH-Blocklists-filtered \
        -chdir_cache /var/cache/doh_blocklist \
        -u https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/refs/heads/master/doh-domains_overall.txt \
        -u https://raw.githubusercontent.com/BPplays/DoH-Blocklists-filtered/refs/heads/main/.src/doh-domains_full.txt \
        -curl_loc ./.src/doh-domains_full.txt"

# Load configuration from /etc/rc.conf
load_rc_config $name
: ${doh_blocklists_server_enable:="NO"}

run_rc_command "$1"

