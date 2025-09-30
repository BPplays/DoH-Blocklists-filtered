#!/bin/sh
# doh-lookup - retrieve IPv4/IPv6 addresses via dig from a given domain list
# and write the adjusted output to separate lists (IPv4/IPv6 addresses plus domains)
# Copyright (c) 2019-2025 Dirk Brenken (dev@brenken.org)
#
# This is free software, licensed under the GNU General Public License v3.

# disable (s)hellcheck in release
# shellcheck disable=all

# prepare environment
#
export LC_ALL=C
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
input="$1"
output_prefix="$2"

cdncheck="./cdncheck/cdncheck"

check_domains="google.com heise.de openwrt.org"
cache_domains="doh.dns.apple.com doh.dns.apple.com.v.aaplimg.com mask-api.icloud.com mask-h2.icloud.com mask.icloud.com dns.nextdns.io"
dig_tool="$(command -v dig)"
awk_tool="$(command -v awk)"
: >"./${output_prefix}ipv4.tmp"
: >"./${output_prefix}ipv6.tmp"
: >"./${output_prefix}ipv4_cache.tmp"
: >"./${output_prefix}ipv6_cache.tmp"
: >"./${output_prefix}domains.tmp"
: >"./${output_prefix}domains_abandoned.tmp"

# sanity pre-checks
#
if [ ! -x "${dig_tool}" ] || [ ! -x "${awk_tool}" ] || [ ! -x "${awk_tool}" ] || [ ! -s "${input}" ]; then
	printf "%s\n" "ERR: base pre-processing check failed"
	exit 1
fi

for domain in ${check_domains}; do
	out="$("${dig_tool}" +noall +answer +time=5 +tries=5 "${domain}" A "${domain}" AAAA 2>/dev/null)"
	if [ -z "${out}" ]; then
		printf "%s\n" "ERR: domain pre-processing check failed"
		exit 1
	else
		ips="$(printf "%s" "${out}" | "${awk_tool}" '/^.*[[:space:]]+IN[[:space:]]+A{1,4}[[:space:]]+/{printf "%s ",$NF}')"
		if [ -z "${ips}" ]; then
			printf "%s\n" "ERR: ip pre-processing check failed"
			exit 1
		fi
	fi
done

# pre-fill cache domains
#
for domain in ${cache_domains}; do
	"${awk_tool}" -v d="${domain}" '$0~d{print $0}' "./${output_prefix}-doh-ipv4.txt" >>"./${output_prefix}ipv4_cache.tmp"
	"${awk_tool}" -v d="${domain}" '$0~d{print $0}' "./${output_prefix}-doh-ipv6.txt" >>"./${output_prefix}ipv6_cache.tmp"
done

# domain processing
#
cnt="0"
doh_start="$(date "+%s")"
doh_cnt="$("${awk_tool}" 'END{printf "%d",NR}' "./${input}" 2>/dev/null)"
printf "%s\n" "::: Start DOH-processing, overall domains: ${doh_cnt}"
while IFS= read -r domain; do
	(
		domain_ok="false"
		out="$("${dig_tool}" +noall +answer +time=5 +tries=5 "${domain}" A "${domain}" AAAA 2>/dev/null)"
		if [ -n "${out}" ]; then
			ips="$(printf "%s" "${out}" | "${awk_tool}" '/^.*[[:space:]]+IN[[:space:]]+A{1,4}[[:space:]]+/{printf "%s ",$NF}')"
			if [ -n "${ips}" ]; then
				for ip in ${ips}; do
					if [ "${ip%%.*}" = "127" ] || [ "${ip%%.*}" = "0" ] || [ -z "${ip%%::*}" ]; then
						continue
					else
						check="$(ipcalc-ng -s --addrspace "${ip}" | "${awk_tool}" '!/Private/{print $0}')"
						rc="${?}"
						if [ -n "${check}" ] && [ "${rc}" = "0" ]; then

							check="$($cdncheck -silent -i "${ip}")"
							rc="${?}"
							if [ -z "${check}" ] && [ "${rc}" = "0" ]; then
								domain_ok="true"
								if [ "${ip##*:}" = "${ip}" ]; then
									printf "%-20s%s\n" "${ip}" "# ${domain}" >>"./${output_prefix}ipv4.tmp"
								else
									printf "%-40s%s\n" "${ip}" "# ${domain}" >>"./${output_prefix}ipv6.tmp"
								fi
							fi
						fi
					fi
				done
			fi
		fi
		if [ "${domain_ok}" = "true" ]; then
			printf "%s\n" "${domain}" >>./${output_prefix}domains.tmp
		else
			printf "%s\n" "${domain}" >>./${output_prefix}domains_abandoned.tmp
		fi
	) &
	hold1="$((cnt % 512))"
	hold2="$((cnt % 2048))"
	[ "${hold1}" = "0" ] && sleep 3
	[ "${hold2}" = "0" ] && wait
	cnt="$((cnt + 1))"
done <"${input}"
wait

# post-processing check
#
if [ ! -s "./${output_prefix}ipv4.tmp" ] || [ ! -s "./${output_prefix}ipv6.tmp" ] || [ ! -s "./${output_prefix}domains.tmp" ] || [ ! -f "./${output_prefix}domains_abandoned.tmp" ]; then
	printf "%s\n" "ERR: post-processing check failed"
	exit 1
fi

# final sort/merge step
#
sort -b -u -n -t. -k1,1 -k2,2 -k3,3 -k4,4 "./${output_prefix}ipv4_cache.tmp" "./${output_prefix}ipv4.tmp" >"./${output_prefix}-doh-ipv4.txt"
sort -b -u -k1,1 "./${output_prefix}ipv6_cache.tmp" "./${output_prefix}ipv6.tmp" >"./${output_prefix}-doh-ipv6.txt"
sort -b -u "./${output_prefix}domains.tmp" >"./${output_prefix}-doh-domains.txt"
# sort -b -u "./${output_prefix}domains_abandoned.tmp" >"./${output_prefix}-doh-domains_abandoned.txt"
cnt_cache_tmpv4="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}ipv4_cache.tmp" 2>/dev/null)"
cnt_cache_tmpv6="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}ipv6_cache.tmp" 2>/dev/null)"
cnt_tmpv4="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}ipv4.tmp" 2>/dev/null)"
cnt_tmpv6="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}ipv6.tmp" 2>/dev/null)"
cnt_ipv4="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}-doh-ipv4.txt" 2>/dev/null)"
cnt_ipv6="$("${awk_tool}" 'END{printf "%d",NR}' "./${output_prefix}-doh-ipv6.txt" 2>/dev/null)"
doh_end="$(date "+%s")"
doh_duration="$(((doh_end - doh_start) / 60))m $(((doh_end - doh_start) % 60))s"
printf "%s\n" "::: Finished DOH-processing, duration: ${doh_duration}, cachev4/cachev6: ${cnt_cache_tmpv4}/${cnt_cache_tmpv6}, all/unique IPv4: ${cnt_tmpv4}/${cnt_ipv4}, all/unique IPv6: ${cnt_tmpv6}/${cnt_ipv6}"
