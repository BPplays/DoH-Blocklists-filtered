# DoH-IP-blocklists

This repo contains the filtered domain names and the IP addresses of public DoH server.  
It's forked from [dibdot DoH-IP-blocklists](https://github.com/dibdot/DoH-IP-blocklists) and pulls from that for `full` every day so it should stay up to date  
the folders used:  
  * `./full`: (updated every day) list of domains from the full dibdot list and the known good part of the mini list  
  * `./mini`: (updated every hour) list main by me, from some common ones and all DoH servers chromium will use  

it uses [cdncheck](https://github.com/projectdiscovery/cdncheck) to filter for known CDN IP ranges for both IPv6 and IPv4 exept for `./.src/doh-domains_mini_good.txt` this is google and cloudflare it doesn't use cdncheck and is part of both `mini` and `full` this is because cloudflare uses part of it's published CDN range for it's DNS on IPv6
