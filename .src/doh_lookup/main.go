package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	// sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/projectdiscovery/cdncheck"
	"gopkg.in/yaml.v3"
)

var errDomainNotOk error = errors.New("domain not ok")

var DefaultResolvers []string

// IPv6Resolvers trusted IPv6 resolvers
var IPv6Resolvers = []string{
	"[2606:4700:4700::1111]:53",
	"[2606:4700:4700::1001]:53",
	"[2001:4860:4860::8888]:53",
	"[2001:4860:4860::8844]:53",
}

// IPv4Resolvers trusted IPv4 resolvers
var IPv4Resolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// checkConnectivity tests if connectivity is available to any of the IPs you input
//
// - IPs: IPs and ports (e.g. "[2001:db8::1]:53")
//
// - proto: protocol to use (e.g. "udp", "tcp", etc)
func checkConnectivity(IPs []string, proto string) bool {
	var wg sync.WaitGroup
	results := make(chan bool, len(IPs))

	for _, IP := range IPs {
		wg.Add(1)
		go func(){
			defer wg.Done()

			conn, err := net.DialTimeout(proto, IP, 3*time.Second)
			if conn != nil {
				defer conn.Close()
			}

			results <- err == nil
		}()
	}
	wg.Wait()
	close(results)

	for result := range results {
		if result { return true }
	}
	return false
}

func availableIpVersions() (hasV6 bool, hasV4 bool) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func(){
		defer wg.Done()
		if checkConnectivity([]string{"[2001:4860:4860::8888]:53"}, "udp") {
			hasV6 = true
		}
	}()

	wg.Add(1)
	go func(){
		defer wg.Done()
		if checkConnectivity([]string{"8.8.8.8:53"}, "udp") {
			hasV4 = true
		}
	}()

	wg.Wait()

	return hasV6, hasV4
}


// init checks for IPv6 and IPv4 connectivity and adds either group of resolvers if available, falls back to both if it can't detect any
func init() {
	hasV6, hasV4 := availableIpVersions()

	if hasV6 {
		DefaultResolvers = append(DefaultResolvers, IPv6Resolvers...)
	}

	if hasV4 {
		DefaultResolvers = append(DefaultResolvers, IPv4Resolvers...)
	}

	if len(DefaultResolvers) <= 0 {
		DefaultResolvers = append(DefaultResolvers, IPv6Resolvers...)
		DefaultResolvers = append(DefaultResolvers, IPv4Resolvers...)
	}
}


var typeMap map[string]string = map[string]string{
  "ipv6": "-doh-ipv6",
  "ipv4":   "-doh-ipv4",
  "domains":   "-doh-domains",
}


type Config struct {
	Resolvers []string `yaml:"resolvers"`
	Lists []List `yaml:"lists"`
}

type List struct {
	Name             string      `yaml:"name"`
	InputFiles       []InputFile `yaml:"input_files"`
	OutputFilePrefix string      `yaml:"output_file_prefix"`
}

type InputFile struct {
	Path     string `yaml:"path"`
	CdnCheck bool   `yaml:"cdncheck"`
}

func makeDirs(cfg Config) {
	for _, list := range cfg.Lists {
		for _, prefix := range list.InputFiles {
			for _, fileEnd := range []string{"ipv6", "ipv4", "domains"} {
				file := fmt.Sprintf("%v%v", prefix.Path, typeMap[fileEnd])
				os.MkdirAll(filepath.Dir(file), 0755)
			}
		}
	}
}

func readConfig(file string) (Config) {
	var cfg Config

	for range 4 {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config: %v\n", err)
			continue
		}

		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "unmarshal yaml: %v\n", err)
			continue
		}

		return cfg
	}

	log.Fatalln("can't read config")
	return cfg
}


func queryWithResolvers(
	Host string,
	MaxRetries int,
	timeout time.Duration,
	resolvers []string,
) (data *retryabledns.DNSData, err error) {

	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}

	retryabledns, err := retryabledns.NewWithOptions(retryabledns.Options{
		BaseResolvers: resolvers,
		MaxRetries: MaxRetries,
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	data, err = retryabledns.QueryMultiple(Host, []uint16{
		dns.TypeAAAA,
		dns.TypeA,
	})
	if err != nil {
		return nil, err
	}

	return data, nil

}


func preCheck() {
	checkDomains := []string{"google.com", "heise.de", "openwrt.org", "facebook.com"}
	timeout := 5 * time.Second
	tries := 5

	for _, host := range checkDomains {
		data, err := queryWithResolvers(host, tries, timeout, DefaultResolvers)
		if err != nil {
			continue
		}
		if (len(data.AAAA) <= 0) || (len(data.A) <= 0) {
			continue
		}

		return
	}

	log.Fatalln("preCheck failed")

}


func checkHost(host string, useCdnCheck bool) (outputV6 []string, outputV4 []string, err error) {
	domainOk := false
	data, err := queryWithResolvers(host, 5, 5 * time.Second, DefaultResolvers)
	if err != nil {
		return outputV6, outputV4, err
	}

	for _, addrStr := range append(data.AAAA, data.A...) {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			continue
		}

		uaddr := addr.Unmap()
		client := cdncheck.New()

		matched, _, err := client.CheckCDN(net.ParseIP(uaddr.String()))
		if err != nil {
			continue
		}

		if useCdnCheck && matched {
			continue
		}



		domainOk = true
		if uaddr.Is6() {
			outputV6 = append(outputV6, fmt.Sprintf("%-40s%s", addr, "# "+host))
		} else if uaddr.Is4() {
			outputV4 = append(outputV4, fmt.Sprintf("%-20s%s", addr, "# "+host))
		}

	}

	if !domainOk || (len(outputV6) <= 0 && len(outputV4) <= 0) {
		return outputV6, outputV4, errDomainNotOk
	}

	return outputV6, outputV4, nil

}

func checkList(list List) ([]string, []string, []string) {

	var v6Ips []string
	var v4Ips []string
	var validDomains []string

	var wg sync.WaitGroup
	var mu sync.Mutex


	for _, ifile := range list.InputFiles {
		var hosts []string
		file, err := os.ReadFile(ifile.Path)
		if err != nil {
			continue
		}
		strHosts := strings.Split(string(file), "\n")
		for _, strHost := range strHosts {
			hosts = append(hosts, strings.TrimSpace(strHost))
		}

		for _, host := range hosts {
			wg.Add(1)
			go func(){
				defer wg.Done()
				hostIpsV6, hostIpsV4, err := checkHost(host, ifile.CdnCheck)
				if err != nil {
					return
				}

				mu.Lock()
				v6Ips = append(v6Ips, hostIpsV6...)
				v4Ips = append(v4Ips, hostIpsV4...)
				validDomains = append(validDomains, host)
				mu.Unlock()

			}()


		}
	}

	return v6Ips, v4Ips, validDomains
}

func checkDns(cfg Config) {
	var v6Ips []string
	var v4Ips []string
	var validDomains []string

	for _, list := range cfg.Lists {
		v6Ips, v4Ips, validDomains = checkList(list)

	}

	if (len(v6Ips) <= 0) && (len(v4Ips) <= 0) {
		log.Fatalln("no ips found")
	}
}

func main() {
	configPath := flag.String("c", "", "")
	flag.Parse()

	cfg := readConfig(*configPath)
	makeDirs(cfg)
	preCheck()


}
