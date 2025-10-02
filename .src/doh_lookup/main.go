package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	"gopkg.in/yaml.v3"
)

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


func preCheck(cfg Config) {
	checkDomains := []string{"", "google.com"}
	timeout := 5 * time.Second
	tries := 5

	for _, host := range checkDomains {
		queryWithResolvers(host, tries, timeout, DefaultResolvers)
	}

}

func main() {
	configPath := flag.String("c", "", "")
	flag.Parse()

	cfg := readConfig(*configPath)
	makeDirs(cfg)

}
