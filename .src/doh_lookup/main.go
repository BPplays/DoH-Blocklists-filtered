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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"

	"github.com/projectdiscovery/cdncheck"
	"gopkg.in/yaml.v3"
)

var (
	curReqs int = 0
	maxReqs int = 256
	curReqsMu sync.Mutex
)

var errDomainNotOk error = errors.New("domain not ok")

var dryRun *bool

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
	Cache bool      `yaml:"cache"`
	CacheTime time.Duration      `yaml:"cache_time"`
	InputFiles       []InputFile `yaml:"input_files"`
	OutputDir string      `yaml:"output_dir"`
	OutputFilePrefix string      `yaml:"output_file_prefix"`
}

type InputFile struct {
	Path     string `yaml:"path"`
	CdnCheck bool   `yaml:"cdncheck"`
}

type Cache struct {
	line string `yaml:"line"`
	time time.Time `yaml:"time"`
}


func cacheFilterExpired(caches []Cache, expire time.Duration) ([]Cache) {
	var output []Cache
	for _, cache := range caches {
		oldness := time.Since(cache.time)
		if oldness > expire {
			continue
		}
		output = append(output, cache)
	}

	return output
}

func sortCache(a, b Cache) int {
	return strings.Compare(a.line, b.line)
}

func writeCache(path string, caches []Cache, expire time.Duration) (error) {
	caches = cacheFilterExpired(caches, expire)
	slices.SortFunc(caches, sortCache)

	myaml, err := yaml.Marshal(caches)
	if err != nil {
		return err
	}

	os.MkdirAll(filepath.Dir(path), 0755)
	os.WriteFile(path, myaml, 0755)
	return nil
}

func readCache(path string, expire time.Duration) ([]Cache, error) {
	var caches []Cache

	cacheB, err := os.ReadFile(path)
	if err != nil {
		return caches, err
	}

	err = yaml.Unmarshal(cacheB, caches)
	if err != nil {
		return caches, err
	}

	caches = cacheFilterExpired(caches, expire)
	slices.SortFunc(caches, sortCache)

	return caches, nil
}

func makeNewCaches(strs []string) (caches []Cache) {
	for _, str := range strs {
		caches = append(
			caches,
			Cache{line: str, time: time.Now()},
		)
	}
	return
}


func appendCache(strs []string, caches []Cache) (output []string) {
	output = append(output, strs...)
	for _, cache := range caches {
		output = append(output, cache.line)
	}
	return
}

func readAndPutCachesFromList(
	v6Ips, v4Ips, validDomains []string,
	list List,
) ([]string, []string, []string) {
	fmt.Println(
		"reading caches from list, test:",
		filepath.Join(list.OutputDir, ".cache", "ipv6.yml"),
	)

	caches, err := readCache(
		filepath.Join(list.OutputDir, ".cache", "ipv6.yml"),
		list.CacheTime,
	)
	if err == nil {
		appendCache(v6Ips, caches)
	}


	caches, err = readCache(
		filepath.Join(list.OutputDir, ".cache", "ipv4.yml"),
		list.CacheTime,
	)
	if err == nil {
		appendCache(v4Ips, caches)
	}

	caches, err = readCache(
		filepath.Join(list.OutputDir, ".cache", "valid_domains.yml"),
		list.CacheTime,
	)
	if err == nil {
		appendCache(validDomains, caches)
	}
	return v6Ips, v4Ips, validDomains
}

func writeCachesFromList(
	v6Ips, v4Ips, validDomains []string,
	list List,
) () {
	fmt.Println("writing caches from list")

	var caches []Cache

	caches = makeNewCaches(v6Ips)
	err := writeCache(
		filepath.Join(list.OutputDir, ".cache", "ipv6.yml"),
		caches,
		list.CacheTime,
	)
	if err != nil {
		log.Println("failed to save cache file:", err)
	}


	caches = makeNewCaches(v4Ips)
	err = writeCache(
		filepath.Join(list.OutputDir, ".cache", "ipv4.yml"),
		caches,
		list.CacheTime,
	)
	if err != nil {
		log.Println("failed to save cache file:", err)
	}


	caches = makeNewCaches(validDomains)
	err = writeCache(
		filepath.Join(list.OutputDir, ".cache", "valid_domains.yml"),
		caches,
		list.CacheTime,
	)
	if err != nil {
		log.Println("failed to save cache file:", err)
	}
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

	// start := time.Now()
	domainOk := false
	data, err := queryWithResolvers(host, 5, 5 * time.Second, DefaultResolvers)
	if err != nil {
		return outputV6, outputV4, err
	}

	// fmt.Printf("qeury time %v\n", time.Since(start))


	// start = time.Now()
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

		matched, _, _, err := client.Check(net.ParseIP(uaddr.String()))
		if err != nil {
			continue
		}
		if matched {fmt.Printf("cdncheck:\n    %v\n\n", fmt.Sprintf("%-40s%s", addr, "# "+host))}

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
	// fmt.Printf("addresss formatting and check time time %v\n", time.Since(start))

	return outputV6, outputV4, nil

}

func checkList(list List) ([]string, []string, []string) {

	var v6Ips []string
	var v4Ips []string
	var validDomains []string

	var wg sync.WaitGroup
	var mu sync.Mutex


	fmt.Println(list)
	if list.Cache {
		v6Ips, v4Ips, validDomains = readAndPutCachesFromList(
			v6Ips,
			v4Ips,
			validDomains,
			list,
		)
	}


	start := time.Now()
	for _, ifile := range list.InputFiles {


		var hosts []string
		file, err := os.ReadFile(ifile.Path)
		if err != nil {
			fmt.Printf("ifile read err %v\n", err)
			continue
		}

		for strHost := range strings.SplitSeq(string(file), "\n") {
			hosts = append(hosts, strings.TrimSpace(strHost))
		}

		fmt.Printf("time reading ifiles: %v\n", time.Since(start))

		start = time.Now()
		for _, host := range hosts {
			for {

				curReqsMu.Lock()
				if curReqs < maxReqs {
					if curReqs < 0 {
						log.Fatalln("curReqs is negative")
					}
					// fmt.Println("req now avail", curReqs)
					curReqsMu.Unlock()

					break
				}
				curReqsMu.Unlock()
				// fmt.Println("waiting util avail")

				time.Sleep(500 * time.Millisecond)

			}


			curReqsMu.Lock()
			curReqs += 1
			curReqsMu.Unlock()
			wg.Add(1)
			go func(){
				defer func(){
					wg.Done()
					curReqsMu.Lock()
					curReqs -= 1
					curReqsMu.Unlock()
				}()

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
	wg.Wait()
	fmt.Printf("time since hostcheck: %v\n", time.Since(start))

	if list.Cache {
		writeCachesFromList(v6Ips, v4Ips, validDomains, list)
	}

	return v6Ips, v4Ips, validDomains
}

func checkDns(cfg Config) {
	var wg sync.WaitGroup

	fmt.Println(len(cfg.Lists))
	fmt.Println(cfg.Lists)
	for _, list := range cfg.Lists {
		wg.Add(1)
		go func() {
			defer wg.Done()

			v6Ips, v4Ips, validDomains := checkList(list)
			if (len(v6Ips) <= 0) && (len(v4Ips) <= 0) {
				log.Fatalln("no ips found")
			}

			v6Out := sliceutil.Dedupe(v6Ips)
			v4Out := sliceutil.Dedupe(v4Ips)
			domainsOut := sliceutil.Dedupe(validDomains)
			if *dryRun {
				fmt.Println(strings.Join(v6Out, "\n"))
				return
			}

			slices.Sort(v6Out)
			slices.Sort(v4Out)
			slices.Sort(domainsOut)


			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-ipv6.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(v6Out, "\n")),
				0755,
				)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-ipv4.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(v4Out, "\n")),
				0755,
				)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-domains.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(domainsOut, "\n")),
				0755,
				)
		}()
	}
	wg.Wait()
}

func main() {
	configPath := flag.String("c", "", "")
	dryRun = flag.Bool("d", false, "")
	flag.Parse()

	cfg := readConfig(*configPath)
	makeDirs(cfg)
	preCheck()

	start := time.Now()

	checkDns(cfg)

	fmt.Printf("total resolve time: %v\n", time.Since(start))

}
