package main

import (
	"crypto/rand"
	"encoding/hex"
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
	"bufio"
	"bytes"
	"io"
	"net/http"

	"golang.org/x/crypto/sha3"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"

	"github.com/projectdiscovery/cdncheck"
	"gopkg.in/yaml.v3"
)

var (
	curReqs   int = 0
	maxReqs   int = 256
	curReqsMu sync.Mutex

	cacheFormat string = "%v/.cache/%v%v.yml"

	nat64Prefixs []netip.Prefix
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
		go func() {
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
		if result {
			return true
		}
	}
	return false
}

func availableIpVersions() (hasV6 bool, hasV4 bool) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if checkConnectivity([]string{"[2001:4860:4860::8888]:53"}, "udp") {
			hasV6 = true
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if checkConnectivity([]string{"8.8.8.8:53"}, "udp") {
			hasV4 = true
		}
	}()

	wg.Wait()

	return hasV6, hasV4
}

var typeMap map[string]string = map[string]string{
	"ipv6":    "-doh-ipv6",
	"ipv4":    "-doh-ipv4",
	"nat64":   "-doh-ipv4-nat64",
	"domains": "-doh-domains",
	"domain":  "-doh-domains",
}

type Config struct {
	Resolvers []string `yaml:"resolvers"`
	Lists     []List   `yaml:"lists"`
}

type List struct {
	Name             string        `yaml:"name"`
	Cache            bool          `yaml:"cache"`
	CacheTime        time.Duration `yaml:"cache_time"`
	InputFiles       []InputFile   `yaml:"input_files"`
	OutputDir        string        `yaml:"output_dir"`
	OutputFilePrefix string        `yaml:"output_file_prefix"`
}

type InputFile struct {
	Path     string `yaml:"path"`
	CdnCheck bool   `yaml:"cdncheck"`
	PublicIpsOnly bool   `yaml:"public_ips_only"`
}

type Line struct {
	Host       string     `yaml:"host"`
	Addr       netip.Addr `yaml:"addr"`
	ExtraHosts []string   `yaml:"extra_hosts"`
}

func (l *Line) String() (str string) {
	defer func() {
		if r := recover(); r != nil {
			str = ""
		}
	}()

	str = ""

	if l == nil {
		return str
	}

	if l.Addr.IsUnspecified() {
		return l.Host
	}

	hosts := []string{l.Host}
	hosts = append(hosts, l.ExtraHosts...)
	hosts = sliceutil.Dedupe(hosts)
	slices.Sort(hosts)

	// always a 2 space gap at least
	if !l.Addr.Is4() {
		return fmt.Sprintf("%-41s%s", l.Addr, "# "+strings.Join(hosts, ", "))
	} else {
		return fmt.Sprintf("%-17s%s", l.Addr, "# "+strings.Join(hosts, ", "))
	}

}

func (l *Line) mapKey() (str string) {
	defer func() {
		if r := recover(); r != nil {
			randomBytes := make([]byte, 128)
			_, err := rand.Read(randomBytes)
			if err != nil {
				str = rand.Text()
				return
			}
			hash := sha3.Sum512(randomBytes)
			str = hex.EncodeToString(hash[:])
		}
	}()

	if l == nil {
		randomBytes := make([]byte, 128)
		_, err := rand.Read(randomBytes)
		if err != nil {
			str = rand.Text()
			return
		}
		hash := sha3.Sum512(randomBytes)
		str = hex.EncodeToString(hash[:])
		return str
	}


	var sb strings.Builder
	sb.WriteString(fmt.Sprint(l.Addr))
	sb.WriteString(l.Host)

	sb.WriteString("ah")

	hosts := []string{l.Host}
	hosts = append(hosts, l.ExtraHosts...)
	slices.Sort(hosts)

	sb.WriteString(strings.Join(hosts, ""))

	return sb.String()

}

type Cache struct {
	Line Line      `yaml:"line"`
	Time time.Time `yaml:"time"`
}

type CacheLoop struct {
	name   string
	lines  *[]Line
	caches *[]Cache
}

func cacheFilterExpired(caches []Cache, expire time.Duration) []Cache {
	var output []Cache
	for _, cache := range caches {
		oldness := time.Since(cache.Time)
		if oldness > expire {
			continue
		}
		output = append(output, cache)
	}

	return output
}

func sortCache(a, b Cache) int {
	return sortLine(a.Line, b.Line)
}
func sortLine(a, b Line) int {
	if (!a.Addr.IsUnspecified()) && (!b.Addr.IsUnspecified()) {
		return a.Addr.Compare(b.Addr)
	}

	if (a.Addr.IsUnspecified()) && (b.Addr.IsUnspecified()) {
		return strings.Compare(a.Host, b.Host)
	}

	return strings.Compare(a.String(), b.String())
}

func validateIps(lines []Line) (out []Line) {
	for _, l := range lines {
		if !validateIp(l.Addr, false) { continue }

		out = append(out, l)
	}

	return out
}

func validateIp(ip netip.Addr, publicOnly bool) bool {
	if ip.Is4In6() { ip = netip.AddrFrom4(ip.As4()) }

	if !ip.IsValid() { return false }
	if ip.IsUnspecified() { return false }
	if ip.IsLoopback() { return false }

	if publicOnly {
		if ip.IsLinkLocalUnicast() { return false }
		if ip.IsPrivate() { return false }
		if ip.IsLinkLocalMulticast() { return false }
		if ip.IsInterfaceLocalMulticast() { return false }
	}


	return true
}

func LinesToStrings(lines []Line) (strs []string) {
	for _, l := range lines {
		strs = append(strs, l.String())
	}
	return strs
}

func mixPrefixIP(prefix *netip.Prefix, suffix *netip.Addr) *netip.Prefix {
	prefixBits := prefix.Bits()
	if prefixBits >= 128 {
		return prefix
	}

	prefixBytes := (*prefix).Addr().As16()
	suffixBytes := (*suffix).As16()

	fullBytes := prefixBits / 8 // how many full bytes the prefix occupies
	rem := prefixBits % 8       // leftover bits in the partial byte (0..7)

	if rem == 0 {
		copy(prefixBytes[fullBytes:], suffixBytes[fullBytes:])
	} else {
		mask := byte(0xFF) << uint(8-rem) // mask has top `rem` bits set
		prefixBytes[fullBytes] = (prefixBytes[fullBytes] & mask) | (suffixBytes[fullBytes] & ^mask)
		if fullBytes+1 <= 15 {
			copy(prefixBytes[fullBytes+1:], suffixBytes[fullBytes+1:])
		}
	}

	out := netip.AddrFrom16(prefixBytes)
	outPrefix := netip.PrefixFrom(out, prefixBits)
	return &outPrefix
}

func writeCache(path string, caches []Cache, expire time.Duration) error {
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

	err = yaml.Unmarshal(cacheB, &caches)
	if err != nil {
		return caches, err
	}

	caches = cacheFilterExpired(caches, expire)
	slices.SortFunc(caches, sortCache)

	return caches, nil
}

func makeNewCaches(lines []Line) (caches []Cache) {
	for _, line := range lines {
		caches = append(
			caches,
			Cache{Line: line, Time: time.Now()},
		)
	}
	return
}

func appendCacheToLines(lines []Line, caches []Cache) (output []Line) {
	output = append(output, lines...)
	for _, cache := range caches {
		output = append(output, cache.Line)
	}
	return
}

func putCacheToCache(caches []Cache, newCaches []Cache) (output []Cache) {
	output = append(output, caches...)

	cMap := make(map[string]int, len(output))
	for i, cache := range output {
		cMap[cache.Line.mapKey()] = i
	}

	for _, newCache := range newCaches {
		if index, ok := cMap[newCache.Line.mapKey()]; ok {
			if newCache.Time.Compare(output[index].Time) > 0 {
				output[index] = newCache
			}
		} else {
			output = append(output, newCache)
		}
	}
	return
}

func readAndPutCachesFromListAndWriteOut(
	v6Ips, v4Ips, validDomains []Line,
	list List,
) ([]Cache, []Cache, []Cache, []Line, []Line, []Line) {
	var cachesV6, cachesV4, cachesDomain []Cache
	var err error

	v6Ips = lineDedupeIps(v6Ips)
	v4Ips = lineDedupeIps(v4Ips)

	v6Ips = validateIps(v6Ips)
	v4Ips = validateIps(v4Ips)

	fmt.Println("reading caches from list")

	loops := []CacheLoop{
		{
			name:   typeMap["ipv6"],
			lines:  &v6Ips,
			caches: &cachesV6,
		},

		{
			name:   typeMap["ipv4"],
			lines:  &v4Ips,
			caches: &cachesV4,
		},

		{
			name:   typeMap["domains"],
			lines:  &validDomains,
			caches: &cachesDomain,
		},
	}

	for _, loop := range loops {

		name := fmt.Sprintf(
			cacheFormat,
			list.OutputDir,
			list.OutputFilePrefix,
			loop.name,
		)

		*loop.caches, err = readCache(
			name,
			list.CacheTime,
		)
		if err == nil {
			writeCaches := putCacheToCache(
				*loop.caches,
				makeNewCaches(*loop.lines),
			)

			err := writeCache(name, writeCaches, list.CacheTime)
			if err != nil {
				log.Println("error writing cache:", err)
			}

			*loop.lines = appendCacheToLines(*loop.lines, *loop.caches)

		} else {
			if os.IsNotExist(err) {
				log.Println("making cache doesn't exist, for:", loop.name)
				err := writeCache(name, makeNewCaches(*loop.lines), list.CacheTime)
				if err != nil {
					log.Println("error writing and making new cache:", err)
				}

			} else {
				log.Println("error reading cache:", err)
			}
		}

	}

	return cachesV6, cachesV4, cachesDomain, v6Ips, v4Ips, validDomains
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

func toNat64(ipv4s []Line) (nat64s []Line) {
	for _, line := range ipv4s {
		if (!line.Addr.Is4In6()) && (!line.Addr.Is4()) {
			continue
		}
		for _, pref := range nat64Prefixs {
			// always use 96 or else mapped ipv4 get ::ffff infront
			nat64Pref := netip.PrefixFrom(pref.Addr(), 96)
			addr := mixPrefixIP(&nat64Pref, &line.Addr)

			tmpLine := line
			tmpLine.Addr = (*addr).Addr()

			nat64s = append(nat64s, tmpLine)
		}
	}

	slices.SortFunc(nat64s, sortLine)

	return nat64s
}

func lineDedupeIps(ips []Line) (out []Line) {

	prevIp := netip.IPv6Unspecified()

	slices.SortFunc(ips, sortLine)

	for i, ip := range ips {
		if i == 0 {
			prevIp = ip.Addr
			out = append(out, ip)
			continue
		}

		if ip.Addr == prevIp {
			tmp := out[len(out)-1]
			tmp.ExtraHosts = append(tmp.ExtraHosts, ip.Host)
			out[len(out)-1] = tmp
		} else {
			tmp := out[len(out)-1]

			hosts := []string{tmp.Host}
			hosts = append(hosts, tmp.ExtraHosts...)
			hosts = sliceutil.Dedupe(hosts)
			slices.Sort(hosts)


			if len(hosts) >= 1 {
				tmp.Host = hosts[0]
			}

			if len(hosts) >= 2 {
				tmp.ExtraHosts = hosts[1:]
			} else {
				tmp.ExtraHosts = []string{}
			}

			out[len(out)-1] = tmp

			prevIp = ip.Addr
			out = append(out, ip)
		}

	}

	return out
}

func lineDedupeHost(host Line) any {
	return host.Host
}

func readConfig(file string) Config {
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
		MaxRetries:    MaxRetries,
		Timeout:       timeout,
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

func checkHost(
	host string,
	inputFile InputFile,
) (
	outputV6 []Line,
	outputV4 []Line,
	err error,
) {

	// start := time.Now()
	domainOk := false
	data, err := queryWithResolvers(host, 5, 5*time.Second, DefaultResolvers)
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

		if !validateIp(addr, inputFile.PublicIpsOnly) { continue }

		uaddr := addr.Unmap()
		client := cdncheck.New()

		matched, _, _, err := client.Check(net.ParseIP(uaddr.String()))
		if err != nil {
			continue
		}
		if matched {
			fmt.Printf("cdncheck:\n    %v\n\n", fmt.Sprintf("%-40s%s", addr, "# "+host))
		}

		if inputFile.CdnCheck && matched {
			continue
		}


		domainOk = true
		if uaddr.Is6() {
			outputV6 = append(
				outputV6,
				Line{Addr: uaddr, Host: host},
			)

		} else if uaddr.Is4() {
			outputV4 = append(
				outputV4,
				Line{Addr: uaddr, Host: host},
			)
		}

	}

	if !domainOk || (len(outputV6) <= 0 && len(outputV4) <= 0) {
		return outputV6, outputV4, errDomainNotOk
	}
	// fmt.Printf("addresss formatting and check time time %v\n", time.Since(start))

	return outputV6, outputV4, nil

}

func checkList(list List) ([]Line, []Line, []Line) {

	var v6Ips []Line
	var v4Ips []Line
	var validDomains []Line

	var wg sync.WaitGroup
	var mu sync.Mutex

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

				time.Sleep(200 * time.Millisecond)

			}

			curReqsMu.Lock()
			curReqs += 1
			curReqsMu.Unlock()
			wg.Add(1)
			go func(host string) {
				defer func() {
					wg.Done()
					curReqsMu.Lock()
					curReqs -= 1
					curReqsMu.Unlock()
				}()

				hostIpsV6, hostIpsV4, err := checkHost(host, ifile)
				if err != nil {
					return
				}

				mu.Lock()
				v6Ips = append(v6Ips, hostIpsV6...)
				v4Ips = append(v4Ips, hostIpsV4...)
				validDomains = append(validDomains, Line{
					Host: host,
					Addr: netip.IPv6Unspecified(),
				})
				mu.Unlock()

			}(host)

		}
	}
	wg.Wait()
	fmt.Printf("time since hostcheck: %v\n", time.Since(start))

	v6Ips = lineDedupeIps(v6Ips)
	v4Ips = lineDedupeIps(v4Ips)
	validDomains = sliceutil.DedupeFunc(
		validDomains,
		lineDedupeHost,
	)

	fmt.Println(list)
	// var cachesV6, cachesV4, cachesDomain []Cache

	if list.Cache {
		_, _, _, v6Ips, v4Ips, validDomains = readAndPutCachesFromListAndWriteOut(
			v6Ips,
			v4Ips,
			validDomains,
			list,
		)
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

			v6Out := lineDedupeIps(v6Ips)
			v4Out := lineDedupeIps(v4Ips)
			v6Out = validateIps(v6Out)
			v4Out = validateIps(v4Out)

			domainsOut := sliceutil.DedupeFunc(
				validDomains,
				lineDedupeHost,
			)
			if *dryRun {
				fmt.Println(strings.Join(LinesToStrings(v6Out), "\n"))
				return
			}

			slices.SortFunc(v6Out, sortLine)
			slices.SortFunc(v4Out, sortLine)
			slices.SortFunc(domainsOut, sortLine)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-ipv6.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(LinesToStrings(v6Out), "\n")),
				0755,
			)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-ipv4.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(LinesToStrings(v4Out), "\n")),
				0755,
			)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-ipv4-nat64.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(LinesToStrings(toNat64(v4Out)), "\n")),
				0755,
			)

			os.WriteFile(
				fmt.Sprintf(
					"%v/%v-doh-domains.txt",
					list.OutputDir,
					list.OutputFilePrefix,
				),
				[]byte(strings.Join(LinesToStrings(domainsOut), "\n")),
				0755,
			)
		}()
	}
	wg.Wait()
}

func fetchAndSaveIfValid(url, outputPath string, minLines int) error {
	// Fetch the file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Read the entire response into memory
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Count lines
	lineCount := countLines(data)
	fmt.Printf("File has %d lines\n", lineCount)

	// Check if file meets minimum line requirement
	if lineCount < minLines {
		fmt.Printf("File has fewer than %d lines, not saving\n", minLines)
		return nil
	}

	// Save the file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}

	fmt.Printf("File saved to %s\n", outputPath)
	return nil
}

func countLines(data []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		count++
	}
	return count
}

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

	nat64Prefixs = append(
		nat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1::/96"),
	)
	nat64Prefixs = append(
		nat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffe::/96"),
	)
	nat64Prefixs = append(
		nat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffd:1::/96"),
	)
	nat64Prefixs = append(
		nat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffc:2::/96"),
	)
	nat64Prefixs = append(
		nat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:abcd:0:5431::/96"),
	)

}

func main() {
	configPath := flag.String("c", "", "")
	dryRun = flag.Bool("d", false, "")
	webgetFileUrl := flag.String("curl_url", "", "")
	webgetFileLoc := flag.String("curl_loc", "", "")
	flag.Parse()

	if *webgetFileUrl != "" {
		for range 10 {
			err := fetchAndSaveIfValid(*webgetFileUrl, *webgetFileLoc, 50)
			if err == nil { break }
			time.Sleep(110 * time.Millisecond)
		}
		os.Exit(0)
	}

	cfg := readConfig(*configPath)
	makeDirs(cfg)
	preCheck()

	start := time.Now()

	checkDns(cfg)

	fmt.Printf("total resolve time: %v\n", time.Since(start))

}
