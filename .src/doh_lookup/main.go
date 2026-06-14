package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/semaphore"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"

	"github.com/projectdiscovery/cdncheck"
	"gopkg.in/yaml.v3"
)

var (
	cacheFormat string = "%v/.cache/%v%v.yml"
	cacheDir *string

	Nat64Prefixs []netip.Prefix
	WellKnownNat64Prefixs []netip.Prefix
)

type snapshot struct {
	m map[string][]byte
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type CDNcheckClientWrapper struct {
	client *cdncheck.Client
}

var (
	cdnCheckInstance *CDNcheckClientWrapper = &CDNcheckClientWrapper{}
)


// Expose methods through wrapper if you want
func (c *CDNcheckClientWrapper) Client() *cdncheck.Client {
	return c.client
}

type prefixList []netip.Prefix

func (p *prefixList) String() string {
	parts := make([]string, len(*p))
	for i, v := range *p {
		parts[i] = v.String()
	}
	return strings.Join(parts, ",")
}

func (p *prefixList) Set(s string) error {
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = append(*p, pfx)
	return nil
}

var errDomainNotOk error = errors.New("domain not ok")
var errNotEnoughLines error = errors.New("file doesn't have enough lines")
var errInputListTooShort error = errors.New("input list too short")

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

func (l *Line) SingleString() (str string) {
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

	return l.Addr.String()

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

func validateIpLines(ips []Line, publicOnly bool) (out []Line) {
	for _, ip := range ips {
		if validateIp(ip.Addr, publicOnly) {
			out = append(out, ip)
		}
	}
	return out
}

func LinesToStrings(lines []Line) (strs []string) {
	for _, l := range lines {
		strs = append(strs, l.String())
	}
	return strs
}

func LinesToSingleStrings(lines []Line) (strs []string) {
	for _, l := range lines {
		strs = append(strs, l.SingleString())
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
		if *cacheDir != "" {
			name = filepath.Clean(name)
			name = filepath.Join(*cacheDir, name)
			err := os.MkdirAll(filepath.Dir(name), 0755)
			if err != nil {
				log.Printf("can't mkdirAll: %v", err)
			}
		}

		*loop.caches, err = readCache(
			name,
			list.CacheTime,
		)
		if err == nil {
			writeCaches := putCacheToCache(
				*loop.caches,
				makeNewCaches(*loop.lines),
			)

			slices.SortFunc(writeCaches, sortCache)

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

func toNat64(nat64_prefixs []netip.Prefix, ipv4s []Line) (nat64s []Line) {
	for _, line := range ipv4s {
		if (!line.Addr.Is4In6()) && (!line.Addr.Is4()) {
			continue
		}
		for _, pref := range nat64_prefixs {
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
	if len(ips) <= 0 { return ips }

	prevIp := netip.IPv6Unspecified()

	slices.SortFunc(ips, sortLine)

	ips = validateIpLines(ips, false)

	// Needed or else might not finish last line, TODO: fix later (probably never)
	ips = append(ips, Line{Addr: netip.IPv6Unspecified()})

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

	out = validateIpLines(out, false)

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

func normalizeToURLPath(p string) string {
    // Turn OS separators into forward slashes
    s := filepath.ToSlash(p)
    // Use path.Clean because it works with forward-slash paths (URL-style)
    // Prepend "/" if you want an absolute-looking path
    s = path.Clean("/" + s)
    if s == "." {
        return "/"
    }
    return s
}


func updateList(name string, lines []Line, list List) (m map[string][]byte) {
	m = make(map[string][]byte)

	nameBase := fmt.Sprintf(
		"%v%v",
		list.OutputFilePrefix,
		name,
	)



	txtPath := fmt.Sprintf(
			"%v/%v.txt",
			list.OutputDir,
			nameBase,
			)
	fmt.Printf("saving to map [%v]\n", txtPath)
	m[normalizeToURLPath(txtPath)] = []byte(strings.Join(LinesToStrings(lines), "\n"))



	jsonPath := fmt.Sprintf(
			"%v/json/%v.json",
			list.OutputDir,
			nameBase,
			)
	fmt.Printf("saving to map [%v]\n", jsonPath)

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// encoder.SetIndent("", "  ")
	err := encoder.Encode(LinesToSingleStrings(lines))
	if err != nil {
		fmt.Printf("failed to encode json: %v\n", err)
	}
	m[normalizeToURLPath(jsonPath)] = buf.Bytes()

	return m
}

func writeList(name string, lines []Line, list List) {

	dirs := []string{filepath.Join(list.OutputDir, "json")}
	for _, dir := range dirs {
		fmt.Printf("making dir: %v\n", dir)
		os.MkdirAll(dir, 0755)
	}

	nameBase := fmt.Sprintf(
		"%v%v",
		list.OutputFilePrefix,
		name,
	)



	txtPath := fmt.Sprintf(
			"%v/%v.txt",
			list.OutputDir,
			nameBase,
			)
	fmt.Printf("writing to [%v]\n", txtPath)
	err := os.WriteFile(
		txtPath,
		[]byte(strings.Join(LinesToStrings(lines), "\n")),
		0644,
		)
	if err != nil {
		fmt.Printf("[%v] error wring file %v\n", name, err)
	}



	jsonPath := fmt.Sprintf(
			"%v/json/%v.json",
			list.OutputDir,
			nameBase,
			)
	fmt.Printf("writing to [%v]\n", jsonPath)
	file, err := os.OpenFile(
		jsonPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		fmt.Printf("failed to write json: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	// encoder.SetIndent("", "  ")
	err = encoder.Encode(LinesToSingleStrings(lines))
	if err != nil {
		fmt.Printf("failed to encode json: %v\n", err)
	}

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

	client := cdnCheckInstance.client
	for _, addrStr := range append(data.AAAA, data.A...) {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}

		if !validateIp(addr, inputFile.PublicIpsOnly) { continue }

		uaddr := addr.Unmap()

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

func checkList(
	ctx context.Context,
	sem *semaphore.Weighted,
	list List,
) ([]Line, []Line, []Line, error) {

	var v6Ips []Line
	var v4Ips []Line
	var validDomains []Line

	var wg sync.WaitGroup
	var mu sync.Mutex

	start := time.Now()
	for _, ifile := range list.InputFiles {
		if ctx.Err() != nil { break }

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
			err = sem.Acquire(ctx, 1)
			if err != nil {
				fmt.Printf("sem Acquire failed: %v\n", err)
				return v6Ips, v4Ips, validDomains, err
			}
			// fmt.Println("sem acquired")

			if ctx.Err() != nil { break }

			wg.Add(1)
			go func(host string) {
				defer func() {
					wg.Done()
					sem.Release(1)
					// fmt.Println("sem released")
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

	return v6Ips, v4Ips, validDomains, nil
}

func checkDns(cfg Config, updateList func(string, []Line, List)) {
	var wg sync.WaitGroup

	fmt.Println(len(cfg.Lists))
	fmt.Println(cfg.Lists)

	ctx := context.Background()
	sem := semaphore.NewWeighted(256)

	for _, list := range cfg.Lists {
		wg.Add(1)
		go func() {
			defer wg.Done()

			v6Ips, v4Ips, validDomains, err := checkList(ctx, sem, list)

			if err != nil {
				log.Fatalf("checkList error: %v\n", err)
			}

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

			updateList("-doh-ipv6", v6Out, list)
			updateList("-doh-ipv4", v4Out, list)

			updateList("-doh-ipv4-nat64", toNat64(Nat64Prefixs, v4Out), list)

			updateList("-doh-domains", domainsOut, list)

		}()
	}
	wg.Wait()
}

func fetchAndSaveIfValid(urls []string, outputPath string, minLines int) error {
	if len(urls) < 1 {
		return errInputListTooShort
	}
	url := urls[0]

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
		if len(urls) < 2 {
			return errNotEnoughLines
		} else {
			return fetchAndSaveIfValid(urls[1:], outputPath, minLines)
		}
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
	t := false
	dryRun = &t

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


	WellKnownNat64Prefixs = append(
		WellKnownNat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1::/96"),
	)
	WellKnownNat64Prefixs = append(
		WellKnownNat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffe::/96"),
	)
	WellKnownNat64Prefixs = append(
		WellKnownNat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffd:1::/96"),
	)
	WellKnownNat64Prefixs = append(
		WellKnownNat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:fffc:2::/96"),
	)
	WellKnownNat64Prefixs = append(
		WellKnownNat64Prefixs,
		netip.MustParsePrefix("64:ff9b:1:abcd:0:5431::/96"),
	)


	cdnCheckInstance = &CDNcheckClientWrapper{
		client: cdncheck.New(),
	}

}

func main() {
	var webgetFileUrls stringSliceFlag
	var customNat64 prefixList

	configPath := flag.String("c", "", "")
	daemon := flag.Bool("d", false, "")
	port := flag.Int("port", 58182, "")
	webgetOnly := flag.Bool("curl_only", false, "")
	webgetFileUrl := flag.String("curl_url", "", "")
	flag.Var(&webgetFileUrls, "u", "URL (can be specified multiple times)")
	webgetFileLoc := flag.String("curl_loc", "", "")
	newCwd := flag.String("chdir", "", "")
	cacheDir = flag.String("chdir_cache", "", "")
	flag.Var(
		&customNat64,
		"n",
		"NAT64 prefixes; may be repeated; overrides the defaults",
	)
	flag.Parse()

	os.Chdir(*newCwd)

	webgetFileUrls = append(webgetFileUrls, *webgetFileUrl)

	if *port > math.MaxUint16 {
		log.Println("port too big")
		os.Exit(1)
	}

	if *port < 0 {
		log.Println("port < 0")
		os.Exit(1)
	}


	var cfg Config

	if !*webgetOnly {
		cfg = readConfig(*configPath)
		preCheck()
	}


	if len(customNat64) <= 0 {
		fmt.Println(customNat64)
		Nat64Prefixs = append(
			Nat64Prefixs,
			WellKnownNat64Prefixs...,
		)
	} else {
		Nat64Prefixs = append(Nat64Prefixs, customNat64...)
		fmt.Printf("using custom NAT64 prefixes: %v\n", Nat64Prefixs)
	}


	var snap atomic.Value
	snap.Store(snapshot{m: map[string][]byte{}})

	if *daemon {
		if *webgetOnly {
			log.Println("can't have daemon and curl_only")
		}

		sleepTime := 100 * time.Second
		sleepTimeFetch := 500 * time.Second
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			s := snap.Load().(snapshot)
			if data, ok := s.m[r.URL.Path]; ok {
				w.Write(data)
				return
			}
			fmt.Printf("snap is %v\npath is %v\n", s, r.URL.Path)
			http.NotFound(w, r)
		})
		srv := &http.Server{
			Addr: fmt.Sprintf("[::]:%d", *port),
		}

		if len(webgetFileUrls) > 0 {
			go func() {
				startTime := time.Now()
				for range 10 {
					err := fetchAndSaveIfValid(webgetFileUrls, *webgetFileLoc, 50)
					if err == nil { break }
					time.Sleep(110 * time.Millisecond)
				}
				time.Sleep(sleepTimeFetch - time.Since(startTime))
			}()
		}

		go func() {
			log.Printf("listening on %s\n", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("server error: %v", err)
			}
		}()

		for {
			startTime := time.Now()
			snapMap := make(map[string][]byte)
			checkDns(
				cfg,
				func(s string, l1 []Line, l2 List) {
					newMap := updateList(s, l1, l2)
					snapMap = mapsutil.Merge(snapMap, newMap)
				},
			)
			snap.Store(snapshot{m: snapMap})
			time.Sleep(sleepTime - time.Since(startTime))
		}

	} else {
		if len(webgetFileUrls) > 0 {
			var err error
			for range 10 {
				err = fetchAndSaveIfValid(webgetFileUrls, *webgetFileLoc, 50)
				if err == nil { break }
				time.Sleep(110 * time.Millisecond)
			}

			if *webgetOnly {
				if err == nil {
					os.Exit(0)
				} else {
					os.Exit(1)
				}
			}
		}

		makeDirs(cfg)
		start := time.Now()
		checkDns(cfg, writeList)

		fmt.Printf("total resolve time: %v\n", time.Since(start))

	}

}
