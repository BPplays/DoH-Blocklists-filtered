package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"


	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

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

func queryWithResolvers(domain string, qtypes []uint16, resolvers []string, timeout time.Duration, tries int) ([]string, error) {
	client := &dns.Client{Timeout: timeout}
	seen := map[string]struct{}{}
	results := []string{}

	for _, qtype := range qtypes {
		for _, resolver := range resolvers {
			var lastErr error
			for attempt := 0; attempt < tries; attempt++ {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(domain), qtype)
				in, _, err := client.Exchange(msg, resolver)
				if err != nil {
					lastErr = err
					// retry same resolver up to tries
					continue
				}
				if in == nil || in.Rcode != dns.RcodeSuccess {
					lastErr = fmt.Errorf("bad rcode: %v", in)
					continue
				}
				for _, ans := range in.Answer {
					switch v := ans.(type) {
					case *dns.AAAA:
						if _, ok := seen[v.AAAA.String()]; !ok {
							seen[v.AAAA.String()] = struct{}{}
							results = append(results, v.AAAA.String())
						}
					case *dns.A:
						if _, ok := seen[v.A.String()]; !ok {
							seen[v.A.String()] = struct{}{}
							results = append(results, v.A.String())
						}
					}
				}
				// break out of retry loop for this resolver (we got a response)
				lastErr = nil
				break
			}
			// if this resolver failed completely, try next resolver
			if lastErr != nil {
				// you can log lastErr if you want
				continue
			}
			// if we already have answers for this qtype, optionally stop trying other resolvers
			// here we continue so that we collect A and AAAA from all resolvers if they exist
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no answers from any resolver")
	}
	return results, nil
}


func preCheck(cfg Config) {
	checkDomains := []string{"example.com", "google.com"}
	timeout := 5 * time.Second
	tries := 5

	queryWithResolvers()

}

func main() {
	configPath := flag.String("c", "", "")
	flag.Parse()

	cfg := readConfig(*configPath)
	makeDirs(cfg)

}
