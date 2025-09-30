package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var typeMap map[string]string = map[string]string{
  "ipv6": "-doh-ipv6",
  "ipv4":   "-doh-ipv4",
  "domains":   "-doh-domains",
}


type Config struct {
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

		break
	}

	return cfg
}

func main() {
	configPath := flag.String("c", "", "")
	flag.Parse()

	cfg := readConfig(*configPath)
	makeDirs(cfg)

}
