package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"pault.ag/go/sniff/parser"
)

type SniffConfig struct {
	Default bool
	Host    string
	Names   []string
	Port    int
}

type SniffConfigList []SniffConfig

func (l *SniffConfigList) GetHostMap() map[string]SniffConfig {
	ret := map[string]SniffConfig{}

	for _, el := range *l {
		for _, host := range el.Names {
			ret[host] = el
		}
	}

	return ret
}

func (l *SniffConfigList) GetDefault() *SniffConfig {
	for _, el := range *l {
		if el.Default {
			return &el
		}
	}
	return nil
}

func LoadSniffConfig(path string) (*SniffConfigList, error) {
	fd, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	data := make(SniffConfigList, 0)
	return &data, json.NewDecoder(fd).Decode(&data)
}

func main() {
	config, err := LoadSniffConfig("/home/paultag/sniff.json")
	if err != nil {
		panic(err)
	}

	fd, err := os.Open("/home/paultag/client.start.1")
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		panic(err)
	}

	hostMap := config.GetHostMap()
	hostDefault := config.GetDefault()

	name, err := parser.GetHostname(data[:])
	if err != nil {
		panic(err)
	}

	if sniffConfig, ok := hostMap[name]; ok {
		fmt.Printf("%s\n", sniffConfig.Host)
	} else {
		if hostDefault == nil {
			panic("No default")
		}
		fmt.Printf("%s\n", hostDefault.Host)
	}
}
