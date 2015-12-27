package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"pault.ag/go/sniff/parser"
)

func main() {
	fd, err := os.Open("/home/paultag/client.start.1")
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(data); i++ {
		name, err := parser.GetHostname(data[:i])
		fmt.Printf("%s %s\n", name, err)
	}
}
