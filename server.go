/* {{{ Copyright (c) Paul R. Tagliamonte <paultag@debian.org>, 2015
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sync"

	"github.com/paultag/sniff/parser"
)

type ServerAndRegexp struct {
	Server *Server
	Regexp *regexp.Regexp
}

type Proxy struct {
	Lock       sync.RWMutex
	ServerList []ServerAndRegexp
	Default    *Server
}

func (c *Proxy) Get(host string) *Server {
	c.Lock.RLock()
	defer c.Lock.RUnlock()

	for _, tuple := range c.ServerList {
		if tuple.Regexp.MatchString(host) {
			return tuple.Server
		}
	}
	return c.Default
}

func (p *Proxy) Update(c *Config) error {
	servers := []ServerAndRegexp{}
	for i, server := range c.Servers {
		for _, hostname := range server.Names {
			var host_regexp *regexp.Regexp
			var err error
			if server.Regexp {
				host_regexp, err = regexp.Compile(hostname)
			} else {
				host_regexp, err = regexp.Compile("^" + regexp.QuoteMeta(hostname) + "$")
			}
			if err != nil {
				fmt.Errorf("Cannot update proxy due to invalid regex: %v", err)
				return err
			}
			tuple := ServerAndRegexp{&c.Servers[i], host_regexp}
			servers = append(servers, tuple)
		}
	}
	var def *Server
	for i, server := range c.Servers {
		if server.Default {
			def = &c.Servers[i]
			break
		}
	}

	p.Lock.Lock()
	defer p.Lock.Unlock()
	p.ServerList = servers
	p.Default = def

	return nil
}

func (c *Config) Serve() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(
		"%s:%d", c.Bind.Host, c.Bind.Port,
	))
	if err != nil {
		return err
	}

	proxy := Proxy{}
	err = proxy.Update(c)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go proxy.Handle(conn)
	}
}

func (s *Proxy) Handle(conn net.Conn) {
	data := make([]byte, 4096)

	length, err := conn.Read(data)
	if err != nil {
		log.Printf("Error: %s", err)
	}

	var proxy *Server
	hostname, hostname_err := parser.GetHostname(data[:])
	if hostname_err == nil {
		log.Printf("Parsed hostname: %s\n", hostname)

		proxy = s.Get(hostname)
		if proxy == nil {
			log.Printf("No proxy matched %s", hostname)
			conn.Close()
			return
		}
	} else {
		log.Printf("Parsed request without hostname")

		proxy = s.Default
		if proxy == nil {
			log.Printf("No default proxy")
			conn.Close()
			return
		}
	}

	clientConn, err := net.Dial("tcp", fmt.Sprintf(
		"%s:%d", proxy.Host, proxy.Port,
	))
	if err != nil {
		log.Printf("Error: %s", err)
		conn.Close()
		return
	}
	n, err := clientConn.Write(data[:length])
	log.Printf("Wrote %d bytes\n", n)
	if err != nil {
		log.Printf("Error: %s", err)
		conn.Close()
		clientConn.Close()
	}
	Copycat(clientConn, conn)
}

func Copycat(client, server net.Conn) {
	defer client.Close()
	defer server.Close()

	log.Printf("Entering copy routine\n")

	doCopy := func(s, c net.Conn, cancel chan<- bool) {
		io.Copy(s, c)
		cancel <- true
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	select {
	case <-cancel:
		log.Printf("Disconnect\n")
		return
	}

}

// vim: foldmethod=marker
