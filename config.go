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
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/golang/glog"
	"k8s.io/client-go/tools/cache"
)

type Config struct {
	Bind       Bind
	Servers    []Server
	Ports      []ProxyPort
	Kubernetes *Kubernetes
	proxy      *Proxy
	portProxy  *PortProxy
	lock       sync.Mutex

	serviceController *cache.Controller
	serviceStore      cache.Store
	ingressController *cache.Controller
	ingressStore      cache.Store
}

type Kubernetes struct {
	Kubeconfig   string
	IngressClass string
}

type Bind struct {
	Host           string
	Port           int
	PortProxyRange string
}

type ProxyPort struct {
	Port       int
	TargetHost string
}

type Server struct {
	Default bool
	Regexp  bool
	Host    string
	Names   []string
	Port    int
}

func LoadConfig(path string) (*Config, error) {
	glog.V(5).Infof("Loading config from: %s", path)

	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	config := Config{}
	err = json.NewDecoder(fd).Decode(&config)
	if err != nil {
		return nil, err
	}

	glog.V(5).Infof("Read config: %+v", config)

	if len(config.Servers) > 0 && config.Kubernetes != nil {
		return nil, errors.New("Cannot set .Servers and .Kubernetes in config file")
	}

	return &config, err
}
