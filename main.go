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
	"flag"
	"fmt"

	"github.com/kubermatic/k8sniff/metrics"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var k8sniffConfig, kubeconfig string

	flag.StringVar(&k8sniffConfig, "config", "k8sniff.json", "Config")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.Parse()

	config, err := LoadConfig(k8sniffConfig)
	if err != nil {
		panic(err)
	}
	config.Kubernetes.Kubeconfig = kubeconfig

	var cfg *rest.Config
	if config.Kubernetes.Kubeconfig != "" {
		// uses the current context in kubeconfig
		cfg, err = clientcmd.BuildConfigFromFlags("", config.Kubernetes.Kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		// creates the in-cluster config
		cfg, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}
	config.Kubernetes.Client = kubernetes.NewForConfigOrDie(cfg)

	go metrics.Serve(fmt.Sprintf("%s:%d", config.Metrics.Host, config.Metrics.Port), config.Metrics.Path)

	panic(config.Serve())
}
