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
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/paultag/sniff/parser"

	corev1 "k8s.io/client-go/1.4/kubernetes/typed/core/v1"
	typedv1beta1 "k8s.io/client-go/1.4/kubernetes/typed/extensions/v1beta1"
	"k8s.io/client-go/1.4/pkg/api"
	_ "k8s.io/client-go/1.4/pkg/api/install"
	apiv1 "k8s.io/client-go/1.4/pkg/api/v1"
	_ "k8s.io/client-go/1.4/pkg/apis/extensions/install"
	extapiv1beta1 "k8s.io/client-go/1.4/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.4/pkg/fields"
	"k8s.io/client-go/1.4/pkg/util/intstr"
	"k8s.io/client-go/1.4/pkg/watch"
	"k8s.io/client-go/1.4/tools/cache"
	"k8s.io/client-go/1.4/tools/clientcmd"
)

const (
	// ingressClassKey picks a specific "class" for the Ingress. The controller
	// only processes Ingresses with this annotation either unset, or set
	// to either nginxIngressClass or the empty string.
	ingressClassKey = "kubernetes.io/ingress.class"
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
				return fmt.Errorf("cannot update proxy due to invalid regex: %v", err)
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
	glog.V(1).Infof("Listening on %s:%d", c.Bind.Host, c.Bind.Port)
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

	if c.Kubernetes != nil {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if c.Kubernetes.Kubeconfig != "" {
			rules.ExplicitPath = c.Kubernetes.Kubeconfig
		}
		ccfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
		rcfg, err := ccfg.ClientConfig()
		if err != nil {
			return err
		}
		extclient := typedv1beta1.NewForConfigOrDie(rcfg)
		client := corev1.NewForConfigOrDie(rcfg)

		// trigger to update the proxy
		updateTrigger := make(chan struct{}, 1)

		// watch services
		services := NotifyingStore{
			Store: cache.NewStore(cache.MetaNamespaceKeyFunc),
			NotifyFunc: func () {
				select {
				case updateTrigger <- struct{}{}:
				default:
				}
			},
		}
		lw := cache.NewListWatchFromClient(client, "services", "", fields.Everything())
		refl := cache.NewReflector(lw, &apiv1.Service{}, &services, time.Minute)
		refl.Run()

		// wait until services are ready
		glog.V(1).Infof("Waiting for service store to be ready")
		for {
			if refl.LastSyncResourceVersion() != "" {
				break
			}
			time.Sleep(time.Millisecond * 200)
		}

		// watch ingresses
		ingresses := map[string]*extapiv1beta1.Ingress{}
		lock := sync.Mutex{}
		class := c.Kubernetes.IngressClass
		if class == "" {
			class = "sniff"
		}
		go func() {
			for {
				w, err := extclient.Ingresses("").Watch(api.ListOptions{})
				if err != nil {
					glog.Errorf("Ingress watch error: %v", err)
					// TODO: add backoff logic
					time.Sleep(time.Second)
					continue
				}
				evs := w.ResultChan()

			EventLoop:
				for ev := range evs {
					i := ev.Object.(*extapiv1beta1.Ingress)
					if i != nil && i.Annotations[ingressClassKey] != class {
						continue
					}
					switch ev.Type {
					case watch.Added, watch.Modified:
						glog.V(5).Infof("event %s for %s/%s", ev.Type, i.Namespace, i.Name)
						lock.Lock()
						ingresses[i.Namespace+"/"+i.Name] = i
						lock.Unlock()
					case watch.Deleted:
						glog.V(5).Infof("event %s for %s/%s", ev.Type, i.Namespace, i.Name)
						lock.Lock()
						delete(ingresses, i.Namespace+"/"+i.Name)
						lock.Unlock()
					case watch.Error:
						if i != nil {
							glog.V(5).Infof("event %s for %s/%s", ev.Type, i.Namespace, i.Name)
						}
						w.Stop()
						break EventLoop
					}
					select {
					case updateTrigger <- struct{}{}:
					default:
					}
				}

				// TODO: add backoff logic
				time.Sleep(time.Second)
			}
		}()

		go func() {
			for range updateTrigger {
				lock.Lock()

				serverForBackend := func(ing *extapiv1beta1.Ingress, backend *extapiv1beta1.IngressBackend) (*Server, error) {
					obj, found, err := services.GetByKey(fmt.Sprintf("%s/%s", ing.Namespace, backend.ServiceName))
					if err != nil {
						return nil, err
					}
					if !found {
						return nil, fmt.Errorf("service %s/%s not found", ing.Namespace, backend.ServiceName)
					}
					svc := obj.(*apiv1.Service)
					var port int
					if backend.ServicePort.Type == intstr.String {
						for _, p := range svc.Spec.Ports {
							if p.Name == backend.ServicePort.StrVal {
								port = int(p.Port)
								break
							}
						}
						if port == 0 {
							return nil, fmt.Errorf("port %q of service %s/%s not found", backend.ServicePort.StrVal, svc.Namespace, svc.Name)
						}
					} else {
						port = int(backend.ServicePort.IntVal)
					}
					return &Server{
						Host: svc.Spec.ClusterIP,
						// TODO: support string values:
						Port: port,
					}, nil
				}

				for _, i := range ingresses {
					c.Servers = []Server{}
					if i.Spec.Backend != nil {
						s, err := serverForBackend(i, i.Spec.Backend)
						if err != nil {
							glog.Errorf("Ingress %s/%s error with default backend, skipping: %v", i.Namespace, i.Name, err)
						} else {
							s.Default = true
							glog.V(4).Infof("Adding default backend -> %s:%d", s.Host, s.Port)
							c.Servers = append(c.Servers, *s)
						}
					}
					for _, r := range i.Spec.Rules {
						if r.HTTP == nil {
							glog.Errorf("Ingress %s/%s error with rule, skipping: http must be set", i.Namespace, i.Name)
							continue
						}
						for _, p := range r.HTTP.Paths {
							if p.Path != "" && p.Path != "/" {
								glog.Errorf("Ingress %s/%s error with rule, skipping: %v", i.Namespace, i.Name, err)
								continue
							}
							s, err := serverForBackend(i, &p.Backend)
							if err != nil {
								glog.Errorf("Ingress %s/%s error with rule %q path %q, skipping: %v", i.Namespace, i.Name, r.Host, p.Path, err)
								continue
							}
							s.Names = []string{r.Host}
							glog.V(4).Infof("Adding backend %q -> %s:%d", r.Host, s.Host, s.Port)
							c.Servers = append(c.Servers, *s)
						}
					}
				}
				lock.Unlock()

				glog.V(2).Infof("Updating proxy configuration")
				err := proxy.Update(c)
				if err != nil {
					glog.Errorf("Error updating proxy: %v", err)
					// TODO: add backoff logic
					time.Sleep(time.Second)
				} else {
					glog.V(2).Infof("Proxy configuration update done")
				}

			}
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		glog.V(3).Infof(
			"%s -> %s",
			conn.RemoteAddr(),
			conn.LocalAddr(),
		)
		go proxy.Handle(conn)
	}
}

func (s *Proxy) Handle(conn net.Conn) {
	defer conn.Close()
	data := make([]byte, 4096)

	length, err := conn.Read(data)
	if err != nil {
		glog.V(4).Infof("Error reading the first 4k of the connection: %s", err)
		return
	}

	var proxy *Server
	hostname, hostname_err := parser.GetHostname(data[:])
	if hostname_err == nil {
		glog.V(6).Infof("Parsed hostname: %s", hostname)

		proxy = s.Get(hostname)
		if proxy == nil {
			glog.V(4).Infof("No proxy matched %s", hostname)
			return
		}
	} else {
		glog.V(6).Info("Parsed request without hostname")

		proxy = s.Default
		if proxy == nil {
			glog.V(4).Info("No default proxy")
			return
		}
	}

	clientConn, err := net.Dial("tcp", fmt.Sprintf(
		"%s:%d", proxy.Host, proxy.Port,
	))
	if err != nil {
		glog.Warningf("Error connecting to backend: %s", err)
		return
	}
	defer clientConn.Close()
	n, err := clientConn.Write(data[:length])
	glog.V(7).Infof("Wrote %d bytes", n)
	if err != nil {
		glog.V(7).Infof("Error sending data to backend: %s", err)
		clientConn.Close()
	}
	Copycat(clientConn, conn)
}

func Copycat(client, server net.Conn) {
	glog.V(6).Info("Entering copy routine")

	doCopy := func(s, c net.Conn, cancel chan<- bool) {
		io.Copy(s, c)
		cancel <- true
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	select {
	case <-cancel:
		glog.V(6).Info("Disconnected")
		return
	}

}

// vim: foldmethod=marker
