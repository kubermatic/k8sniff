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
	"github.com/kubermatic/k8sniff/metrics"
	"github.com/kubermatic/k8sniff/parser"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/util/intstr"
	"k8s.io/client-go/pkg/util/wait"
	"k8s.io/client-go/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// ingressClassKey picks a specific "class" for the Ingress. The controller
	// only processes Ingresses with this annotation either unset, or set
	// to either nginxIngressClass or the empty string.
	ingressClassKey = "kubernetes.io/ingress.class"
)

// now provides func() time.Time
// so it is easier to mock, if wou want to add tests
var now = time.Now

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
	currentServers := c.CurrentServers()
	for i, server := range currentServers {
		for _, hostname := range server.Names {
			var host_regexp *regexp.Regexp
			var err error
			if server.Regexp {
				host_regexp, err = regexp.Compile(hostname)
			} else {
				host_regexp, err = regexp.Compile("^" + regexp.QuoteMeta(hostname) + "$")
			}
			if err != nil {
				metrics.IncErrors(metrics.Error)
				return fmt.Errorf("cannot update proxy due to invalid regex: %v", err)
			}
			tuple := ServerAndRegexp{&currentServers[i], host_regexp}
			servers = append(servers, tuple)
		}
	}
	var def *Server
	for i, server := range currentServers {
		if server.Default {
			def = &currentServers[i]
			break
		}
	}

	p.Lock.Lock()
	defer p.Lock.Unlock()
	p.ServerList = servers
	p.Default = def

	return nil
}

func (c *Config) UpdateServers() error {
	class := c.Kubernetes.IngressClass
	if class == "" {
		class = "k8sniff"
	}

	c.lock.Lock()
	serverForBackend := func(ing *v1beta1.Ingress, backend *v1beta1.IngressBackend) (*Server, error) {
		obj, found, err := c.serviceStore.GetByKey(fmt.Sprintf("%s/%s", ing.Namespace, backend.ServiceName))
		if err != nil {
			metrics.IncErrors(metrics.Error)
			return nil, err
		}
		if !found {
			metrics.IncErrors(metrics.Error)
			return nil, fmt.Errorf("service %s/%s not found", ing.Namespace, backend.ServiceName)
		}
		svc := obj.(*v1.Service)
		var port int
		if backend.ServicePort.Type == intstr.String {
			for _, p := range svc.Spec.Ports {
				if p.Name == backend.ServicePort.StrVal {
					port = int(p.Port)
					break
				}
			}
			if port == 0 {
				metrics.IncErrors(metrics.Error)
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

	c.Servers = []Server{}
	iList := c.ingressStore.List()
	for _, i := range iList {
		i := i.(*v1beta1.Ingress)
		name := fmt.Sprintf("%s/%s", i.Namespace, i.Name)
		if i.Annotations[ingressClassKey] != class {
			glog.Errorf("Skipping ingress %s due to missing annotation. Expected %s=%s Got %s=%s", name, ingressClassKey, class, ingressClassKey, i.Annotations[ingressClassKey])
			continue
		}

		if i.Spec.Backend != nil {
			s, err := serverForBackend(i, i.Spec.Backend)
			if err != nil {
				metrics.IncErrors(metrics.Info)
				glog.Errorf("Ingress %s error with default backend, skipping: %v", name, err)
			} else {
				s.Default = true
				glog.V(4).Infof("Adding default backend -> %s:%d", s.Host, s.Port)
				c.Servers = append(c.Servers, *s)
			}
		}
		for _, r := range i.Spec.Rules {
			if r.HTTP == nil {
				glog.Errorf("Ingress %s error with rule, skipping: http must be set", name)
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Path != "" && p.Path != "/" {
					glog.Errorf("Ingress %s error with rule, skipping: path is not empty", name)
					continue
				}
				s, err := serverForBackend(i, &p.Backend)
				if err != nil {
					metrics.IncErrors(metrics.Info)
					glog.Errorf("Ingress %s error with rule %q path %q, skipping: %v", name, r.Host, p.Path, err)
					continue
				}
				s.Names = []string{r.Host}
				glog.V(4).Infof("Adding backend %q -> %s:%d", r.Host, s.Host, s.Port)
				c.Servers = append(c.Servers, *s)
			}
		}
	}
	c.lock.Unlock()

	glog.V(2).Infof("Updating proxy configuration")
	err := c.proxy.Update(c)
	if err != nil {
		metrics.IncErrors(metrics.Info)
		glog.Errorf("Error updating proxy: %v", err)
		// TODO: add backoff logic
		time.Sleep(time.Second)
	} else {
		glog.V(2).Infof("Proxy configuration update done")
	}

	return nil
}

// gets a point in time copy for reading to prevent race conditions when reading and updating server list
func (c *Config) CurrentServers() []Server {
	c.lock.Lock()
	defer c.lock.Unlock()

	copyOfServers := make([]Server, len(c.Servers))
	for i := range c.Servers {
		copyOfServers[i] = c.Servers[i]
	}

	return copyOfServers
}

func (c *Config) Serve() error {
	glog.V(1).Infof("Listening on %s:%d", c.Bind.Host, c.Bind.Port)
	listener, err := net.Listen("tcp", fmt.Sprintf(
		"%s:%d", c.Bind.Host, c.Bind.Port,
	))
	if err != nil {
		metrics.IncErrors(metrics.Error)
		return err
	}

	c.proxy = &Proxy{}
	err = c.proxy.Update(c)
	if err != nil {
		metrics.IncErrors(metrics.Error)
		return err
	}

	if c.Kubernetes != nil {
		var rcfg *rest.Config
		var err error
		if c.Kubernetes.Kubeconfig != "" {
			// uses the current context in kubeconfig
			rcfg, err = clientcmd.BuildConfigFromFlags("", c.Kubernetes.Kubeconfig)
			if err != nil {
				metrics.IncErrors(metrics.Fatal)
				panic(err.Error())
			}
		} else {
			// creates the in-cluster config
			rcfg, err = rest.InClusterConfig()
			if err != nil {
				metrics.IncErrors(metrics.Fatal)
				panic(err.Error())
			}
		}

		client := kubernetes.NewForConfigOrDie(rcfg)

		c.ingressStore, c.ingressController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
					return client.Extensions().Ingresses(v1.NamespaceAll).List(options)
				},
				WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
					return client.Extensions().Ingresses(v1.NamespaceAll).Watch(options)
				},
			},
			&v1beta1.Ingress{},
			5*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					i := obj.(*v1beta1.Ingress)
					glog.V(4).Infof("Adding ingress %s/%s", i.Namespace, i.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after adding ingress %s: %v", i.Name, err)
					}
				},
				UpdateFunc: func(old, cur interface{}) {
					i := cur.(*v1beta1.Ingress)
					glog.V(4).Infof("Updating ingress %s/%s", i.Namespace, i.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after updating ingress %s: %v", i.Name, err)
					}
				},
				DeleteFunc: func(obj interface{}) {
					i := obj.(*v1beta1.Ingress)
					glog.V(4).Infof("Deleting ingress %s/%s", i.Namespace, i.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after deleting ingress %s: %v", i.Name, err)
					}
				},
			},
		)

		c.serviceStore, c.serviceController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
					return client.Services(v1.NamespaceAll).List(options)
				},
				WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
					return client.Services(v1.NamespaceAll).Watch(options)
				},
			},
			&v1.Service{},
			5*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					s := obj.(*v1.Service)
					glog.V(4).Infof("Adding service %q", s.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after adding service %s: %v", s.Name, err)
					}
				},
				UpdateFunc: func(old, cur interface{}) {
					s := cur.(*v1.Service)
					glog.V(4).Infof("Updating service %q", s.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after updating service %s: %v", s.Namespace, err)
					}
				},
				DeleteFunc: func(obj interface{}) {
					s := obj.(*v1.Service)
					glog.V(4).Infof("Deleting service %q", s.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Info)
						glog.Errorf("failed to update servers list after deleting service %s: %v", s.Name, err)
					}
				},
			},
		)

		// wait until services are ready
		glog.V(1).Infof("Waiting for service store to be ready")
		go c.serviceController.Run(wait.NeverStop)
		for {
			if c.serviceController.HasSynced() {
				break
			}
			time.Sleep(time.Millisecond * 200)
		}

		go c.ingressController.Run(wait.NeverStop)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			metrics.IncErrors(metrics.Error)
			return err
		}
		start := now()
		metrics.IncConnections()
		glog.V(3).Infof(
			"%s -> %s",
			conn.RemoteAddr(),
			conn.LocalAddr(),
		)
		go c.proxy.Handle(conn, start)
	}
}

func (s *Proxy) Handle(conn net.Conn, start time.Time) {
	defer func(s time.Time) {
		conn.Close()
		metrics.ConnectionTime(now().Sub(s))
	}(start)
	data := make([]byte, 4096)

	length, err := conn.Read(data)
	if err != nil {
		metrics.IncErrors(metrics.Error)
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
		} else {
			glog.V(4).Infof("Host found %s", proxy.Host)
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
		metrics.IncErrors(metrics.Error)
		glog.Warningf("Error connecting to backend: %s", err)
		return
	}
	defer clientConn.Close()
	n, err := clientConn.Write(data[:length])
	glog.V(7).Infof("Wrote %d bytes", n)
	if err != nil {
		metrics.IncErrors(metrics.Info)
		glog.V(7).Infof("Error sending data to backend: %s", err)
		clientConn.Close()
		return
	}
	Copycat(clientConn, conn)
}

func Copycat(client, server net.Conn) {
	glog.V(6).Info("Entering copy routine")

	doCopy := func(s, c net.Conn, cancel chan<- bool) {
		if _, err := io.Copy(s, c); err != nil {
			metrics.IncErrors(metrics.Info)
		}
		cancel <- true
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	select {
	case <-cancel:
		glog.V(6).Info("Disconnected")
	}
}
