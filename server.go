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
	"github.com/kubermatic/k8sniff/parser"

	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/runtime"
	"k8s.io/client-go/pkg/util/intstr"
	"k8s.io/client-go/pkg/util/wait"
	"k8s.io/client-go/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"strconv"
	"strings"
)

const (
	// ingressClassKey picks a specific "class" for the Ingress. The controller
	// only processes Ingresses with this annotation either unset, or set
	// to either nginxIngressClass or the empty string.
	ingressClassKey = "kubernetes.io/ingress.class"
	proxyClassKey   = "kubernetes.io/k8sniff-tcp-proxy-port"
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

type PortProxy struct {
	Lock    sync.RWMutex
	Ports   map[int]string
	Default *Server
}

func (p *PortProxy) Update(c *Config) {
	ports := make(map[int]string)
	for _, port := range c.Ports {
		ports[port.Port] = port.TargetHost
	}
	p.Lock.Lock()
	defer p.Lock.Unlock()
	p.Ports = ports
}

func (p *PortProxy) Get(port int) string {
	p.Lock.RLock()
	defer p.Lock.RUnlock()

	host, _ := p.Ports[port]
	return host
}

func (p *Proxy) Get(host string) *Server {
	p.Lock.RLock()
	defer p.Lock.RUnlock()

	for _, tuple := range p.ServerList {
		if tuple.Regexp.MatchString(host) {
			return tuple.Server
		}
	}
	return p.Default
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

func (c *Config) UpdatePorts() error {
	services := c.serviceStore.List()
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, service := range services {
		service := service.(*v1.Service)
		if port, found := service.Annotations[proxyClassKey]; found {
			glog.V(4).Infof("Adding port %s to portProxy for service %s/%s", port, service.Namespace, service.Name)
			port, _ := strconv.Atoi(port)
			c.Ports = append(c.Ports, ProxyPort{TargetHost: service.Spec.ClusterIP, Port: port})
		}
	}

	glog.V(2).Infof("Updating portProxy configuration")
	c.portProxy.Update(c)
	glog.V(2).Infof("PortProxy configuration update done")
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
			return nil, err
		}
		if !found {
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
		glog.Errorf("Error updating proxy: %v", err)
		// TODO: add backoff logic
		time.Sleep(time.Second)
	} else {
		glog.V(2).Infof("Proxy configuration update done")
	}

	return nil
}

func (c *Config) GetListener() []net.Listener {
	return nil
}

func (c *Config) Debug() {
	glog.V(2).Info("==============================================================================")
	glog.V(2).Info("")
	glog.V(2).Info("Configured backends:")
	for _, s := range c.proxy.ServerList {
		glog.V(2).Infof("%s -> %s", strings.Join(s.Server.Names, ","), s.Server.Host)
	}
	glog.V(2).Info("")
	glog.V(2).Info("Configured ports:")
	for port, target := range c.portProxy.Ports {
		glog.V(2).Infof(":%d -> %s:%d", port, target, port)
	}
	glog.V(2).Info("")
	glog.V(2).Info("==============================================================================")
}

func (c *Config) UpdateService() {
	c.portProxy.Lock.Lock()
	defer c.portProxy.Lock.Unlock()

	svc, err := c.Kubernetes.Client.Services("k8sniff").Get("k8sniff-ingress-lb")
	if err != nil {
		glog.Errorf("Own service not found.")
		return
	}

	updated := false
	for ppPort := range c.portProxy.Ports {
		existInSvc := false
		for _, sp := range svc.Spec.Ports {
			if sp.Port == int32(ppPort) {
				existInSvc = true
				break
			}
		}
		if !existInSvc {
			np := v1.ServicePort{
				Name:       fmt.Sprintf("tcp-proxy-%d", ppPort),
				Protocol:   v1.ProtocolTCP,
				Port:       int32(ppPort),
				TargetPort: intstr.IntOrString{IntVal: int32(ppPort)},
			}
			svc.Spec.Ports = append(svc.Spec.Ports, np)
			updated = true
			glog.V(2).Infof("Exposing port %d", ppPort)
		}
	}

	if updated {
		_, err = c.Kubernetes.Client.Services("k8sniff").Update(svc)
		if err != nil {
			glog.Errorf("Unable to save service during port update: %v", err)
		} else {
			glog.V(2).Info("Updated own service ports")
		}
	}
}

func (c *Config) Serve() error {
	glog.V(1).Infof("Listening on %s:%d", c.Bind.Host, c.Bind.Port)

	c.proxy = &Proxy{}
	err := c.proxy.Update(c)
	if err != nil {
		return err
	}

	c.portProxy = &PortProxy{}
	c.portProxy.Update(c)

	if c.Kubernetes != nil && c.Kubernetes.Client != nil {
		c.ingressStore, c.ingressController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
					return c.Kubernetes.Client.Extensions().Ingresses(v1.NamespaceAll).List(options)
				},
				WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
					return c.Kubernetes.Client.Extensions().Ingresses(v1.NamespaceAll).Watch(options)
				},
			},
			&v1beta1.Ingress{},
			5*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					i := obj.(*v1beta1.Ingress)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after adding ingress %s: %v", i.Name, err)
					}
				},
				UpdateFunc: func(old, cur interface{}) {
					i := cur.(*v1beta1.Ingress)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after updating ingress %s: %v", i.Name, err)
					}
				},
				DeleteFunc: func(obj interface{}) {
					i := obj.(*v1beta1.Ingress)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after deleting ingress %s: %v", i.Name, err)
					}
				},
			},
		)

		c.serviceStore, c.serviceController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
					return c.Kubernetes.Client.Services(v1.NamespaceAll).List(options)
				},
				WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
					return c.Kubernetes.Client.Services(v1.NamespaceAll).Watch(options)
				},
			},
			&v1.Service{},
			5*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					s := obj.(*v1.Service)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after adding service %s: %v", s.Name, err)
					}
					c.UpdatePorts()
				},
				UpdateFunc: func(old, cur interface{}) {
					s := cur.(*v1.Service)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after updating service %s: %v", s.Namespace, err)
					}
					c.UpdatePorts()
				},
				DeleteFunc: func(obj interface{}) {
					s := obj.(*v1.Service)
					err := c.UpdateServers()
					if err != nil {
						glog.Errorf("failed to update servers list after deleting service %s: %v", s.Name, err)
					}
					c.UpdatePorts()
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

	go wait.Forever(c.Debug, 30*time.Second)
	go wait.Forever(c.UpdateService, 5*time.Second)

	//Port proxy
	r := strings.Split(c.Bind.PortProxyRange, "-")
	min, err := strconv.Atoi(r[0])
	if err != nil {
		return fmt.Errorf("failed to parse port range: %v", err)
	}
	max, err := strconv.Atoi(r[1])
	if err != nil {
		return fmt.Errorf("failed to parse port range: %v", err)
	}

	for i := min; i <= max; i++ {
		listener, err := net.Listen("tcp", fmt.Sprintf(
			"%s:%d", c.Bind.Host, i,
		))
		if err != nil {
			return err
		}
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					glog.Error(err)
					return
				}
				glog.V(3).Infof(
					"%s -> %s",
					conn.RemoteAddr(),
					conn.LocalAddr(),
				)
				go c.portProxy.Handle(conn)
			}
		}()
	}

	// Normal proxy
	listener, err := net.Listen("tcp", fmt.Sprintf(
		"%s:%d", c.Bind.Host, c.Bind.Port,
	))
	if err != nil {
		return err
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
		go c.proxy.Handle(conn)
	}

	return nil
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

func (p *PortProxy) Handle(conn net.Conn) {
	defer conn.Close()

	s := strings.Split(conn.LocalAddr().String(), ":")
	port, _ := strconv.Atoi(s[1])

	if target, found := p.Ports[port]; found {
		glog.V(2).Infof("proxy request to %s:%d", target, port)

		clientConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
		if err != nil {
			glog.Warningf("Error connecting to service: %s", err)
			return
		}
		defer clientConn.Close()
		Copycat(clientConn, conn)

	} else {
		glog.Errorf("no service found for port %d", port)
	}
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
