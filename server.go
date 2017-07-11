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

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"math/rand"
	"strings"
)

const (
	// ingressClassKey picks a specific "class" for the Ingress. The controller
	// only processes Ingresses with this annotation either unset, or set
	// to either nginxIngressClass or the empty string.
	ingressClassKey = "kubernetes.io/ingress.class"

	ConnectionClosedErr = "use of closed network connection"
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
	currentServers := c.Servers
	for i, server := range currentServers {
		for _, hostname := range server.Names {
			var hostRegexp *regexp.Regexp
			var err error
			if server.Regexp {
				hostRegexp, err = regexp.Compile(hostname)
			} else {
				hostRegexp, err = regexp.Compile("^" + regexp.QuoteMeta(hostname) + "$")
			}
			if err != nil {
				return fmt.Errorf("cannot update proxy due to invalid regex: %v", err)
			}
			tuple := ServerAndRegexp{&currentServers[i], hostRegexp}
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
				return nil, fmt.Errorf("port %s of service %s/%s not found", backend.ServicePort.StrVal, svc.Namespace, svc.Name)
			}
		} else {
			port = int(backend.ServicePort.IntVal)
		}
		return &Server{
			Host: svc.Spec.ClusterIP,
			Port: port,
		}, nil
	}

	servers := []Server{}
	ingressList := c.ingressStore.List()
	for _, i := range ingressList {
		i := i.(*v1beta1.Ingress)
		name := fmt.Sprintf("%s/%s", i.Namespace, i.Name)
		if i.Annotations[ingressClassKey] != class {
			glog.V(6).Infof("Skipping ingress %s due to missing annotation. Expected %s=%s Got %s=%s", name, ingressClassKey, class, ingressClassKey, i.Annotations[ingressClassKey])
			continue
		}

		if i.Spec.Backend != nil {
			s, err := serverForBackend(i, i.Spec.Backend)
			if err != nil {
				metrics.IncErrors(metrics.Error)
				glog.Errorf("Ingress %s error with default backend, skipping: %v", name, err)
			} else {
				s.Default = true
				glog.V(4).Infof("Adding default backend -> %s:%d", s.Host, s.Port)
				servers = append(servers, *s)
			}
		}
		for _, r := range i.Spec.Rules {
			if r.HTTP == nil {
				metrics.IncErrors(metrics.Error)
				glog.Errorf("Ingress %s error with rule, skipping: http must be set", name)
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Path != "" && p.Path != "/" {
					metrics.IncErrors(metrics.Error)
					glog.Errorf("Ingress %s error with rule, skipping: path is not empty", name)
					continue
				}
				s, err := serverForBackend(i, &p.Backend)
				if err != nil {
					metrics.IncErrors(metrics.Error)
					glog.Errorf("Ingress %s error with rule %q path %q, skipping: %v", name, r.Host, p.Path, err)
					continue
				}
				s.Names = []string{r.Host}
				glog.V(4).Infof("Adding backend %q -> %s:%d", r.Host, s.Host, s.Port)
				servers = append(servers, *s)
			}
		}
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Servers = servers

	glog.V(2).Infof("Updating proxy configuration")
	err := c.proxy.Update(c)
	if err != nil {
		time.Sleep(time.Second)
		return fmt.Errorf("failed to update proxy: %v", err)
	}

	glog.V(2).Infof("Proxy configuration update done")
	return nil
}

func (c *Config) Serve() error {
	glog.V(1).Infof("Listening on %s:%d", c.Bind.Host, c.Bind.Port)
	listener, err := net.Listen("tcp", fmt.Sprintf(
		"%s:%d", c.Bind.Host, c.Bind.Port,
	))
	if err != nil {
		metrics.IncErrors(metrics.Fatal)
		return err
	}

	c.proxy = &Proxy{}
	err = c.proxy.Update(c)
	if err != nil {
		metrics.IncErrors(metrics.Fatal)
		return err
	}

	if c.Kubernetes != nil {
		rcfg, err := clientcmd.BuildConfigFromFlags("", c.Kubernetes.Kubeconfig)
		if err != nil {
			metrics.IncErrors(metrics.Fatal)
			return err
		}

		client := kubernetes.NewForConfigOrDie(rcfg)

		c.ingressStore, c.ingressController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return client.ExtensionsV1beta1().Ingresses(metav1.NamespaceAll).List(options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return client.ExtensionsV1beta1().Ingresses(metav1.NamespaceAll).Watch(options)
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
						metrics.IncErrors(metrics.Error)
						glog.Errorf("failed to update servers list after adding ingress %s: %v", i.Name, err)
					}
				},
				UpdateFunc: func(old, cur interface{}) {
					i := cur.(*v1beta1.Ingress)
					glog.V(4).Infof("Updating ingress %s/%s", i.Namespace, i.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Error)
						glog.Errorf("failed to update servers list after updating ingress %s: %v", i.Name, err)
					}
				},
				DeleteFunc: func(obj interface{}) {
					i := obj.(*v1beta1.Ingress)
					glog.V(4).Infof("Deleting ingress %s/%s", i.Namespace, i.Name)
					err := c.UpdateServers()
					if err != nil {
						metrics.IncErrors(metrics.Error)
						glog.Errorf("failed to update servers list after deleting ingress %s: %v", i.Name, err)
					}
				},
			},
		)

		c.serviceStore, c.serviceController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return client.Services(metav1.NamespaceAll).List(options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return client.Services(metav1.NamespaceAll).Watch(options)
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

		connectionID := RandomString(8)
		glog.V(4).Infof(
			"[%s] Proxy: %s -> %s",
			connectionID,
			conn.RemoteAddr(),
			conn.LocalAddr(),
		)
		go c.proxy.Handle(conn, connectionID)
	}
}

func (p *Proxy) Handle(conn net.Conn, connectionID string) {
	metrics.IncConnections()
	start := now()
	defer func(s time.Time) {
		err := conn.Close()
		if err != nil {
			glog.Errorf("[%s] Failed closing connection: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		}
		metrics.DecConnections()
		metrics.ConnectionTime(now().Sub(s))
	}(start)
	data := make([]byte, 4096)

	length, err := conn.Read(data)
	if err != nil {
		metrics.IncErrors(metrics.Error)
		glog.V(4).Infof("[%s] Error reading the first 4k of the connection: %v", connectionID, err)
		return
	}

	var proxy *Server
	hostname, hostnameErr := parser.GetHostname(data[:])
	if hostnameErr == nil {
		glog.V(6).Infof("[%s] Parsed hostname: %s", connectionID, hostname)

		proxy = p.Get(hostname)
		if proxy == nil {
			glog.V(4).Infof("[%s] No proxy matched %s", connectionID, hostname)
			return
		} else {
			glog.V(4).Infof("[%s] Host found %s", connectionID, proxy.Host)
		}
	} else {
		glog.V(6).Info("[%s] Parsed request without hostname", connectionID)

		proxy = p.Default
		if proxy == nil {
			glog.V(4).Info("[%s] No default proxy", connectionID)
			return
		}
	}

	clientConn, err := net.Dial("tcp", fmt.Sprintf(
		"%s:%d", proxy.Host, proxy.Port,
	))
	if err != nil {
		metrics.IncErrors(metrics.Error)
		glog.Errorf("[%s] Error connecting to backend: %v", connectionID, err)
		return
	}

	defer func() {
		err := clientConn.Close()
		if err != nil {
			glog.Errorf("[%s] Failed closing client connection: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		}
	}()

	n, err := clientConn.Write(data[:length])
	glog.V(7).Infof("[%s] Wrote %d bytes", connectionID, n)
	if err != nil {
		metrics.IncErrors(metrics.Info)
		glog.V(7).Infof("[%s] Error sending data to backend: %v", connectionID, err)
		return
	}
	Copycat(clientConn, conn, connectionID)
}

func Copycat(client, server net.Conn, connectionID string) {
	glog.V(6).Infof("[%s] Initiating copy between %s and %s", connectionID, client.RemoteAddr().String(), server.RemoteAddr().String())

	doCopy := func(s, c net.Conn, cancel chan<- bool) {
		glog.V(7).Infof("[%s] Established connection %s -> %s", connectionID, s.RemoteAddr().String(), c.RemoteAddr().String())
		_, err := io.Copy(s, c)
		if err != nil && !strings.Contains(err.Error(), ConnectionClosedErr) {
			glog.Errorf("[%s] Failed copying connection data: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		}
		glog.V(7).Infof("[%s] Destroyed connection %s -> %s", connectionID, s.RemoteAddr().String(), c.RemoteAddr().String())
		cancel <- true
	}

	cancel := make(chan bool, 2)

	go doCopy(server, client, cancel)
	go doCopy(client, server, cancel)

	select {
	case <-cancel:
		glog.V(6).Infof("[%s] Disconnected", connectionID)
		return
	}
}

func RandomString(strlen int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}
