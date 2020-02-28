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
	"github.com/platform9/cnxmd/pkg/cnxmd"
	"io"
	"math/rand"
	"net"
	"reflect"
	"regexp"
	"strings"
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
)

const (
	// ingressClassKey picks a specific "class" for the Ingress. The controller
	// only processes Ingresses with this annotation either unset, or set
	// to either nginxIngressClass or the empty string.
	ingressClassKey = "kubernetes.io/ingress.class"

	ConnectionClosedErr      = "use of closed network connection"
	ConnectionResetErr       = "connection reset by peer"
	MaxTeardownTimeInSeconds = 35
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

func (c *Config) UpdateServers(reason string) error {
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

	var servers []Server
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
				glog.V(0).Infof("Ingress %s error with default backend, skipping: %v", name, err)
			} else {
				s.Default = true
				s.IngressName = name
				servers = append(servers, *s)
			}
		}
		for _, r := range i.Spec.Rules {
			if r.HTTP == nil {
				metrics.IncErrors(metrics.Error)
				glog.V(0).Infof("Ingress %s error with rule, skipping: http must be set", name)
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Path != "" && p.Path != "/" {
					metrics.IncErrors(metrics.Error)
					glog.V(0).Infof("Ingress %s error with rule, skipping: path is not empty", name)
					continue
				}
				s, err := serverForBackend(i, &p.Backend)
				if err != nil {
					metrics.IncErrors(metrics.Error)
					glog.V(0).Infof("Ingress %s error with rule %q path %q, skipping: %v", name, r.Host, p.Path, err)
					continue
				}
				s.Names = []string{r.Host}
				s.IngressName = name
				glog.V(6).Infof("Adding backend %q -> %s:%d", r.Host, s.Host, s.Port)
				servers = append(servers, *s)
			}
		}
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if !reflect.DeepEqual(c.Servers, servers) {
		c.Servers = servers
		glog.V(2).Infof("Updating proxy configuration")
		err := c.proxy.Update(c)
		if err != nil {
			time.Sleep(time.Second)
			return fmt.Errorf("failed to update proxy: %v", err)
		}
		if glog.V(4) {
			glog.V(2).Infof("================================================")
			glog.V(2).Infof("Updated servers. New servers:")
			c.PrintCurrentServers(2)
			glog.V(2).Infof("================================================")
		} else {
			glog.V(3).Infof("Updated servers because '%s'. There are now %d servers",
				reason, len(c.Servers))
		}
	}

	metrics.SetBackendCount(len(c.Servers) - 1)

	return nil
}

func (c *Config) PrintCurrentServers(logLevel glog.Level) {
	for _, s := range c.Servers {
		hostnames := strings.Join(s.Names, ",")
		if hostnames == "" {
			hostnames = "default backend"
		}
		glog.V(logLevel).Infof("%s -> %s (%s)", hostnames, s.Host, s.IngressName)
	}
}

func (c *Config) Debug() {
	glog.V(4).Info("================================================")
	glog.V(4).Info("Current configured servers:")
	c.PrintCurrentServers(4)
	glog.V(4).Info("================================================")
}

func (c *Config) TriggerUpdate(reason string) {
	if !c.ControllersHaveSynced() {
		return
	}
	err := c.UpdateServers(reason)
	if err != nil {
		metrics.IncErrors(metrics.Info)
		glog.V(0).Infof("failed to update servers list: %v", err)
	}
}

func (c *Config) ControllersHaveSynced() bool {
	return c.ingressController.HasSynced() && c.serviceController.HasSynced()
}

func (c *Config) Serve(stopCh chan struct{}) error {
	glog.V(0).Infof("Listening on %s:%d", c.Bind.Host, c.Bind.Port)
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
		cfg, err := clientcmd.BuildConfigFromFlags("", c.Kubernetes.Kubeconfig)
		if err != nil {
			panic(err)
		}
		c.Kubernetes.Client = kubernetes.NewForConfigOrDie(cfg)
		c.ingressStore, c.ingressController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return c.Kubernetes.Client.ExtensionsV1beta1().Ingresses("").List(options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return c.Kubernetes.Client.ExtensionsV1beta1().Ingresses("").Watch(options)
				},
			},
			&v1beta1.Ingress{},
			30*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					ing := obj.(*v1beta1.Ingress)
					msg := fmt.Sprintf("ingress added: %s/%s", ing.Namespace, ing.Name)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
				UpdateFunc: func(old, cur interface{}) {
					oldIng := old.(*v1beta1.Ingress)
					ing := cur.(*v1beta1.Ingress)
					if reflect.DeepEqual(oldIng, ing) {
						glog.V(3).Infof("ignoring spurious update for ingress %s/%s",
							ing.Namespace, ing.Name)
						return
					}
					msg := fmt.Sprintf("ingress updated: %s/%s old: %+v new: %+v",
						ing.Namespace, ing.Name, oldIng, ing)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
				DeleteFunc: func(obj interface{}) {
					ing := obj.(*v1beta1.Ingress)
					msg := fmt.Sprintf("ingress deleted: %s/%s", ing.Namespace, ing.Name)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
			},
		)

		c.serviceStore, c.serviceController = cache.NewInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return c.Kubernetes.Client.Services("").List(options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					return c.Kubernetes.Client.Services("").Watch(options)
				},
			},
			&v1.Service{},
			30*time.Minute,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					svc := obj.(*v1.Service)
					msg := fmt.Sprintf("service added: %s/%s", svc.Namespace, svc.Name)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
				UpdateFunc: func(old, cur interface{}) {
					oldSvc := old.(*v1.Service)
					svc := cur.(*v1.Service)
					if reflect.DeepEqual(oldSvc, svc) {
						glog.V(3).Infof("ignoring spurious update for service %s/%s",
							svc.Namespace, svc.Name)
						return
					}
					msg := fmt.Sprintf("service updated: %s/%s old: %+v new: %+v",
						svc.Namespace, svc.Name, oldSvc, svc)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
				DeleteFunc: func(obj interface{}) {
					svc := obj.(*v1.Service)
					msg := fmt.Sprintf("service deleted: %s/%s", svc.Namespace, svc.Name)
					glog.V(3).Infof(msg)
					go c.TriggerUpdate(msg)
				},
			},
		)

		go c.serviceController.Run(stopCh)
		go c.ingressController.Run(stopCh)
	}
	c.TriggerUpdate("init")

	go wait.Forever(func() {
		c.Debug()
	}, 30*time.Second)

	for {
		cnx, err := listener.Accept()
		if err != nil {
			metrics.IncErrors(metrics.Error)
			return err
		}
		conn := cnx.(*net.TCPConn)
		connectionID := RandomString(8)
		glog.V(3).Infof(
			"[%s] Accepted connection - remoteaddr:%s localaddr:%s",
			connectionID,
			conn.RemoteAddr(),
			conn.LocalAddr(),
		)
		go c.proxy.Handle(conn, connectionID)
	}
}

func (p *Proxy) Handle(conn *net.TCPConn, connectionID string) {
	metrics.IncConnections()
	start := now()
	defer func(s time.Time) {
		err := conn.Close()
		if err != nil {
			glog.V(0).Infof("[%s] Failed closing connection: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		} else {
			glog.V(3).Infof("[%s] Closed connection", connectionID)
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
	var hostname string
	hostnameType := "SNI"
	headerBytes, kv, err := cnxmd.Parse(data[:length])
	if err == nil {
		hostnameType = "CNXMD"
		glog.V(4).Infof("[%s] found CNXMD header of %d bytes", connectionID, headerBytes)
		hostname = kv["host"]
		if hostname == "" {
			metrics.IncErrors(metrics.Error)
			glog.V(3).Infof("[%s] CNXMD header contains no host key", connectionID)
			return
		}
		glog.V(4).Infof("[%s] CNXMD hostname: %s", connectionID, hostname)
		proxy = p.Get(hostname)
	} else {
		headerBytes = 0
		var hostnameErr error
		hostname, hostnameErr = parser.GetHostname(data[:])
		if hostnameErr == nil {
			glog.V(6).Infof("[%s] Parsed hostname: %s", connectionID, hostname)
			proxy = p.Get(hostname)
		} else {
			glog.V(3).Infof("[%s] No hostname found, attempting default proxy", connectionID)

			proxy = p.Default
			if proxy == nil {
				glog.V(3).Info("[%s] No default proxy", connectionID)
				return
			}
		}
	}
	if proxy == nil {
		glog.V(4).Infof("[%s] No proxy matched %s", connectionID, hostname)
		return
	} else {
		glog.V(3).Infof("[%s] %s hostname %s maps to %s",
			connectionID, hostnameType, hostname, proxy.Host)
	}
	data = data[headerBytes:length]
	proxyBackend := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	clientCnx, err := net.Dial("tcp", proxyBackend)
	if err != nil {
		metrics.IncErrors(metrics.Error)
		glog.V(0).Infof("[%s] Error connecting to backend: %v", connectionID, err)
		return
	}
	clientConn := clientCnx.(*net.TCPConn)
	proxyIngressBackend := fmt.Sprintf("%s:%d", proxy.IngressName, proxy.Port)
	metrics.IncBackendConnections(proxyIngressBackend)

	defer func() {
		err := clientConn.Close()
		if err != nil {
			glog.V(0).Infof("[%s] Failed closing client connection: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		}
		metrics.DecBackendConnections(proxyIngressBackend)
	}()

	n, err := clientConn.Write(data)
	glog.V(7).Infof("[%s] Wrote %d bytes", connectionID, n)
	if err != nil {
		metrics.IncErrors(metrics.Info)
		glog.V(7).Infof("[%s] Error sending data to backend: %v", connectionID, err)
		return
	}
	metrics.AddBackendBytesSent(proxyIngressBackend, int64(n))
	Copycat(clientConn, conn, connectionID, proxyIngressBackend)
}

func Copycat(client *net.TCPConn, server *net.TCPConn, connectionID string, backend string) {
	glog.V(6).Infof("[%s] Initiating copy between %s and %s", connectionID, client.RemoteAddr().String(), server.RemoteAddr().String())

	doCopy := func(s, c *net.TCPConn, cancel chan<- string, bytesProcessedCtrCallback func(string, int64)) {
		glog.V(7).Infof("[%s] Established connection %s -> %s", connectionID, c.RemoteAddr().String(), s.RemoteAddr().String())
		numWritten, err := io.Copy(s, c)
		reason := "EOF"
		if err != nil {
			reason = err.Error()
		}
		glog.V(3).Infof("[%s] Copied %d bytes from %s to %s, finished because: %s",
			connectionID, numWritten, c.RemoteAddr().String(), s.RemoteAddr().String(),
			reason)
		if err != nil && !strings.Contains(err.Error(), ConnectionClosedErr) && !strings.Contains(err.Error(), ConnectionResetErr) {
			glog.V(0).Infof("[%s] Failed copying connection data: %v", connectionID, err)
			metrics.IncErrors(metrics.Error)
		}
		glog.V(4).Infof("[%s] Copy finished for %s -> %s", connectionID, c.RemoteAddr().String(), s.RemoteAddr().String())
		s.CloseWrite() // propagate EOF signal to destination
		cancel <- c.RemoteAddr().String()
		bytesProcessedCtrCallback(backend, numWritten)
		metrics.BytesCopied(numWritten)
	}

	cancel := make(chan string, 2)

	go doCopy(server, client, cancel, metrics.AddBackendBytesRcvd)
	go doCopy(client, server, cancel, metrics.AddBackendBytesSent)

	closedSrc := <-cancel
	glog.V(3).Infof("[%s] 1st source to close: %s", connectionID, closedSrc)
	start := time.Now()
	timer := time.NewTimer(MaxTeardownTimeInSeconds * time.Second)
	select {
	case closedSrc = <-cancel:
		glog.V(3).Infof("[%s] 2nd source to close: %s (all done)", connectionID, closedSrc)
		timer.Stop()
	case <-timer.C:
		glog.V(3).Infof("[%s] timed out waiting for 2nd source to close", connectionID)
		metrics.TeardownTimeout()
	}
	elapsed := time.Now().Sub(start)
	metrics.TeardownTime(elapsed)
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
