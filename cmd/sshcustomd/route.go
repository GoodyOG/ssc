package main

import (
	"net"
	"strings"
	"sync"
	"time"
)

// RouteInfo holds network routing information.
type RouteInfo struct {
	Online bool
	Raw    string
	Iface  string
	Gw     string
	Src    string
}

var cachedRoute struct {
	sync.Mutex
	ri      RouteInfo
	expires time.Time
}

// routeInfo discovers the active network route with a 5-second cache.
func routeInfo() RouteInfo {
	cachedRoute.Lock()
	if time.Now().Before(cachedRoute.expires) {
		ri := cachedRoute.ri
		cachedRoute.Unlock()
		return ri
	}
	cachedRoute.Unlock()

	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 1*time.Second)
	if err != nil {
		ri := RouteInfo{Online: false}
		cachedRoute.Lock()
		cachedRoute.ri = ri
		cachedRoute.expires = time.Now().Add(5 * time.Second)
		cachedRoute.Unlock()
		return ri
	}
	defer conn.Close()

	laddr := conn.LocalAddr().String()
	src, _, _ := net.SplitHostPort(laddr)
	iface := ""
	if src != "" {
		ifaces, _ := net.Interfaces()
		for _, ifc := range ifaces {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if strings.HasPrefix(a.String(), src+"/") || strings.HasPrefix(a.String(), src) {
					iface = ifc.Name
					break
				}
			}
			if iface != "" {
				break
			}
		}
	}

	ri := RouteInfo{Online: true, Raw: laddr, Src: src, Iface: iface}
	cachedRoute.Lock()
	cachedRoute.ri = ri
	cachedRoute.expires = time.Now().Add(5 * time.Second)
	cachedRoute.Unlock()
	return ri
}
