package webpanel

import (
	"net"
	"net/http"
	"strings"
)

var cloudflareNetworks = parseTrustedNetworks([]string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
})

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(strings.TrimSpace(host))
	if remote == nil {
		return host
	}
	client := remote
	if remote.IsLoopback() {
		if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
			client = forwarded
		}
	}
	if isCloudflareIP(client) {
		if connecting := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); connecting != nil {
			client = connecting
		}
	}
	return client.String()
}

func isCloudflareIP(ip net.IP) bool {
	for _, network := range cloudflareNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedNetworks(values []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic("invalid trusted network: " + value)
		}
		networks = append(networks, network)
	}
	return networks
}
