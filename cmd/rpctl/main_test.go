package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"rpctl/internal/proxy"
)

func TestPeerAddArguments(t *testing.T) {
	for _, test := range []struct {
		args      []string
		name      string
		lastOctet int
	}{
		{nil, "", 0},
		{[]string{"iphone"}, "iphone", 0},
		{[]string{"iphone", "--ip-last-octet", "25"}, "iphone", 25},
		{[]string{"--ip-last-octet", "25", "iphone"}, "iphone", 25},
		{[]string{"--ip-last-octet=254"}, "", 254},
	} {
		name, lastOctet, err := parsePeerAddArgs(test.args)
		if err != nil || name != test.name || lastOctet != test.lastOctet {
			t.Errorf("args=%q name=%q lastOctet=%d error=%v", test.args, name, lastOctet, err)
		}
	}
	for _, args := range [][]string{
		{"--ip-last-octet"},
		{"--ip-last-octet="},
		{"--ip-last-octet", "0"},
		{"--ip-last-octet", "255"},
		{"--ip-last-octet", "1.5"},
		{"--ip-last-octet", "25", "--ip-last-octet", "26"},
		{"iphone", "another-phone"},
		{"--unknown"},
	} {
		if _, _, err := parsePeerAddArgs(args); err == nil {
			t.Errorf("invalid arguments accepted: %q", args)
		}
	}
}

func TestCommandArgumentValidation(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"proxy", "list", "unexpected"},
		{"proxy", "show"},
		{"proxy", "add", "example.com"},
		{"proxy", "add", "example.com", "--upstream", "http://localhost:80", "extra"},
		{"proxy", "delete"},
		{"system", "reload", "extra"},
		{"wg", "delete"},
		{"unknown"},
	} {
		if err := run(proxy.Store{}, args); err == nil {
			t.Errorf("accepted invalid arguments %q", args)
		}
	}
}

func TestProbeHTTPChallenge(t *testing.T) {
	webroot := t.TempDir()
	server := httptest.NewServer(http.FileServer(http.Dir(webroot)))
	defer server.Close()
	if err := probeHTTPChallenge(server.Client(), webroot, server.URL); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(webroot, ".well-known", "acme-challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("HTTP-01 token was not removed: %v", entries)
	}
}

func TestProbeHTTPChallengeRejectsWrongOrigin(t *testing.T) {
	webroot := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("another server"))
	}))
	defer server.Close()
	if err := probeHTTPChallenge(server.Client(), webroot, server.URL); err == nil {
		t.Fatal("accepted an HTTP-01 response from another server")
	}
}

func TestProbeHTTPChallengeRejectsSymlinkDirectory(t *testing.T) {
	webroot := t.TempDir()
	wellKnown := filepath.Join(webroot, ".well-known")
	if err := os.Mkdir(wellKnown, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(wellKnown, "acme-challenge")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	if err := probeHTTPChallenge(server.Client(), webroot, server.URL); err == nil {
		t.Fatal("accepted a symlink HTTP-01 directory")
	}
}

func TestSplitNetworkAddresses(t *testing.T) {
	addresses := []networkAddress{
		{interfaceName: "lo", ip: net.ParseIP("127.0.0.1"), up: true, loopback: true},
		{interfaceName: "enp1s0", ip: net.ParseIP("203.0.113.10"), up: true},
		{interfaceName: "enp1s0", ip: net.ParseIP("2001:db8::10"), up: true},
		{interfaceName: "wg-home", ip: net.ParseIP("10.77.0.1"), up: true},
		{interfaceName: "tailscale0", ip: net.ParseIP("100.64.0.1"), up: true},
		{interfaceName: "down0", ip: net.ParseIP("192.0.2.10")},
	}
	vpnInterfaces := map[string]struct{}{"wg-home": {}, "tailscale0": {}}
	server, vpn := splitNetworkAddresses(addresses, vpnInterfaces)
	wantServer := []string{"2001:db8::10 (enp1s0)", "203.0.113.10 (enp1s0)"}
	wantVPN := []string{"10.77.0.1 (wg-home)", "100.64.0.1 (tailscale0)"}
	if !reflect.DeepEqual(server, wantServer) {
		t.Fatalf("server addresses = %v, want %v", server, wantServer)
	}
	if !reflect.DeepEqual(vpn, wantVPN) {
		t.Fatalf("VPN addresses = %v, want %v", vpn, wantVPN)
	}
}

func TestVPNInterfaceNames(t *testing.T) {
	for _, name := range []string{"wg0", "wg-home", "tailscale0"} {
		if !isVPNInterfaceName(name) {
			t.Errorf("did not recognize VPN interface %q", name)
		}
	}
	for _, name := range []string{"enp1s0", "lo", "bridge0"} {
		if isVPNInterfaceName(name) {
			t.Errorf("misclassified interface %q", name)
		}
	}
}

func TestReadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("correct horse battery\n"), 0600); err != nil {
		t.Fatal(err)
	}
	password, err := readPasswordFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "correct horse battery" {
		t.Fatal("unexpected password content")
	}
	for index := range password {
		password[index] = 0
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(path); err == nil {
		t.Fatal("accepted password file readable by other users")
	}

	symlink := filepath.Join(dir, "password-link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPasswordFile(symlink); err == nil {
		t.Fatal("accepted symlink password file")
	}
}
