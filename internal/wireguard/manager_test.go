package wireguard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeRunner struct {
	privateKey string
	publicKeys map[string]string
	psk        string
	failSync   bool
}

func (r *fakeRunner) Run(input []byte, name string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "genkey" {
		return []byte(r.privateKey + "\n"), nil
	}
	if len(args) == 1 && args[0] == "genpsk" {
		return []byte(r.psk + "\n"), nil
	}
	if len(args) == 1 && args[0] == "pubkey" {
		public := r.publicKeys[strings.TrimSpace(string(input))]
		if public == "" {
			return nil, errors.New("unknown private key")
		}
		return []byte(public + "\n"), nil
	}
	if len(args) == 2 && args[0] == "strip" {
		return os.ReadFile(args[1])
	}
	if len(args) == 3 && args[0] == "syncconf" {
		if r.failSync {
			return []byte("sync failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

func testKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func testManager(t *testing.T) (Manager, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	configDir := filepath.Join(dir, "wireguard")
	peerDir := filepath.Join(dir, "peers")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(peerDir, 0700); err != nil {
		t.Fatal(err)
	}
	serverPrivate := testKey(10)
	client1Private := testKey(1)
	generatedPrivate := testKey(2)
	server := "[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51820\nPrivateKey = " + serverPrivate + "\n\n[Peer]\n# client1\nPublicKey = " + testKey(21) + "\nPresharedKey = " + testKey(31) + "\nAllowedIPs = 10.77.0.2/32\n"
	client1 := "[Interface]\nAddress = 10.77.0.2/32\nPrivateKey = " + client1Private + "\n\n[Peer]\nPublicKey = " + testKey(20) + "\nPresharedKey = " + testKey(31) + "\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 10.77.0.0/24\nPersistentKeepalive = 25\n"
	configPath := filepath.Join(configDir, "wg0.conf")
	if err := os.WriteFile(configPath, []byte(server), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(peerDir, "client1.conf"), []byte(client1), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{
		privateKey: generatedPrivate,
		publicKeys: map[string]string{
			serverPrivate:    testKey(20),
			client1Private:   testKey(21),
			generatedPrivate: testKey(22),
		},
		psk: testKey(32),
	}
	manager := Manager{
		ConfigPath: configPath,
		PeerDir:    peerDir,
		ValuesPath: filepath.Join(dir, "peer-defaults.json"),
		LockPath:   filepath.Join(dir, "operation.lock"),
		Interface:  "wg0",
		WGPath:     "wg",
		WGQuick:    "wg-quick",
		Runner:     runner,
	}
	return manager, runner
}

func TestAddWithLastOctet(t *testing.T) {
	manager, _ := testManager(t)
	peer, err := manager.AddWithLastOctet("iphone", 25)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != "iphone" || peer.Address != "10.77.0.25/32" {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	client, err := manager.Config("iphone")
	if err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(client, []byte("Address = 10.77.0.25/32")) || !bytes.Contains(server, []byte("AllowedIPs = 10.77.0.25/32")) {
		t.Fatal("the selected address was not written to both configurations")
	}
	if _, err := manager.AddWithLastOctet("another-phone", 25); err == nil {
		t.Fatal("a duplicate address was accepted")
	}
}

func TestAddWithLastOctetRejectsUnavailableAddressWithoutChanges(t *testing.T) {
	for _, lastOctet := range []int{-1, 1, 2, 255, 256} {
		t.Run(strconv.Itoa(lastOctet), func(t *testing.T) {
			manager, _ := testManager(t)
			before, err := os.ReadFile(manager.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.AddWithLastOctet("iphone", lastOctet); err == nil {
				t.Fatal("an invalid or occupied address was accepted")
			}
			after, err := os.ReadFile(manager.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("rejected allocation changed the server configuration")
			}
			if _, err := os.Stat(filepath.Join(manager.PeerDir, "iphone.conf")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected allocation created a peer configuration: %v", err)
			}
		})
	}
}

func TestPeerAllocationReservesAllowedIPRanges(t *testing.T) {
	manager, _ := testManager(t)
	before, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	before = append(before, []byte("\n[Peer]\nPublicKey = "+testKey(23)+"\nAllowedIPs = 10.77.0.0/29, 192.168.150.0/24, 10.77.0.4/30\n")...)
	if err := os.WriteFile(manager.ConfigPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddWithLastOctet("iphone", 5); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("an address inside an existing peer range was accepted: %v", err)
	}
	after, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected allocation changed the server configuration")
	}
	peer, err := manager.Add("iphone")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Address != "10.77.0.8/32" {
		t.Fatalf("automatic allocation did not skip the reserved range: %+v", peer)
	}
}

func TestPeerAllocationReservesAdditionalServerAddresses(t *testing.T) {
	manager, _ := testManager(t)
	config, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.Replace(config, []byte("Address = 10.77.0.1/24"), []byte("Address = 10.77.0.1/24, 10.77.0.3/32"), 1)
	if err := os.WriteFile(manager.ConfigPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddWithLastOctet("iphone", 3); err == nil {
		t.Fatal("an additional server address was accepted")
	}
	peer, err := manager.Add("iphone")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Address != "10.77.0.4/32" {
		t.Fatalf("automatic allocation did not skip the server address: %+v", peer)
	}
}

func TestUsedAddressesBoundsLargeAllowedIPRanges(t *testing.T) {
	server, network, err := net.ParseCIDR("10.79.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	used, err := usedAddresses([]byte("[Peer]\nAllowedIPs = 0.0.0.0/0, 10.0.0.0/8\n"), nil, network)
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 65536 {
		t.Fatalf("reservation was not limited to the allocation subnet: %d addresses", len(used))
	}
	if _, err := nextAddress(network, server, used); err == nil {
		t.Fatal("an address was allocated inside a fully reserved subnet")
	}
}

func TestConcurrentManualPeerAllocation(t *testing.T) {
	manager, _ := testManager(t)
	results := make(chan error, 2)
	for _, name := range []string{"iphone", "android"} {
		go func() {
			_, err := manager.AddWithLastOctet(name, 25)
			results <- err
		}()
	}
	successful := 0
	for range 2 {
		if err := <-results; err == nil {
			successful++
		} else if !strings.Contains(err.Error(), "already in use") {
			t.Fatalf("unexpected allocation error: %v", err)
		}
	}
	if successful != 1 {
		t.Fatalf("the same address was allocated %d times", successful)
	}
}

func TestAddressWithLastOctetUsesActualSubnet(t *testing.T) {
	for _, test := range []struct {
		server    string
		lastOctet int
		want      string
	}{
		{"192.168.150.1/24", 254, "192.168.150.254"},
		{"10.79.3.1/16", 25, "10.79.3.25"},
		{"10.79.0.100/24", 1, "10.79.0.1"},
		{"10.79.0.5/30", 6, "10.79.0.6"},
		{"10.79.0.5/30", 4, ""},
		{"10.79.0.5/30", 7, ""},
		{"10.79.0.5/30", 25, ""},
		{"10.79.0.5/30", 5, ""},
	} {
		t.Run(test.server+"/"+strconv.Itoa(test.lastOctet), func(t *testing.T) {
			server, network, err := net.ParseCIDR(test.server)
			if err != nil {
				t.Fatal(err)
			}
			address, err := addressWithLastOctet(network, server, map[uint32]struct{}{}, test.lastOctet)
			if test.want == "" {
				if err == nil {
					t.Fatal("a reserved or out-of-subnet address was accepted")
				}
			} else if err != nil || address.String() != test.want {
				t.Fatalf("address=%v error=%v; want %s", address, err, test.want)
			}
		})
	}
}

func TestAddListConfigAndDeletePeer(t *testing.T) {
	manager, _ := testManager(t)
	peer, err := manager.Add("")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != "client2" || peer.Address != "10.77.0.3/32" || peer.PublicKey != testKey(22) {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	info, err := os.Stat(peer.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("client config mode = %o", info.Mode().Perm())
	}
	config, err := manager.Config("client2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("Address = 10.77.0.3/32")) || !bytes.Contains(config, []byte("Endpoint = 203.0.113.10:51820")) {
		t.Fatalf("unexpected client config:\n%s", config)
	}
	peers, err := manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].Name != "client1" || peers[1].Name != "client2" {
		t.Fatalf("unexpected peer list: %+v", peers)
	}
	server, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(server, []byte("# rpctl-peer: client2")) || !bytes.Contains(server, []byte("AllowedIPs = 10.77.0.3/32")) {
		t.Fatalf("server config is missing client2:\n%s", server)
	}
	if err := manager.Delete("client2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(peer.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted client config still exists: %v", err)
	}
	server, err = os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(server, []byte(testKey(22))) {
		t.Fatal("deleted public key remains in server config")
	}
}

func TestListWaitsForPeerMutation(t *testing.T) {
	manager, _ := testManager(t)
	unlock, err := manager.lock(syscall.LOCK_EX)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.List()
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("peer list did not wait for mutation lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer list remained blocked after mutation completed")
	}
}

func TestAddRollsBackWhenLiveSyncFails(t *testing.T) {
	manager, runner := testManager(t)
	original, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	runner.failSync = true
	if _, err := manager.Add("client2"); err == nil {
		t.Fatal("add succeeded when live sync failed")
	}
	current, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, original) {
		t.Fatal("server configuration was not restored")
	}
	if _, err := os.Stat(filepath.Join(manager.PeerDir, "client2.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("client config was not removed: %v", err)
	}
}

func TestDeleteLastPeerPreservesDefaultsForFutureAdd(t *testing.T) {
	manager, _ := testManager(t)
	if err := manager.Delete("client1"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(manager.ValuesPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("defaults mode = %o", info.Mode().Perm())
	}
	peer, err := manager.Add("")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Name != "client1" || peer.Address != "10.77.0.2/32" {
		t.Fatalf("unexpected replacement peer: %+v", peer)
	}
	config, err := manager.Config("client1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("Endpoint = 203.0.113.10:51820")) || !bytes.Contains(config, []byte("AllowedIPs = 10.77.0.0/24")) {
		t.Fatalf("replacement config lost client defaults:\n%s", config)
	}
}

func TestPeerValidationAndPathSafety(t *testing.T) {
	manager, _ := testManager(t)
	for _, name := range []string{"", "../peer", "peer/name", "peer name", "-peer", strings.Repeat("a", 33)} {
		if err := ValidatePeerName(name); err == nil {
			t.Errorf("accepted invalid peer name %q", name)
		}
	}
	for _, name := range []string{"client2", "home-server", "origin_3"} {
		if err := ValidatePeerName(name); err != nil {
			t.Errorf("rejected valid peer name %q: %v", name, err)
		}
	}
	if _, err := manager.Config("../server"); err == nil {
		t.Fatal("path traversal peer name was accepted")
	}
}

func TestPrepareRejectsInvalidInterfaceNames(t *testing.T) {
	manager, _ := testManager(t)
	for _, name := range []string{"wg interface", "wg/interface", strings.Repeat("a", 16)} {
		manager.Interface = name
		if err := manager.prepare(); err == nil {
			t.Errorf("accepted invalid interface name %q", name)
		}
	}
	for _, name := range []string{"wg0", "wg-test", "vpn_1", "a.b"} {
		manager.Interface = name
		if err := manager.prepare(); err != nil {
			t.Errorf("rejected valid interface name %q: %v", name, err)
		}
	}
}

func TestValidateClientDefaultsRejectsInvalidEndpointLabels(t *testing.T) {
	valid := []string{
		"vpn.example.com:51820",
		"wg-host:1",
		"203.0.113.10:65535",
		"[2001:db8::1]:51820",
	}
	for _, endpoint := range valid {
		if err := validateClientDefaults(clientDefaults{Endpoint: endpoint, AllowedIPs: "10.77.0.0/24"}); err != nil {
			t.Errorf("rejected valid endpoint %q: %v", endpoint, err)
		}
	}
	invalid := []string{
		"-vpn.example.com:51820",
		"vpn-.example.com:51820",
		"vpn.-example.com:51820",
		"vpn..example.com:51820",
		strings.Repeat("a", 64) + ".example.com:51820",
	}
	for _, endpoint := range invalid {
		if err := validateClientDefaults(clientDefaults{Endpoint: endpoint, AllowedIPs: "10.77.0.0/24"}); err == nil {
			t.Errorf("accepted invalid endpoint %q", endpoint)
		}
	}
}
