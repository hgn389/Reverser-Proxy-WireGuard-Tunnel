package wireguard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
