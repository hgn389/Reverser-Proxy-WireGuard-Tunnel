package wireguard

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type routingExit int

func (e routingExit) Error() string { return "routing command failed" }
func (e routingExit) ExitCode() int { return int(e) }

type routingTestRunner struct {
	rules           map[string]bool
	forward         string
	route           string
	failNAT         bool
	failForward     bool
	failCheck       bool
	missingIPTables bool
	calls           int
}

func (r *routingTestRunner) Run(_ []byte, path string, args ...string) ([]byte, error) {
	r.calls++
	switch filepath.Base(path) {
	case "ip":
		return []byte(r.route), nil
	case "sysctl":
		if args[0] == "-n" {
			return []byte(r.forward + "\n"), nil
		}
		if r.failForward && args[1] == "net.ipv4.ip_forward=1" {
			return nil, errors.New("sysctl failure")
		}
		r.forward = strings.TrimPrefix(args[1], "net.ipv4.ip_forward=")
		return nil, nil
	case "iptables":
		if r.missingIPTables {
			return nil, os.ErrNotExist
		}
		operation := args[4]
		parameters := args[6:]
		if operation == "-I" {
			parameters = parameters[1:]
		}
		key := args[3] + " " + args[5] + " " + strings.Join(parameters, " ")
		switch operation {
		case "-C":
			if r.failCheck {
				return nil, routingExit(4)
			}
			if !r.rules[key] {
				return nil, routingExit(1)
			}
		case "-I", "-A":
			if r.failNAT && args[3] == "nat" {
				return nil, routingExit(2)
			}
			r.rules[key] = true
		case "-D":
			delete(r.rules, key)
		default:
			return nil, errors.New("unexpected iptables operation")
		}
		return nil, nil
	}
	return nil, errors.New("unexpected routing command")
}

func testModeManager(t *testing.T) (Manager, *routingTestRunner) {
	t.Helper()
	manager, _ := testManager(t)
	runner := &routingTestRunner{rules: make(map[string]bool), forward: "0", route: "1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.10\n"}
	manager.Routing = &RoutingManager{Runner: runner, ForwardingPath: filepath.Join(t.TempDir(), "forwarding.conf")}
	return manager, runner
}

func TestSetPeerModePreservesIdentityAndInstallationDefault(t *testing.T) {
	manager, runner := testModeManager(t)
	original, err := manager.Config("client1")
	if err != nil {
		t.Fatal(err)
	}
	before, err := manager.Show("client1")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.SetPeerMode("client1", ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Mode != ModeFull || peer.Address != before.Address || peer.PublicKey != before.PublicKey {
		t.Fatalf("mode change altered identity: before=%+v after=%+v", before, peer)
	}
	full, err := manager.Config("client1")
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"Interface", "Peer"} {
		oldValues, _ := parseSection(original, section)
		newValues, _ := parseSection(full, section)
		for _, key := range []string{"address", "privatekey", "publickey", "presharedkey", "endpoint", "persistentkeepalive"} {
			if oldValues[key] != newValues[key] {
				t.Fatalf("%s.%s changed", section, key)
			}
		}
	}
	if !bytes.Contains(full, []byte("AllowedIPs = 0.0.0.0/0")) || !bytes.Contains(full, []byte(managedDNS)) {
		t.Fatal("full mode did not update routes and DNS")
	}
	if runner.forward != "1" || len(runner.rules) != 3 {
		t.Fatalf("routing state: %+v", runner)
	}
	server, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(server, []byte("AllowedIPs = 10.77.0.2/32")) || bytes.Count(server, []byte(routingStart)) != 1 {
		t.Fatal("server peer address changed or persistent routing hooks are missing")
	}
	if _, err := manager.SetPeerMode("client1", ModeFull); err != nil {
		t.Fatal(err)
	}
	repeated, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(server, repeated) || len(runner.rules) != 3 {
		t.Fatal("repeated mode change duplicated routing")
	}
	created, err := manager.Add("another-device")
	if err != nil {
		t.Fatal(err)
	}
	if created.Mode != ModePrivate {
		t.Fatal("changing a peer changed the installation default")
	}
	peer, err = manager.SetPeerMode("client1", ModePrivate)
	if err != nil {
		t.Fatal(err)
	}
	private, err := manager.Config("client1")
	if err != nil {
		t.Fatal(err)
	}
	if peer.Mode != ModePrivate || !bytes.Equal(original, private) {
		t.Fatal("private mode did not restore the original routes and DNS")
	}
	if runner.forward != "1" || len(runner.rules) != 3 {
		t.Fatal("private mode disabled routing used by other peers")
	}
	info, err := os.Stat(peer.ConfigPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("updated client configuration is not private")
	}
}

func TestClientModePreservesCustomDNSAndRejectsMultipleServers(t *testing.T) {
	manager, _ := testManager(t)
	client, err := manager.Config("client1")
	if err != nil {
		t.Fatal(err)
	}
	client = bytes.Replace(client, []byte("[Interface]\n"), []byte("[Interface]\nDNS = 9.9.9.9\n"), 1)
	full, err := clientWithMode(client, "10.77.0.0/24", ModeFull)
	if err != nil {
		t.Fatal(err)
	}
	private, err := clientWithMode(full, "10.77.0.0/24", ModePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(client, private) || bytes.Contains(full, []byte(managedDNS)) {
		t.Fatal("mode switching overwrote custom DNS")
	}
	if _, err := clientWithMode(append(client, []byte("\n[Peer]\nAllowedIPs = 192.168.1.0/24\n")...), "10.77.0.0/24", ModeFull); err == nil {
		t.Fatal("mode switching accepted a multiple-server client configuration")
	}
}

func TestSetPeerModeRoutingFailureLeavesConfigurationsUnchanged(t *testing.T) {
	for _, failure := range []string{"nat", "forwarding", "check", "missing-iptables", "unsafe-uplink", "peer-outside-subnet"} {
		t.Run(failure, func(t *testing.T) {
			manager, runner := testModeManager(t)
			switch failure {
			case "nat":
				runner.failNAT = true
			case "forwarding":
				runner.failForward = true
			case "check":
				runner.failCheck = true
			case "missing-iptables":
				runner.missingIPTables = true
			case "unsafe-uplink":
				runner.route = "1.1.1.1 dev eth0;reboot\n"
			case "peer-outside-subnet":
				for _, path := range []string{manager.ConfigPath, filepath.Join(manager.PeerDir, "client1.conf")} {
					content, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					content = bytes.ReplaceAll(content, []byte("10.77.0.2/32"), []byte("10.79.0.2/32"))
					if err := os.WriteFile(path, content, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			client, _ := manager.Config("client1")
			server, _ := os.ReadFile(manager.ConfigPath)
			if _, err := manager.SetPeerMode("client1", ModeFull); err == nil {
				t.Fatal("routing failure was ignored")
			}
			afterClient, _ := manager.Config("client1")
			afterServer, _ := os.ReadFile(manager.ConfigPath)
			if !bytes.Equal(client, afterClient) || !bytes.Equal(server, afterServer) {
				t.Fatal("failed mode change altered configurations")
			}
			if runner.forward != "0" || len(runner.rules) != 0 {
				t.Fatalf("routing was not rolled back: %+v", runner)
			}
			if _, err := os.Stat(manager.Routing.ForwardingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("forwarding file was not rolled back: %v", err)
			}
		})
	}
}

type rejectRoutingHooksRunner struct{ Runner }

func (r rejectRoutingHooksRunner) Run(input []byte, name string, args ...string) ([]byte, error) {
	if len(args) == 2 && args[0] == "strip" {
		config, err := os.ReadFile(args[1])
		if err != nil {
			return nil, err
		}
		if bytes.Contains(config, []byte(routingStart)) {
			return nil, errors.New("hook validation failed")
		}
	}
	return r.Runner.Run(input, name, args...)
}

func TestSetPeerModeRollsBackRoutingAfterServerValidationFailure(t *testing.T) {
	manager, runner := testModeManager(t)
	manager.Runner = rejectRoutingHooksRunner{manager.Runner}
	if _, err := manager.SetPeerMode("client1", ModeFull); err == nil {
		t.Fatal("invalid server hooks were accepted")
	}
	if runner.forward != "0" || len(runner.rules) != 0 {
		t.Fatal("routing was not rolled back")
	}
	peer, err := manager.Show("client1")
	if err != nil || peer.Mode != ModePrivate {
		t.Fatalf("mode=%s error=%v", peer.Mode, err)
	}
}

func TestRoutingHooksParseWithWGQuickAndShell(t *testing.T) {
	manager, _ := testModeManager(t)
	if _, err := manager.SetPeerMode("client1", ModeFull); err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile(manager.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(server), "\n") {
		if strings.HasPrefix(line, "PostUp = ") || strings.HasPrefix(line, "PostDown = ") {
			command := strings.SplitN(line, "=", 2)[1]
			if output, err := exec.Command("bash", "-n", "-c", command).CombinedOutput(); err != nil {
				t.Fatalf("invalid hook shell syntax: %v: %s", err, output)
			}
		}
	}
	if path, err := exec.LookPath("wg-quick"); err == nil {
		output, err := exec.Command(path, "strip", manager.ConfigPath).CombinedOutput()
		if err != nil {
			t.Fatalf("wg-quick could not parse persistent hooks: %v", err)
		}
		if bytes.Contains(output, []byte("PostUp =")) || bytes.Contains(output, []byte("PostDown =")) {
			t.Fatal("wg-quick did not strip routing hooks")
		}
	}
}
