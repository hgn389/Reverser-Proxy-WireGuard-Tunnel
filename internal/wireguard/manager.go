package wireguard

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	defaultConfigPath = "/etc/wireguard/wg0.conf"
	defaultPeerDir    = "/etc/rpctl/wireguard/peers"
	defaultValuesPath = "/etc/rpctl/wireguard/peer-defaults.json"
	defaultLockPath   = "/etc/rpctl/wireguard/peer-operation.lock"
	defaultWGPath     = "/usr/bin/wg"
	defaultWGQuick    = "/usr/bin/wg-quick"
	maxConfigSize     = 1 << 20
)

var peerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
var interfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
var endpointLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type Peer struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	ConfigPath string `json:"config_path"`
}

type clientDefaults struct {
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowed_ips"`
}

type Runner interface {
	Run(input []byte, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(input []byte, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

type Manager struct {
	ConfigPath string
	PeerDir    string
	ValuesPath string
	LockPath   string
	Interface  string
	WGPath     string
	WGQuick    string
	Runner     Runner
}

func DefaultManager() Manager {
	return Manager{
		ConfigPath: defaultConfigPath,
		PeerDir:    defaultPeerDir,
		ValuesPath: defaultValuesPath,
		LockPath:   defaultLockPath,
		WGPath:     defaultWGPath,
		WGQuick:    defaultWGQuick,
		Runner:     ExecRunner{},
	}
}

func ValidatePeerName(name string) error {
	if !peerNameRE.MatchString(name) {
		return errors.New("peer name must contain 1-32 letters, numbers, underscores, or hyphens and start with a letter or number")
	}
	return nil
}

func (m Manager) List() ([]Peer, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.PeerDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	serverConfig, err := readRegularFile(m.ConfigPath, maxConfigSize)
	if err != nil {
		return nil, fmt.Errorf("reading WireGuard server configuration: %w", err)
	}
	publicKeys, err := peerPublicKeysByAddress(serverConfig)
	if err != nil {
		return nil, err
	}
	peers := make([]Peer, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".conf" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		if err := ValidatePeerName(name); err != nil {
			continue
		}
		peer, err := m.readPeerWithKeys(name, publicKeys)
		if err != nil {
			return nil, fmt.Errorf("reading peer %s: %w", name, err)
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool {
		left := net.ParseIP(strings.TrimSuffix(peers[i].Address, "/32")).To4()
		right := net.ParseIP(strings.TrimSuffix(peers[j].Address, "/32")).To4()
		if left != nil && right != nil {
			return ipToUint32(left) < ipToUint32(right)
		}
		return peers[i].Name < peers[j].Name
	})
	return peers, nil
}

func (m Manager) Show(name string) (Peer, error) {
	if err := m.prepare(); err != nil {
		return Peer{}, err
	}
	return m.readPeer(name)
}

func (m Manager) Config(name string) ([]byte, error) {
	if err := m.prepare(); err != nil {
		return nil, err
	}
	path, err := m.peerPath(name)
	if err != nil {
		return nil, err
	}
	return readRegularFile(path, maxConfigSize)
}

func (m Manager) Add(requestedName string) (Peer, error) {
	if err := m.prepare(); err != nil {
		return Peer{}, err
	}
	unlock, err := m.lock()
	if err != nil {
		return Peer{}, err
	}
	defer unlock()

	serverConfig, err := readRegularFile(m.ConfigPath, maxConfigSize)
	if err != nil {
		return Peer{}, fmt.Errorf("reading WireGuard server configuration: %w", err)
	}
	peers, err := m.List()
	if err != nil {
		return Peer{}, err
	}
	name := requestedName
	if name == "" {
		name = nextPeerName(peers)
	}
	peerPath, err := m.peerPath(name)
	if err != nil {
		return Peer{}, err
	}
	if _, err := os.Lstat(peerPath); err == nil {
		return Peer{}, fmt.Errorf("WireGuard peer %s already exists", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Peer{}, err
	}

	serverValues, err := parseSection(serverConfig, "Interface")
	if err != nil {
		return Peer{}, err
	}
	serverAddress := firstCSVValue(serverValues["address"])
	serverIP, network, err := net.ParseCIDR(serverAddress)
	if err != nil || serverIP.To4() == nil {
		return Peer{}, fmt.Errorf("WireGuard server Address must contain one IPv4 CIDR, got %q", serverAddress)
	}
	used, err := usedAddresses(serverConfig, peers)
	if err != nil {
		return Peer{}, err
	}
	clientIP, err := nextAddress(network, serverIP, used)
	if err != nil {
		return Peer{}, err
	}

	defaults, err := m.clientDefaults(peers)
	if err != nil {
		return Peer{}, err
	}

	clientPrivate, err := m.generateKey("genkey", nil)
	if err != nil {
		return Peer{}, err
	}
	clientPublic, err := m.publicKey(clientPrivate)
	if err != nil {
		return Peer{}, err
	}
	preshared, err := m.generateKey("genpsk", nil)
	if err != nil {
		return Peer{}, err
	}
	serverPrivate := strings.TrimSpace(serverValues["privatekey"])
	if err := validateKey(serverPrivate); err != nil {
		return Peer{}, errors.New("WireGuard server PrivateKey is invalid")
	}
	serverPublic, err := m.publicKey(serverPrivate)
	if err != nil {
		return Peer{}, err
	}

	address := clientIP.String() + "/32"
	serverCandidate := appendPeer(serverConfig, name, clientPublic, preshared, address)
	clientConfig := []byte(fmt.Sprintf("[Interface]\nAddress = %s\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", address, clientPrivate, serverPublic, preshared, defaults.Endpoint, defaults.AllowedIPs))

	if err := os.MkdirAll(m.PeerDir, 0700); err != nil {
		return Peer{}, err
	}
	if err := m.commit(serverConfig, serverCandidate, peerPath, clientConfig, false); err != nil {
		return Peer{}, err
	}
	return Peer{Name: name, Address: address, PublicKey: clientPublic, ConfigPath: peerPath}, nil
}

func (m Manager) Delete(name string) error {
	if err := m.prepare(); err != nil {
		return err
	}
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	peer, err := m.readPeer(name)
	if err != nil {
		return err
	}
	peers, err := m.List()
	if err != nil {
		return err
	}
	if _, err := m.clientDefaults(peers); err != nil {
		return fmt.Errorf("preserving WireGuard client defaults: %w", err)
	}
	serverConfig, err := readRegularFile(m.ConfigPath, maxConfigSize)
	if err != nil {
		return err
	}
	serverCandidate, removed := removePeer(serverConfig, peer.PublicKey)
	if !removed {
		return fmt.Errorf("peer %s was not found in the WireGuard server configuration", name)
	}
	peerPath, _ := m.peerPath(name)
	return m.commit(serverConfig, serverCandidate, peerPath, nil, true)
}

func (m *Manager) prepare() error {
	if m.ConfigPath == "" {
		m.ConfigPath = defaultConfigPath
	}
	if m.PeerDir == "" {
		m.PeerDir = defaultPeerDir
	}
	if m.ValuesPath == "" {
		m.ValuesPath = defaultValuesPath
	}
	if m.LockPath == "" {
		m.LockPath = defaultLockPath
	}
	if m.WGPath == "" {
		m.WGPath = defaultWGPath
	}
	if m.WGQuick == "" {
		m.WGQuick = defaultWGQuick
	}
	if m.Runner == nil {
		m.Runner = ExecRunner{}
	}
	if _, err := os.Lstat(m.ConfigPath); errors.Is(err, os.ErrNotExist) && m.ConfigPath == defaultConfigPath {
		matches, globErr := filepath.Glob("/etc/wireguard/*.conf")
		if globErr != nil {
			return globErr
		}
		if len(matches) == 1 {
			m.ConfigPath = matches[0]
		}
	}
	if m.Interface == "" {
		m.Interface = strings.TrimSuffix(filepath.Base(m.ConfigPath), ".conf")
	}
	if !interfaceNameRE.MatchString(m.Interface) {
		return errors.New("invalid WireGuard interface name")
	}
	if info, err := os.Lstat(m.PeerDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("WireGuard peer path is not a regular directory: %s", m.PeerDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (m Manager) readPeer(name string) (Peer, error) {
	serverConfig, err := readRegularFile(m.ConfigPath, maxConfigSize)
	if err != nil {
		return Peer{}, fmt.Errorf("reading WireGuard server configuration: %w", err)
	}
	publicKeys, err := peerPublicKeysByAddress(serverConfig)
	if err != nil {
		return Peer{}, err
	}
	return m.readPeerWithKeys(name, publicKeys)
}

func (m Manager) readPeerWithKeys(name string, publicKeys map[string]string) (Peer, error) {
	path, err := m.peerPath(name)
	if err != nil {
		return Peer{}, err
	}
	config, err := readRegularFile(path, maxConfigSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Peer{}, fmt.Errorf("WireGuard peer %s does not exist", name)
		}
		return Peer{}, err
	}
	values, err := parseSection(config, "Interface")
	if err != nil {
		return Peer{}, err
	}
	address := firstCSVValue(values["address"])
	if _, _, err := net.ParseCIDR(address); err != nil {
		return Peer{}, fmt.Errorf("invalid Address in %s", path)
	}
	privateKey := strings.TrimSpace(values["privatekey"])
	if err := validateKey(privateKey); err != nil {
		return Peer{}, fmt.Errorf("invalid PrivateKey in %s", path)
	}
	publicKey := publicKeys[address]
	if publicKey == "" {
		return Peer{}, fmt.Errorf("peer %s is missing from the WireGuard server configuration", name)
	}
	return Peer{Name: name, Address: address, PublicKey: publicKey, ConfigPath: path}, nil
}

func (m Manager) peerPath(name string) (string, error) {
	if err := ValidatePeerName(name); err != nil {
		return "", err
	}
	path := filepath.Join(m.PeerDir, name+".conf")
	if filepath.Dir(path) != filepath.Clean(m.PeerDir) {
		return "", errors.New("peer path escapes the configured directory")
	}
	return path, nil
}

func (m Manager) clientDefaults(peers []Peer) (clientDefaults, error) {
	data, err := readRegularFile(m.ValuesPath, 4096)
	if err == nil {
		var defaults clientDefaults
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&defaults); err != nil {
			return clientDefaults{}, fmt.Errorf("reading WireGuard peer defaults: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return clientDefaults{}, errors.New("WireGuard peer defaults contain trailing data")
		}
		if err := validateClientDefaults(defaults); err != nil {
			return clientDefaults{}, err
		}
		return defaults, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return clientDefaults{}, err
	}
	if len(peers) == 0 {
		return clientDefaults{}, errors.New("no WireGuard client template is available")
	}
	template, err := readRegularFile(peers[0].ConfigPath, maxConfigSize)
	if err != nil {
		return clientDefaults{}, err
	}
	values, err := parseSection(template, "Peer")
	if err != nil {
		return clientDefaults{}, err
	}
	defaults := clientDefaults{Endpoint: values["endpoint"], AllowedIPs: values["allowedips"]}
	if err := validateClientDefaults(defaults); err != nil {
		return clientDefaults{}, err
	}
	encoded, err := json.MarshalIndent(defaults, "", "  ")
	if err != nil {
		return clientDefaults{}, err
	}
	if err := os.MkdirAll(filepath.Dir(m.ValuesPath), 0700); err != nil {
		return clientDefaults{}, err
	}
	if err := writeAtomic(m.ValuesPath, append(encoded, '\n'), 0600); err != nil {
		return clientDefaults{}, err
	}
	return defaults, nil
}

func validateClientDefaults(defaults clientDefaults) error {
	endpoint := strings.TrimSpace(defaults.Endpoint)
	if strings.ContainsAny(endpoint, " \t\r\n") {
		return errors.New("WireGuard client Endpoint is invalid")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return errors.New("WireGuard client Endpoint is invalid")
	}
	if net.ParseIP(host) == nil && !validEndpointHostname(host) {
		return errors.New("WireGuard client Endpoint host is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("WireGuard client Endpoint port is invalid")
	}
	values := strings.Split(defaults.AllowedIPs, ",")
	if len(values) == 0 {
		return errors.New("WireGuard client AllowedIPs is missing")
	}
	for _, value := range values {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(value)); err != nil {
			return errors.New("WireGuard client AllowedIPs is invalid")
		}
	}
	return nil
}

func (m Manager) publicKey(private string) (string, error) {
	return m.generateKey("pubkey", []byte(private+"\n"))
}

func (m Manager) generateKey(operation string, input []byte) (string, error) {
	output, err := m.Runner.Run(input, m.WGPath, operation)
	if err != nil {
		return "", commandError("wg "+operation, output, err)
	}
	key := strings.TrimSpace(string(output))
	if err := validateKey(key); err != nil {
		return "", fmt.Errorf("wg %s returned an invalid key", operation)
	}
	return key, nil
}

func (m Manager) commit(oldServer, newServer []byte, peerPath string, clientConfig []byte, deleting bool) error {
	var deletedClient []byte
	var err error
	if deleting {
		deletedClient, err = readRegularFile(peerPath, maxConfigSize)
		if err != nil {
			return fmt.Errorf("reading peer configuration before deletion: %w", err)
		}
	}
	stripped, err := m.strip(newServer)
	if err != nil {
		return err
	}
	if !deleting {
		if _, err := m.strip(clientConfig); err != nil {
			return fmt.Errorf("validating generated client configuration: %w", err)
		}
	}
	if err := writeAtomic(m.ConfigPath, newServer, 0600); err != nil {
		if rollbackErr := writeAtomic(m.ConfigPath, oldServer, 0600); rollbackErr != nil {
			return fmt.Errorf("writing WireGuard server configuration: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("writing WireGuard server configuration: %w; previous server configuration restored", err)
	}
	clientChanged := false
	if !deleting {
		if err := writeNew(peerPath, clientConfig, 0600); err != nil {
			if rollbackErr := writeAtomic(m.ConfigPath, oldServer, 0600); rollbackErr != nil {
				return fmt.Errorf("creating WireGuard peer configuration: %w; rollback failed: %v", err, rollbackErr)
			}
			return fmt.Errorf("creating WireGuard peer configuration: %w; previous server configuration restored", err)
		}
		clientChanged = true
	}
	if err := m.sync(stripped); err != nil {
		var rollbackFailures []error
		if rollbackErr := writeAtomic(m.ConfigPath, oldServer, 0600); rollbackErr != nil {
			rollbackFailures = append(rollbackFailures, fmt.Errorf("restoring server configuration: %w", rollbackErr))
		}
		if clientChanged {
			if removeErr := removeAndSync(peerPath); removeErr != nil {
				rollbackFailures = append(rollbackFailures, fmt.Errorf("removing generated client configuration: %w", removeErr))
			}
		}
		oldStripped, stripErr := m.strip(oldServer)
		if stripErr != nil {
			rollbackFailures = append(rollbackFailures, fmt.Errorf("validating previous live configuration: %w", stripErr))
		} else if syncErr := m.sync(oldStripped); syncErr != nil {
			rollbackFailures = append(rollbackFailures, fmt.Errorf("restoring previous live configuration: %w", syncErr))
		}
		if len(rollbackFailures) > 0 {
			return fmt.Errorf("applying WireGuard configuration: %w; rollback incomplete: %v", err, errors.Join(rollbackFailures...))
		}
		return fmt.Errorf("applying WireGuard configuration: %w; previous configuration restored", err)
	}
	if deleting {
		if err := removeAndSync(peerPath); err != nil {
			var rollbackFailures []error
			if _, statErr := os.Lstat(peerPath); errors.Is(statErr, os.ErrNotExist) {
				if restoreErr := writeNew(peerPath, deletedClient, 0600); restoreErr != nil {
					rollbackFailures = append(rollbackFailures, fmt.Errorf("restoring client configuration: %w", restoreErr))
				}
			} else if statErr != nil {
				rollbackFailures = append(rollbackFailures, fmt.Errorf("checking client configuration after deletion failure: %w", statErr))
			}
			if rollbackErr := writeAtomic(m.ConfigPath, oldServer, 0600); rollbackErr != nil {
				rollbackFailures = append(rollbackFailures, fmt.Errorf("restoring server configuration: %w", rollbackErr))
			}
			oldStripped, stripErr := m.strip(oldServer)
			if stripErr != nil {
				rollbackFailures = append(rollbackFailures, fmt.Errorf("validating previous live configuration: %w", stripErr))
			} else if syncErr := m.sync(oldStripped); syncErr != nil {
				rollbackFailures = append(rollbackFailures, fmt.Errorf("restoring previous live configuration: %w", syncErr))
			}
			if len(rollbackFailures) > 0 {
				return fmt.Errorf("removing peer configuration: %w; rollback incomplete: %v", err, errors.Join(rollbackFailures...))
			}
			return fmt.Errorf("removing peer configuration: %w; WireGuard peer restored", err)
		}
	}
	return nil
}

func (m Manager) strip(config []byte) ([]byte, error) {
	dir := filepath.Dir(m.ConfigPath)
	file, err := createWGQuickTemp(dir)
	if err != nil {
		return nil, err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write(config); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	output, err := m.Runner.Run(nil, m.WGQuick, "strip", path)
	if err != nil {
		return nil, commandError("wg-quick strip", output, err)
	}
	return output, nil
}

// wg-quick treats a configuration filename as an interface name. Keep the
// generated basename valid and within Linux's 15-character interface limit.
func createWGQuickTemp(dir string) (*os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		random := make([]byte, 6)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, "rpc"+hex.EncodeToString(random)+".conf")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("could not create a unique WireGuard validation file")
}

func (m Manager) sync(stripped []byte) error {
	dir := filepath.Dir(m.ConfigPath)
	file, err := os.CreateTemp(dir, ".rpctl-wg-sync-*.conf")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(stripped); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	output, err := m.Runner.Run(nil, m.WGPath, "syncconf", m.Interface, path)
	if err != nil {
		return commandError("wg syncconf", output, err)
	}
	return nil
}

func (m Manager) lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(m.LockPath), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(m.LockPath); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, fmt.Errorf("WireGuard lock path is not a regular file: %s", m.LockPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(m.LockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func peerPublicKeysByAddress(serverConfig []byte) (map[string]string, error) {
	result := make(map[string]string)
	lines := strings.Split(string(serverConfig), "\n")
	for index := 0; index < len(lines); {
		if strings.TrimSpace(lines[index]) != "[Peer]" {
			index++
			continue
		}
		end := index + 1
		for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), "[") {
			end++
		}
		values, err := parseSection([]byte(strings.Join(lines[index:end], "\n")), "Peer")
		if err != nil {
			return nil, err
		}
		publicKey := strings.TrimSpace(values["publickey"])
		if err := validateKey(publicKey); err != nil {
			return nil, errors.New("WireGuard server configuration contains an invalid peer PublicKey")
		}
		for _, address := range strings.Split(values["allowedips"], ",") {
			address = strings.TrimSpace(address)
			if ip, _, err := net.ParseCIDR(address); err == nil && ip.To4() != nil {
				result[ip.String()+"/32"] = publicKey
			}
		}
		index = end
	}
	return result, nil
}

func parseSection(config []byte, wanted string) (map[string]string, error) {
	values := make(map[string]string)
	section := ""
	for _, raw := range strings.Split(string(config), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != wanted {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid WireGuard line %q", raw)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if _, exists := values[key]; !exists {
			values[key] = strings.TrimSpace(parts[1])
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("WireGuard configuration has no [%s] section", wanted)
	}
	return values, nil
}

func firstCSVValue(value string) string {
	if index := strings.IndexByte(value, ','); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func usedAddresses(serverConfig []byte, peers []Peer) (map[uint32]struct{}, error) {
	used := make(map[uint32]struct{})
	for _, peer := range peers {
		ip, _, err := net.ParseCIDR(peer.Address)
		if err != nil || ip.To4() == nil {
			return nil, fmt.Errorf("peer %s has invalid IPv4 address %q", peer.Name, peer.Address)
		}
		used[ipToUint32(ip)] = struct{}{}
	}
	section := ""
	for _, raw := range strings.Split(string(serverConfig), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Peer" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "AllowedIPs") {
			continue
		}
		for _, value := range strings.Split(parts[1], ",") {
			ip, _, err := net.ParseCIDR(strings.TrimSpace(value))
			if err == nil && ip.To4() != nil {
				used[ipToUint32(ip)] = struct{}{}
			}
		}
	}
	return used, nil
}

func nextAddress(network *net.IPNet, serverIP net.IP, used map[uint32]struct{}) (net.IP, error) {
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 || ones > 30 {
		return nil, errors.New("automatic peer allocation requires an IPv4 subnet between /16 and /30")
	}
	start := ipToUint32(network.IP.To4())
	end := start | ^maskToUint32(network.Mask)
	used[ipToUint32(serverIP)] = struct{}{}
	for value := start + 1; value < end; value++ {
		if _, exists := used[value]; !exists {
			return uint32ToIP(value), nil
		}
	}
	return nil, errors.New("WireGuard subnet has no free client addresses")
}

func nextPeerName(peers []Peer) string {
	used := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		used[peer.Name] = struct{}{}
	}
	for index := 1; ; index++ {
		name := "client" + strconv.Itoa(index)
		if _, exists := used[name]; !exists {
			return name
		}
	}
}

func appendPeer(server []byte, name, publicKey, presharedKey, address string) []byte {
	result := append([]byte(nil), bytes.TrimRight(server, "\n")...)
	result = append(result, []byte(fmt.Sprintf("\n\n[Peer]\n# rpctl-peer: %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", name, publicKey, presharedKey, address))...)
	return result
}

func removePeer(server []byte, publicKey string) ([]byte, bool) {
	lines := strings.Split(string(server), "\n")
	var output []string
	removed := false
	for index := 0; index < len(lines); {
		if strings.TrimSpace(lines[index]) != "[Peer]" {
			output = append(output, lines[index])
			index++
			continue
		}
		end := index + 1
		for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), "[") {
			end++
		}
		block := strings.Join(lines[index:end], "\n")
		values, err := parseSection([]byte(block), "Peer")
		if err == nil && strings.TrimSpace(values["publickey"]) == publicKey {
			removed = true
		} else {
			output = append(output, lines[index:end]...)
		}
		index = end
	}
	result := strings.TrimRight(strings.Join(output, "\n"), "\n") + "\n"
	return []byte(result), removed
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return os.ReadFile(path)
}

func writeNew(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	completed = true
	return nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular file %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".rpctl-write-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(temp)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	completed = true
	return nil
}

func removeAndSync(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validEndpointHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !endpointLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

func validateKey(key string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid WireGuard key")
	}
	return nil
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func maskToUint32(mask net.IPMask) uint32 {
	return uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
}

func commandError(action string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, message)
}
