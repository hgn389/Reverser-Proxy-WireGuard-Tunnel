package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

const (
	ModePrivate = "private"
	ModeFull    = "full"
	managedDNS  = "# rpctl-full-tunnel-dns"
)

func ValidatePeerMode(mode string) error {
	if mode != ModePrivate && mode != ModeFull {
		return errors.New("WireGuard mode must be private or full")
	}
	return nil
}

func modeFromAllowedIPs(value string) string {
	for _, route := range strings.Split(value, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(route))
		if err == nil {
			ones, bits := network.Mask.Size()
			if ones == 0 && bits == 32 {
				return ModeFull
			}
		}
	}
	return ModePrivate
}

func (m Manager) SetPeerMode(name, mode string) (Peer, error) {
	if err := ValidatePeerMode(mode); err != nil {
		return Peer{}, err
	}
	if err := m.prepare(); err != nil {
		return Peer{}, err
	}
	unlock, err := m.lock(syscall.LOCK_EX)
	if err != nil {
		return Peer{}, err
	}
	defer unlock()
	peer, err := m.readPeer(name)
	if err != nil {
		return Peer{}, err
	}
	server, err := readRegularFile(m.ConfigPath, maxConfigSize)
	if err != nil {
		return Peer{}, err
	}
	values, err := parseSection(server, "Interface")
	if err != nil {
		return Peer{}, err
	}
	ip, network, err := net.ParseCIDR(firstCSVValue(values["address"]))
	if err != nil || ip.To4() == nil {
		return Peer{}, errors.New("WireGuard server Address must contain an IPv4 subnet")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 || ones > 30 {
		return Peer{}, errors.New("peer mode switching requires an IPv4 subnet between /16 and /30")
	}
	peerIP, _, err := net.ParseCIDR(peer.Address)
	if err != nil || peerIP.To4() == nil || !network.Contains(peerIP) {
		return Peer{}, errors.New("peer mode switching requires an IPv4 peer address inside the server's WireGuard subnet")
	}
	client, err := readRegularFile(peer.ConfigPath, maxConfigSize)
	if err != nil {
		return Peer{}, err
	}
	candidate, err := clientWithMode(client, network.String(), mode)
	if err != nil {
		return Peer{}, err
	}
	if _, err := m.strip(candidate); err != nil {
		return Peer{}, fmt.Errorf("validating client mode configuration: %w", err)
	}
	// Preserve the installation's default for future peers before changing a template.
	peers, err := m.listUnlocked()
	if err != nil {
		return Peer{}, err
	}
	if _, err := m.clientDefaults(peers); err != nil {
		return Peer{}, err
	}
	serverCandidate := server
	undoRouting := func() error { return nil }
	if mode == ModeFull {
		routing := m.Routing
		if routing == nil {
			routing = &RoutingManager{Runner: m.Runner}
		}
		serverCandidate, undoRouting, err = routing.Enable(server, m.Interface, network.String())
		if err != nil {
			return Peer{}, err
		}
	}
	serverWritten, clientWritten := false, false
	rollback := func(cause error) (Peer, error) {
		var failures []error
		if clientWritten {
			if err := writeAtomic(peer.ConfigPath, client, 0600); err != nil {
				failures = append(failures, fmt.Errorf("restoring client configuration: %w", err))
			}
		}
		if serverWritten {
			if err := writeAtomic(m.ConfigPath, server, 0600); err != nil {
				failures = append(failures, fmt.Errorf("restoring server configuration: %w", err))
			}
		}
		if err := undoRouting(); err != nil {
			failures = append(failures, err)
		}
		if len(failures) != 0 {
			return Peer{}, fmt.Errorf("%w; rollback incomplete: %v", cause, errors.Join(failures...))
		}
		return Peer{}, cause
	}
	if !bytes.Equal(server, serverCandidate) {
		if _, err := m.strip(serverCandidate); err != nil {
			return rollback(fmt.Errorf("validating server routing configuration: %w", err))
		}
		serverWritten = true
		if err := writeAtomic(m.ConfigPath, serverCandidate, 0600); err != nil {
			return rollback(fmt.Errorf("saving server routing configuration: %w", err))
		}
	}
	clientWritten = true
	if err := writeAtomic(peer.ConfigPath, candidate, 0600); err != nil {
		return rollback(fmt.Errorf("saving peer mode configuration: %w", err))
	}
	peer.Mode = mode
	return peer, nil
}

func clientWithMode(config []byte, subnet, mode string) ([]byte, error) {
	peers := 0
	for _, line := range strings.Split(string(config), "\n") {
		if strings.TrimSpace(strings.SplitN(line, "#", 2)[0]) == "[Peer]" {
			peers++
		}
	}
	if peers != 1 {
		return nil, errors.New("mode switching requires a client configuration with exactly one [Peer]")
	}
	allowed := subnet
	if mode == ModeFull {
		allowed = "0.0.0.0/0"
	}
	result := replaceConfigValue(config, "Peer", "AllowedIPs", allowed)
	if mode == ModePrivate {
		var lines []string
		section := ""
		for _, line := range strings.Split(string(result), "\n") {
			clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if strings.HasPrefix(clean, "[") {
				section = clean
			}
			parts := strings.SplitN(clean, "=", 2)
			if section == "[Interface]" && len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "DNS") && strings.HasSuffix(strings.TrimSpace(line), managedDNS) {
				continue
			}
			lines = append(lines, line)
		}
		result = []byte(strings.Join(lines, "\n"))
	} else {
		values, err := parseSection(result, "Interface")
		if err != nil {
			return nil, err
		}
		if values["dns"] == "" {
			result = replaceConfigValue(result, "Interface", "DNS", "1.1.1.1, 8.8.8.8 "+managedDNS)
		}
	}
	return result, nil
}

func replaceConfigValue(config []byte, section, key, value string) []byte {
	var result []string
	current, replaced := "", false
	for _, line := range strings.Split(strings.TrimRight(string(config), "\n"), "\n") {
		clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			if current == section && !replaced {
				result = append(result, key+" = "+value)
				replaced = true
			}
			current = strings.TrimSpace(clean[1 : len(clean)-1])
		}
		parts := strings.SplitN(clean, "=", 2)
		if current == section && len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			if !replaced {
				result = append(result, key+" = "+value)
				replaced = true
			}
			continue
		}
		result = append(result, line)
	}
	if current == section && !replaced {
		result = append(result, key+" = "+value)
	}
	return []byte(strings.Join(result, "\n") + "\n")
}
