package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	defaultBinary = "/usr/bin/tailscale"
	maxStatusSize = 4 << 20
)

type Device struct {
	Name    string   `json:"name"`
	DNSName string   `json:"dns_name,omitempty"`
	IPs     []string `json:"ips"`
	OS      string   `json:"os,omitempty"`
	Online  bool     `json:"online"`
}

type Status struct {
	BackendState string   `json:"backend_state"`
	Tailnet      string   `json:"tailnet,omitempty"`
	Self         Device   `json:"self"`
	Peers        []Device `json:"peers"`
}

type Manager struct {
	Binary string
}

type rawStatus struct {
	BackendState   string               `json:"BackendState"`
	MagicDNSSuffix string               `json:"MagicDNSSuffix"`
	CurrentTailnet rawTailnet           `json:"CurrentTailnet"`
	Self           rawDevice            `json:"Self"`
	Peer           map[string]rawDevice `json:"Peer"`
}

type rawTailnet struct {
	Name string `json:"Name"`
}

type rawDevice struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	OS           string   `json:"OS"`
	Online       bool     `json:"Online"`
}

func DefaultManager() Manager {
	return Manager{Binary: defaultBinary}
}

func (m Manager) Status(ctx context.Context) (Status, error) {
	if m.Binary == "" {
		m.Binary = defaultBinary
	}
	info, err := os.Lstat(m.Binary)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, errors.New("Tailscale is not installed")
		}
		return Status{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return Status{}, fmt.Errorf("Tailscale executable is invalid: %s", m.Binary)
	}

	commandContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandContext, m.Binary, "status", "--json").CombinedOutput()
	if len(output) > maxStatusSize {
		return Status{}, errors.New("Tailscale status response is too large")
	}
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return Status{}, fmt.Errorf("reading Tailscale status: %w: %s", err, message)
		}
		return Status{}, fmt.Errorf("reading Tailscale status: %w", err)
	}

	var raw rawStatus
	if err := json.Unmarshal(output, &raw); err != nil {
		return Status{}, errors.New("Tailscale returned invalid status data")
	}
	status := Status{
		BackendState: raw.BackendState,
		Tailnet:      raw.CurrentTailnet.Name,
		Self:         convertDevice(raw.Self),
		Peers:        make([]Device, 0, len(raw.Peer)),
	}
	if status.Tailnet == "" {
		status.Tailnet = raw.MagicDNSSuffix
	}
	for _, peer := range raw.Peer {
		status.Peers = append(status.Peers, convertDevice(peer))
	}
	sort.Slice(status.Peers, func(left, right int) bool {
		return strings.ToLower(status.Peers[left].Name) < strings.ToLower(status.Peers[right].Name)
	})
	return status, nil
}

func convertDevice(raw rawDevice) Device {
	name := raw.HostName
	if name == "" {
		name = strings.TrimSuffix(raw.DNSName, ".")
	}
	return Device{
		Name:    name,
		DNSName: strings.TrimSuffix(raw.DNSName, "."),
		IPs:     append([]string(nil), raw.TailscaleIPs...),
		OS:      raw.OS,
		Online:  raw.Online,
	}
}
