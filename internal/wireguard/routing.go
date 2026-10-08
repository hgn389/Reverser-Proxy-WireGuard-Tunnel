package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	routingStart     = "# rpctl-full-tunnel-routing-begin"
	routingEnd       = "# rpctl-full-tunnel-routing-end"
	forwardingConfig = "# Managed by rpctl. Full-tunnel routing for WireGuard peers.\nnet.ipv4.ip_forward=1\n"
)

type RoutingManager struct {
	Runner         Runner
	IPPath         string
	IPTablesPath   string
	SysctlPath     string
	ForwardingPath string
}

type routingRule struct {
	table      string
	chain      string
	parameters []string
	insert     bool
}

func (r routingRule) args(operation string) []string {
	args := []string{"-w", "5", "-t", r.table, operation, r.chain}
	if operation == "-I" {
		args = append(args, "1")
	}
	return append(args, r.parameters...)
}

func (r routingRule) addOperation() string {
	if r.insert {
		return "-I"
	}
	return "-A"
}

func missingRule(err error) bool {
	var exit interface{ ExitCode() int }
	return errors.As(err, &exit) && exit.ExitCode() == 1
}

// Enable prepares live IPv4 routing and returns an undo function for a failed update.
// Routing remains available when a peer switches back to private mode.
func (r RoutingManager) Enable(server []byte, device, subnet string) ([]byte, func() error, error) {
	if !interfaceNameRE.MatchString(device) {
		return nil, nil, errors.New("invalid WireGuard routing interface")
	}
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, nil, errors.New("invalid WireGuard routing subnet")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 || ones > 30 || network.String() != subnet {
		return nil, nil, errors.New("WireGuard routing requires a canonical IPv4 subnet between /16 and /30")
	}
	if r.Runner == nil {
		r.Runner = ExecRunner{}
	}
	if r.IPPath == "" {
		r.IPPath = "/usr/sbin/ip"
	}
	if r.IPTablesPath == "" {
		r.IPTablesPath = "/usr/sbin/iptables"
	}
	if r.SysctlPath == "" {
		r.SysctlPath = "/usr/sbin/sysctl"
	}
	if r.ForwardingPath == "" {
		r.ForwardingPath = "/etc/sysctl.d/99-rpctl-wireguard-peers.conf"
	}
	output, err := r.Runner.Run(nil, r.IPPath, "-4", "route", "get", "1.1.1.1")
	if err != nil {
		return nil, nil, commandError("detecting the IPv4 Internet interface", output, err)
	}
	fields := strings.Fields(string(output))
	uplink := ""
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "dev" {
			uplink = fields[index+1]
			break
		}
	}
	if !interfaceNameRE.MatchString(uplink) || uplink == device {
		return nil, nil, errors.New("could not detect an IPv4 Internet interface outside WireGuard")
	}
	comment := []string{"-m", "comment", "--comment", "rpctl-" + device + "-full"}
	rules := []routingRule{
		{table: "filter", chain: "FORWARD", parameters: append([]string{"-i", device, "-s", subnet, "-o", uplink}, append(comment, "-j", "ACCEPT")...), insert: true},
		{table: "filter", chain: "FORWARD", parameters: append([]string{"-i", uplink, "-o", device, "-d", subnet, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, append(comment, "-j", "ACCEPT")...), insert: true},
		{table: "nat", chain: "POSTROUTING", parameters: append([]string{"-s", subnet, "-o", uplink}, append(comment, "-j", "MASQUERADE")...)},
	}
	var up, down []string
	for _, rule := range rules {
		check := r.IPTablesPath + " " + strings.Join(rule.args("-C"), " ") + " >/dev/null 2>&1"
		up = append(up, "("+check+" || "+r.IPTablesPath+" "+strings.Join(rule.args(rule.addOperation()), " ")+")")
		down = append(down, "("+check+" && "+r.IPTablesPath+" "+strings.Join(rule.args("-D"), " ")+" || true)")
	}
	hooks := []string{routingStart, "PostUp = " + strings.Join(up, " && "), "PostDown = " + strings.Join(down, "; "), routingEnd}
	candidate, err := withRoutingHooks(server, hooks)
	if err != nil {
		return nil, nil, err
	}
	previousFile, err := readRegularFile(r.ForwardingPath, 4096)
	fileExisted := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading forwarding configuration: %w", err)
	}
	output, err = r.Runner.Run(nil, r.SysctlPath, "-n", "net.ipv4.ip_forward")
	if err != nil {
		return nil, nil, commandError("reading IPv4 forwarding", output, err)
	}
	previousForward := strings.TrimSpace(string(output))
	if previousForward != "0" && previousForward != "1" {
		return nil, nil, errors.New("invalid IPv4 forwarding state")
	}
	var added []routingRule
	fileChanged, forwardChanged := false, false
	undo := func() error {
		var failures []error
		for index := len(added) - 1; index >= 0; index-- {
			output, err := r.Runner.Run(nil, r.IPTablesPath, added[index].args("-D")...)
			if err != nil && !missingRule(err) {
				failures = append(failures, commandError("removing added routing rule", output, err))
			}
		}
		if fileChanged {
			var err error
			if fileExisted {
				err = writeAtomic(r.ForwardingPath, previousFile, 0644)
			} else {
				err = removeAndSync(r.ForwardingPath)
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("restoring forwarding configuration: %w", err))
			}
		}
		if forwardChanged {
			output, err := r.Runner.Run(nil, r.SysctlPath, "-w", "net.ipv4.ip_forward="+previousForward)
			if err != nil {
				failures = append(failures, commandError("restoring IPv4 forwarding", output, err))
			}
		}
		return errors.Join(failures...)
	}
	fail := func(cause error) ([]byte, func() error, error) {
		if err := undo(); err != nil {
			cause = fmt.Errorf("%w; routing rollback incomplete: %v", cause, err)
		}
		return nil, nil, cause
	}
	for _, rule := range rules {
		output, err := r.Runner.Run(nil, r.IPTablesPath, rule.args("-C")...)
		if err == nil {
			continue
		}
		if !missingRule(err) {
			if errors.Is(err, os.ErrNotExist) {
				return fail(fmt.Errorf("Full tunnel requires iptables on VPS-1; run sudo apt install -y iptables and try again: %w", err))
			}
			return fail(commandError("checking full-tunnel routing; install iptables if missing", output, err))
		}
		output, err = r.Runner.Run(nil, r.IPTablesPath, rule.args(rule.addOperation())...)
		if err != nil {
			return fail(commandError("enabling full-tunnel routing", output, err))
		}
		added = append(added, rule)
	}
	if !bytes.Equal(previousFile, []byte(forwardingConfig)) {
		if err := os.MkdirAll(filepath.Dir(r.ForwardingPath), 0755); err != nil {
			return fail(err)
		}
		fileChanged = true
		if err := writeAtomic(r.ForwardingPath, []byte(forwardingConfig), 0644); err != nil {
			return fail(err)
		}
	}
	if previousForward != "1" {
		forwardChanged = true
		output, err := r.Runner.Run(nil, r.SysctlPath, "-w", "net.ipv4.ip_forward=1")
		if err != nil {
			return fail(commandError("enabling IPv4 forwarding", output, err))
		}
	}
	return candidate, undo, nil
}

func withRoutingHooks(server []byte, hooks []string) ([]byte, error) {
	var result []string
	section, inBlock, inserted := "", false, false
	for _, line := range strings.Split(strings.TrimRight(string(server), "\n"), "\n") {
		marker := strings.TrimSpace(line)
		if marker == routingStart {
			if section != "[Interface]" || inBlock {
				return nil, errors.New("invalid managed WireGuard routing block")
			}
			inBlock = true
			continue
		}
		if marker == routingEnd {
			if !inBlock {
				return nil, errors.New("invalid managed WireGuard routing block")
			}
			inBlock = false
			continue
		}
		clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			if inBlock {
				return nil, errors.New("unterminated managed WireGuard routing block")
			}
			if section == "[Interface]" && !inserted {
				result = append(result, hooks...)
				inserted = true
			}
			section = clean
		}
		if !inBlock {
			result = append(result, line)
		}
	}
	if inBlock {
		return nil, errors.New("unterminated managed WireGuard routing block")
	}
	if section == "[Interface]" && !inserted {
		result = append(result, hooks...)
		inserted = true
	}
	if !inserted {
		return nil, errors.New("WireGuard configuration has no [Interface] for routing hooks")
	}
	return []byte(strings.Join(result, "\n") + "\n"), nil
}
