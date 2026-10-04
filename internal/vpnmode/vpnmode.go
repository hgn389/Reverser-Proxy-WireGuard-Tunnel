package vpnmode

import (
	"errors"
	"os"
	"strings"
)

const Path = "/etc/rpctl/vpn-mode"

type Mode string

const (
	None      Mode = "none"
	WireGuard Mode = "wireguard"
	Tailscale Mode = "tailscale"
)

func Detect() Mode {
	if data, err := os.ReadFile(Path); err == nil {
		switch Mode(strings.TrimSpace(string(data))) {
		case WireGuard:
			return WireGuard
		case Tailscale:
			return Tailscale
		case None:
			return None
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return None
	}

	// Preserve the behavior of installations created before vpn-mode existed.
	if info, err := os.Lstat("/etc/wireguard/wg0.conf"); err == nil && info.Mode().IsRegular() {
		return WireGuard
	}
	if info, err := os.Lstat("/var/lib/tailscale/tailscaled.state"); err == nil && info.Mode().IsRegular() {
		return Tailscale
	}
	// Older rpctl releases always rendered WireGuard controls when no explicit
	// selection existed. Keep that behavior until the installer records a mode.
	return WireGuard
}
