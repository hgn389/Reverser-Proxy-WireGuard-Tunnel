package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerSupportsDocumentedUbuntuReleases(t *testing.T) {
	installerPath := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	installer := string(content)
	for _, supported := range []string{"ubuntu:22.04", "ubuntu:24.04"} {
		if !strings.Contains(installer, supported) {
			t.Errorf("installer does not accept documented platform %s", supported)
		}
	}
	if strings.Contains(installer, "Only Ubuntu Server 24.04 is supported.") {
		t.Error("installer still contains the obsolete Ubuntu 24.04-only rejection")
	}
}

func TestInstallerOffersValidatedWireGuardSubnetSelection(t *testing.T) {
	installerPath := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	installer := string(content)
	for _, expected := range []string{
		`default_wg_network="10.10.10.0/24"`,
		`default_wg_server_address="10.10.10.1/24"`,
		`default_wg_client_address="10.10.10.2/32"`,
		"1) Use default subnet:",
		"2) Enter a custom private IPv4 subnet",
		"Custom subnet in CIDR notation",
		"valid_wireguard_network",
		"derive_wireguard_addresses",
		"prompt_custom_wireguard_network",
		"network_conflicts_with_routes",
		"RPCTL_WG_NETWORK must be a canonical private IPv4 subnet between /16 and /30.",
	} {
		if !strings.Contains(installer, expected) {
			t.Errorf("installer is missing WireGuard subnet behavior %q", expected)
		}
	}
	for _, obsolete := range []string{
		`wg_network="${RPCTL_WG_NETWORK:-10.10.0.0/24}"`,
		`wg_server_address="${RPCTL_WG_SERVER_ADDRESS:-10.10.0.1/24}"`,
		`wg_client_address="${RPCTL_WG_CLIENT_ADDRESS:-10.10.0.2/32}"`,
	} {
		if strings.Contains(installer, obsolete) {
			t.Errorf("installer still contains obsolete WireGuard default %q", obsolete)
		}
	}
}

func TestInstallerOffersTailscaleBackend(t *testing.T) {
	installerPath := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	installer := string(content)
	for _, expected := range []string{
		"Select VPN backend:",
		"1) WireGuard (default)",
		"2) Tailscale",
		"3) No VPN",
		"--tailscale",
		"--no-vpn",
		"RPCTL_TS_AUTH_KEY_FILE",
		"--auth-key=\"file:${tailscale_auth_key_file}\"",
		"pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg",
		"pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list",
		"write_vpn_mode \"$vpn_backend\"",
	} {
		if !strings.Contains(installer, expected) {
			t.Errorf("installer is missing Tailscale behavior %q", expected)
		}
	}
}

func TestInstallerWireGuardSubnetHelpers(t *testing.T) {
	installerPath := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	marker := []byte("\nfor arg in \"$@\"; do\n")
	index := strings.Index(string(content), string(marker))
	if index < 0 {
		t.Fatal("installer argument parser marker was not found")
	}
	prefixPath := filepath.Join(t.TempDir(), "installer-functions.sh")
	if err := os.WriteFile(prefixPath, content[:index], 0600); err != nil {
		t.Fatalf("write installer function fixture: %v", err)
	}

	check := `
source "$1"
has_tty=no
select_wireguard_network
test "$wg_network" = "192.168.150.0/24"
test "$wg_server_address" = "192.168.150.1/24"
test "$wg_client_address" = "192.168.150.2/32"
for network in 10.79.0.0/24 192.168.150.0/24 172.16.0.0/16 10.0.0.0/30; do
  valid_wireguard_network "$network"
done
for network in 8.8.8.0/24 192.168.2.1/24 172.15.0.0/16 172.32.0.0/16 10.79.0.0/31 10.79.0.0; do
  if valid_wireguard_network "$network"; then
    exit 1
  fi
done
cidrs_overlap 10.79.0.0/24 10.0.0.0/8
if cidrs_overlap 10.79.0.0/24 10.80.0.0/24; then
  exit 1
fi
`
	command := exec.Command("bash", "-c", check, "bash", prefixPath)
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "RPCTL_WG_NETWORK=") || strings.HasPrefix(variable, "RPCTL_WG_SERVER_ADDRESS=") || strings.HasPrefix(variable, "RPCTL_WG_CLIENT_ADDRESS=") {
			continue
		}
		command.Env = append(command.Env, variable)
	}
	command.Env = append(command.Env, "RPCTL_WG_NETWORK=192.168.150.0/24")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("WireGuard subnet helper checks failed: %v\n%s", err, output)
	}
}
