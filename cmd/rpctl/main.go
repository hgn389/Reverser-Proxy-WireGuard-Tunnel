package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"rpctl/internal/certmgr"
	"rpctl/internal/proxy"
	"rpctl/internal/tailscale"
	"rpctl/internal/updater"
	"rpctl/internal/vpnmode"
	"rpctl/internal/webpanel"
	"rpctl/internal/wireguard"
)

var version = "dev"

const (
	nginxPath     = "/usr/sbin/nginx"
	systemctlPath = "/usr/bin/systemctl"
	wgPath        = "/usr/bin/wg"
)

func main() {
	store := proxy.DefaultStore()
	var err error
	if filepath.Base(os.Args[0]) == "rp" && len(os.Args) == 1 {
		err = menu(store)
	} else {
		err = run(store, os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func help() {
	fmt.Print(`rpctl ` + version + `

  rp                              Open terminal menu
  rpctl status                    Nginx and managed site status
  rpctl proxy list [--quiet]
  rpctl proxy show DOMAIN
  rpctl proxy add DOMAIN --upstream http://HOST:PORT
  rpctl proxy edit DOMAIN --upstream http://HOST:PORT
  rpctl proxy delete DOMAIN
  rpctl proxy enable DOMAIN
  rpctl proxy disable DOMAIN
  rpctl ssl status [DOMAIN]
  rpctl ssl issue DOMAIN
  rpctl ssl renew DOMAIN
  rpctl ssl disable DOMAIN
  rpctl ssl renew-all
  rpctl web status
  rpctl web install
  rpctl web install --domain DOMAIN --username USER --password-file FILE
  rpctl web enable
  rpctl web disable
  rpctl web blocked-ips
  rpctl web unblock IP|--all
  rpctl web public-access status|enable|disable
  rpctl web refresh
  rpctl system nginx-test
  rpctl system reload
  rpctl system recover
  rpctl wg status
  rpctl wg peer list
  rpctl wg peer add [NAME] [--ip-last-octet NUMBER]
  rpctl wg peer show NAME
  rpctl wg peer mode NAME private|full
  rpctl wg peer delete NAME
  rpctl tailscale status
  rpctl update
  rpctl version

Proxy changes require root. HTTP and HTTPS upstreams are supported;
managed sites listen on HTTP port 80 and HTTPS port 443 after SSL issuance.
`)
}

func root() error {
	if os.Geteuid() != 0 {
		return errors.New("this operation needs root; run with sudo")
	}
	return nil
}

func run(s proxy.Store, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		help()
		return nil
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("usage: rpctl version")
		}
		fmt.Println("rpctl", version)
		return nil
	case "status":
		if len(args) != 1 {
			return errors.New("usage: rpctl status")
		}
		sites, err := s.List()
		if err != nil {
			return err
		}
		serverIPs, vpnIPs := networkSummary()
		fmt.Println("rpctl", version)
		fmt.Println("Server IP:", serverIPs)
		fmt.Println("VPN IP:", vpnIPs)
		fmt.Println("VPN backend:", vpnmode.Detect())
		fmt.Printf("Managed sites: %d\n", len(sites))
		if _, err := os.Stat(nginxPath); err != nil {
			fmt.Println("Nginx: not installed")
		} else {
			out, err := exec.Command(systemctlPath, "is-active", "nginx").Output()
			if err != nil {
				fmt.Println("Nginx: inactive")
			} else {
				fmt.Println("Nginx:", strings.TrimSpace(string(out)))
			}
		}
		return nil
	case "motd":
		if len(args) != 1 {
			return errors.New("usage: rpctl motd")
		}
		printMOTD()
		return nil
	case "proxy":
		return proxyCommand(s, args[1:])
	case "ssl":
		return sslCommand(certmgr.DefaultManager(s), s, args[1:])
	case "web":
		return webCommand(s, args[1:])
	case "serve":
		if len(args) != 1 {
			return errors.New("usage: rpctl serve")
		}
		if os.Geteuid() == 0 {
			return errors.New("refusing to run the web panel as root")
		}
		config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath)
		if err != nil {
			return err
		}
		server, err := webpanel.NewServer(config, strings.TrimPrefix(version, "v"), s, webpanel.SocketClient{Path: webpanel.DefaultSocketPath})
		if err != nil {
			return err
		}
		return server.Run()
	case "privileged-once":
		if len(args) != 1 {
			return errors.New("usage: rpctl privileged-once")
		}
		if err := root(); err != nil {
			return err
		}
		// systemd connects stdout directly to the accepted Unix socket. Ignore
		// SIGPIPE so a browser disconnect becomes a normal write error instead
		// of a misleading signal failure in the service journal.
		signal.Ignore(syscall.SIGPIPE)
		err := webpanel.ServePrivilegedOnce(os.Stdin, os.Stdout, s, certmgr.DefaultManager(s))
		if errors.Is(err, syscall.EPIPE) {
			return nil
		}
		return err
	case "system":
		if len(args) != 2 {
			return errors.New("usage: rpctl system nginx-test|reload|recover")
		}
		if args[1] == "nginx-test" {
			if err := root(); err != nil {
				return err
			}
			if err := s.NginxTest(); err != nil {
				return err
			}
			fmt.Println("Nginx configuration is valid.")
			return nil
		}
		if args[1] == "reload" {
			if err := root(); err != nil {
				return err
			}
			if err := s.Reload(); err != nil {
				return err
			}
			fmt.Println("Nginx reloaded successfully.")
			return nil
		}
		if args[1] == "recover" {
			if err := root(); err != nil {
				return err
			}
			if err := s.Recover(); err != nil {
				return err
			}
			fmt.Println("Recovery completed; no interrupted transaction remains.")
			return nil
		}
		return errors.New("usage: rpctl system nginx-test|reload|recover")
	case "wg":
		return wgCommand(args[1:])
	case "tailscale":
		return tailscaleCommand(args[1:])
	case "update":
		if len(args) != 1 {
			return errors.New("usage: rpctl update")
		}
		if err := root(); err != nil {
			return err
		}
		result, err := updater.DefaultManager().UpdateLatest(context.Background())
		if err != nil {
			return err
		}
		if !result.Updated {
			fmt.Printf("rpctl %s is already the latest release.\n", result.Current)
			return nil
		}
		fmt.Printf("rpctl updated successfully: %s -> %s\n", result.Previous, result.Current)
		if result.Warning != "" {
			fmt.Fprintln(os.Stderr, "WARNING:", result.Warning)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q; run rpctl help", args[0])
	}
}

func tailscaleCommand(args []string) error {
	if len(args) != 1 || args[0] != "status" {
		return errors.New("usage: rpctl tailscale status")
	}
	status, err := tailscale.DefaultManager().Status(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("Tailscale:", status.BackendState)
	if status.Tailnet != "" {
		fmt.Println("Tailnet:", status.Tailnet)
	}
	fmt.Printf("This device: %s (%s)\n", status.Self.Name, strings.Join(status.Self.IPs, ", "))
	for _, peer := range status.Peers {
		state := "offline"
		if peer.Online {
			state = "online"
		}
		fmt.Printf("%-32s %-39s %s\n", peer.Name, strings.Join(peer.IPs, ", "), state)
	}
	return nil
}

func parsePeerAddArgs(args []string) (string, int, error) {
	var name string
	var lastOctet int
	var hasLastOctet bool
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--ip-last-octet" || strings.HasPrefix(argument, "--ip-last-octet=") {
			if hasLastOctet {
				return "", 0, errors.New("--ip-last-octet may be specified only once")
			}
			value := strings.TrimPrefix(argument, "--ip-last-octet=")
			if argument == "--ip-last-octet" {
				index++
				if index >= len(args) {
					return "", 0, errors.New("--ip-last-octet requires a whole number from 1 to 254")
				}
				value = args[index]
			}
			parsed, err := wireguard.ParseLastOctet(value)
			if err != nil || parsed == 0 {
				return "", 0, errors.New("--ip-last-octet requires a whole number from 1 to 254")
			}
			lastOctet, hasLastOctet = parsed, true
			continue
		}
		if name != "" || strings.HasPrefix(argument, "-") {
			return "", 0, errors.New("usage: rpctl wg peer add [NAME] [--ip-last-octet NUMBER]")
		}
		if err := wireguard.ValidatePeerName(argument); err != nil {
			return "", 0, err
		}
		name = argument
	}
	return name, lastOctet, nil
}

func wgCommand(args []string) error {
	if len(args) == 1 && args[0] == "status" {
		if err := root(); err != nil {
			return err
		}
		if _, err := os.Stat(wgPath); err != nil {
			return errors.New("WireGuard tools are not installed")
		}
		cmd := exec.Command(wgPath, "show")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if len(args) < 2 || args[0] != "peer" {
		return errors.New("usage: rpctl wg status|peer list|peer add [NAME] [--ip-last-octet NUMBER]|peer show NAME|peer mode NAME private|full|peer delete NAME")
	}
	if err := root(); err != nil {
		return err
	}
	manager := wireguard.DefaultManager()
	switch args[1] {
	case "list":
		if len(args) != 2 {
			return errors.New("usage: rpctl wg peer list")
		}
		peers, err := manager.List()
		if err != nil {
			return err
		}
		if len(peers) == 0 {
			fmt.Println("No managed WireGuard peers.")
			return nil
		}
		fmt.Printf("%-20s %-18s %-10s %s\n", "NAME", "VPN ADDRESS", "MODE", "CLIENT CONFIG")
		for _, peer := range peers {
			fmt.Printf("%-20s %-18s %-10s %s\n", peer.Name, peer.Address, peer.Mode, peer.ConfigPath)
		}
		return nil
	case "add":
		name, lastOctet, err := parsePeerAddArgs(args[2:])
		if err != nil {
			return err
		}
		peer, err := manager.AddWithLastOctet(name, lastOctet)
		if err != nil {
			return err
		}
		fmt.Printf("WireGuard peer created: %s (%s)\n", peer.Name, peer.Address)
		fmt.Println("Client configuration:", peer.ConfigPath)
		return nil
	case "show":
		if len(args) != 3 {
			return errors.New("usage: rpctl wg peer show NAME")
		}
		peer, err := manager.Show(args[2])
		if err != nil {
			return err
		}
		fmt.Println("Name:", peer.Name)
		fmt.Println("VPN address:", peer.Address)
		fmt.Println("Mode:", peer.Mode)
		fmt.Println("Public key:", peer.PublicKey)
		fmt.Println("Client configuration:", peer.ConfigPath)
		return nil
	case "mode":
		if len(args) != 4 {
			return errors.New("usage: rpctl wg peer mode NAME private|full")
		}
		peer, err := manager.SetPeerMode(args[2], args[3])
		if err != nil {
			return err
		}
		fmt.Printf("WireGuard peer %s mode: %s\n", peer.Name, peer.Mode)
		fmt.Println("Deactivate the device tunnel, import its updated .conf file or scan its new QR code, then reactivate it.")
		fmt.Println("Client configuration:", peer.ConfigPath)
		return nil
	case "delete":
		if len(args) != 3 {
			return errors.New("usage: rpctl wg peer delete NAME")
		}
		if err := manager.Delete(args[2]); err != nil {
			return err
		}
		fmt.Println("WireGuard peer deleted:", args[2])
		return nil
	default:
		return fmt.Errorf("unknown WireGuard peer command %q", args[1])
	}
}

func webCommand(s proxy.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rpctl web status|install|enable|disable|blocked-ips|unblock|public-access|refresh")
	}
	installer := webpanel.Installer{Store: s}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: rpctl web status")
		}
		status, err := webpanel.Status()
		if err != nil {
			return err
		}
		fmt.Println("Web Panel:", status)
		return nil
	case "install":
		if err := root(); err != nil {
			return err
		}
		if _, err := os.Lstat(webpanel.DefaultConfigPath); err == nil {
			return errors.New("web panel is already installed; use rpctl web status, enable, or disable")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		flags := flag.NewFlagSet("web install", flag.ContinueOnError)
		domainFlag := flags.String("domain", "", "Web Panel domain")
		usernameFlag := flags.String("username", "", "administrator username")
		passwordFile := flags.String("password-file", "", "root-readable password file")
		noOpenFirewall := flags.Bool("no-open-firewall", false, "do not add a UFW rule for direct IP:port access")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if len(flags.Args()) != 0 {
			return errors.New("usage: rpctl web install [--domain DOMAIN --username USER --password-file FILE]")
		}
		var domain, username string
		var password []byte
		var err error
		if *domainFlag == "" && *usernameFlag == "" && *passwordFile == "" {
			domain, username, password, err = readWebSetup()
		} else {
			if *usernameFlag == "" || *passwordFile == "" {
				return errors.New("--username and --password-file are required; --domain is optional")
			}
			domain, username = *domainFlag, *usernameFlag
			password, err = readPasswordFile(*passwordFile)
		}
		if err != nil {
			return err
		}
		installer.SkipFirewall = *noOpenFirewall
		defer func() {
			for index := range password {
				password[index] = 0
			}
		}()
		if err := installer.Install(domain, username, password); err != nil {
			return err
		}
		config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath)
		if err != nil {
			return err
		}
		sslReady := false
		if domain != "" {
			sslReady = provisionWebPanelSSL(s, domain)
		}
		if domain != "" && sslReady {
			fmt.Printf("Web Panel HTTPS is ready: https://%s\n", domain)
		}
		if publicURL := webpanel.PublicURL(config); publicURL != "" {
			fmt.Printf("Web Panel direct access is ready: %s\n", publicURL)
		}
		if webpanel.PublicFirewallManaged() {
			fmt.Println("UFW rule added: allow 9080/tcp (managed by rpctl).")
		}
		return nil
	case "enable", "disable":
		if len(args) != 1 {
			return fmt.Errorf("usage: rpctl web %s", args[0])
		}
		if err := root(); err != nil {
			return err
		}
		enabled := args[0] == "enable"
		if err := installer.SetEnabled(enabled); err != nil {
			return err
		}
		fmt.Printf("Web Panel %sd successfully.\n", args[0])
		return nil
	case "blocked-ips":
		if len(args) != 1 {
			return errors.New("usage: rpctl web blocked-ips")
		}
		if err := root(); err != nil {
			return err
		}
		_, err := printBlockedWebIPs()
		return err
	case "unblock":
		if len(args) != 2 {
			return errors.New("usage: rpctl web unblock IP|--all")
		}
		if err := root(); err != nil {
			return err
		}
		if _, err := webpanel.LoadConfig(webpanel.DefaultConfigPath); err != nil {
			return fmt.Errorf("web panel is not ready: %w", err)
		}
		blocks := webpanel.DefaultIPBlockStore()
		if args[1] == "--all" || strings.EqualFold(args[1], "all") {
			count, err := blocks.UnblockAll()
			if err != nil {
				return err
			}
			fmt.Printf("Unblocked %d Web Panel IP address(es).\n", count)
			return nil
		}
		removed, err := blocks.Unblock(args[1])
		if err != nil {
			return err
		}
		if !removed {
			return fmt.Errorf("IP address %s is not blocked", args[1])
		}
		fmt.Printf("Unblocked Web Panel IP: %s\n", args[1])
		return nil
	case "public-access":
		if len(args) != 2 || (args[1] != "status" && args[1] != "enable" && args[1] != "disable") {
			return errors.New("usage: rpctl web public-access status|enable|disable")
		}
		config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath)
		if err != nil {
			return fmt.Errorf("web panel is not ready: %w", err)
		}
		if args[1] == "status" {
			state := "disabled"
			address := ""
			if config.PublicAccess {
				state = "enabled"
				address = " (" + webpanel.PublicURL(config) + ")"
			}
			fmt.Printf("Web Panel IP:port access: %s%s\n", state, address)
			return nil
		}
		if err := root(); err != nil {
			return err
		}
		enabled := args[1] == "enable"
		firewallChanged, err := installer.SetPublicAccess(enabled)
		if err != nil {
			return err
		}
		updated, err := webpanel.LoadConfig(webpanel.DefaultConfigPath)
		if err != nil {
			return err
		}
		if enabled {
			fmt.Printf("Web Panel IP:port access enabled: %s\n", webpanel.PublicURL(updated))
			if firewallChanged {
				fmt.Println("UFW rule added: allow 9080/tcp (managed by rpctl).")
			}
		} else {
			fmt.Println("Web Panel IP:port access disabled; localhost/domain access remains available.")
			if firewallChanged {
				fmt.Println("rpctl-managed UFW rule removed: 9080/tcp.")
			}
		}
		return nil
	case "refresh":
		if len(args) != 1 {
			return errors.New("usage: rpctl web refresh")
		}
		if err := root(); err != nil {
			return err
		}
		if err := installer.RefreshUnits(); err != nil {
			return err
		}
		fmt.Println("Web Panel systemd units refreshed successfully.")
		return nil
	default:
		return fmt.Errorf("unknown web command %q", args[0])
	}
}

func provisionWebPanelSSL(s proxy.Store, domain string) bool {
	manager := certmgr.DefaultManager(s)
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}).DialContext,
		},
	}
	fmt.Printf("Checking %s before issuing its HTTPS certificate...\n", domain)
	if err := probeHTTPChallenge(client, manager.Webroot, "http://"+domain); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: SSL was not issued because %s does not reach this reverse proxy: %v\n", domain, err)
		printWebPanelSSLInstructions(domain)
		return false
	}
	if err := manager.Issue(domain); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: automatic SSL issuance failed for %s: %v\n", domain, err)
		printWebPanelSSLInstructions(domain)
		return false
	}
	fmt.Printf("SSL certificate issued automatically for %s.\n", domain)
	return true
}

func printWebPanelSSLInstructions(domain string) {
	fmt.Printf("Until SSL is issued, use direct IP:port access instead of https://%s.\n", domain)
	fmt.Println("After DNS points to this VPS, run 'rp', select 9. SSL certificates, then 2. Issue certificate.")
}

func readPasswordFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("password file must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("password file permissions must be 0600 or stricter")
	}
	if info.Size() < 1 || info.Size() > 74 {
		return nil, errors.New("password file must contain a 12-72 byte password")
	}
	password, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	password = bytes.TrimSuffix(password, []byte{'\n'})
	password = bytes.TrimSuffix(password, []byte{'\r'})
	if len(password) < 12 || len(password) > 72 {
		for index := range password {
			password[index] = 0
		}
		return nil, errors.New("password file must contain a 12-72 byte password")
	}
	return password, nil
}

func readWebSetup() (string, string, []byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", "", nil, errors.New("web installation needs an interactive terminal")
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	readLine := func(label string) (string, error) {
		if _, err := fmt.Fprint(tty, label); err != nil {
			return "", err
		}
		value, err := reader.ReadString('\n')
		return strings.TrimSpace(value), err
	}
	domain, err := readLine("Web Panel domain (Enter to use IP:9080): ")
	if err != nil {
		return "", "", nil, err
	}
	if domain != "" {
		if err := proxy.ValidateDomain(domain); err != nil {
			return "", "", nil, err
		}
	}
	username, err := readLine("Admin username: ")
	if err != nil {
		return "", "", nil, err
	}
	if _, err := fmt.Fprint(tty, "Admin password (12-72 characters): "); err != nil {
		return "", "", nil, err
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", "", nil, err
	}
	if _, err := fmt.Fprint(tty, "Confirm password: "); err != nil {
		return "", "", nil, err
	}
	confirmation, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", "", nil, err
	}
	defer func() {
		for index := range confirmation {
			confirmation[index] = 0
		}
	}()
	if !bytes.Equal(password, confirmation) {
		for index := range password {
			password[index] = 0
		}
		return "", "", nil, errors.New("password confirmation does not match")
	}
	return domain, username, password, nil
}

func sslCommand(manager certmgr.Manager, s proxy.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rpctl ssl status [DOMAIN]|issue DOMAIN|renew DOMAIN|disable DOMAIN|renew-all")
	}
	switch args[0] {
	case "status":
		if len(args) > 2 {
			return errors.New("usage: rpctl ssl status [DOMAIN]")
		}
		var domains []string
		if len(args) == 2 {
			domains = []string{args[1]}
		} else {
			sites, err := s.List()
			if err != nil {
				return err
			}
			for _, site := range sites {
				domains = append(domains, site.Domain)
			}
		}
		if len(domains) == 0 {
			fmt.Println("No managed sites.")
			return nil
		}
		for _, domain := range domains {
			status, err := manager.Status(domain)
			if err != nil {
				return fmt.Errorf("%s: %w", domain, err)
			}
			state := "disabled"
			if status.Enabled {
				state = "enabled"
			}
			expiry := "no certificate"
			if status.Issued {
				expiry = fmt.Sprintf("expires %s (%d days)", status.NotAfter.UTC().Format("2006-01-02"), status.DaysLeft)
			}
			fmt.Printf("%-35s %-8s %s\n", domain, state, expiry)
		}
		return nil
	case "issue", "renew", "disable":
		if len(args) != 2 {
			return fmt.Errorf("usage: rpctl ssl %s DOMAIN", args[0])
		}
		if err := root(); err != nil {
			return err
		}
		var err error
		switch args[0] {
		case "issue":
			err = manager.Issue(args[1])
		case "renew":
			err = manager.Renew(args[1])
		case "disable":
			err = manager.Disable(args[1])
		}
		if err != nil {
			return err
		}
		fmt.Printf("SSL %s succeeded: %s\n", args[0], args[1])
		return nil
	case "renew-all":
		if len(args) != 1 {
			return errors.New("usage: rpctl ssl renew-all")
		}
		if err := root(); err != nil {
			return err
		}
		sites, err := s.List()
		if err != nil {
			return err
		}
		var failures []string
		for _, site := range sites {
			if !site.SSLEnabled {
				continue
			}
			if err := manager.Renew(site.Domain); err != nil {
				failures = append(failures, site.Domain+": "+err.Error())
			}
		}
		if len(failures) > 0 {
			return errors.New(strings.Join(failures, "; "))
		}
		return nil
	default:
		return fmt.Errorf("unknown ssl command %q", args[0])
	}
}

func proxyCommand(s proxy.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rpctl proxy list|show|add|edit|delete|enable|disable")
	}
	switch args[0] {
	case "list":
		quiet := len(args) == 2 && args[1] == "--quiet"
		if len(args) != 1 && !quiet {
			return errors.New("usage: rpctl proxy list [--quiet]")
		}
		sites, err := s.List()
		if err != nil {
			return err
		}
		if len(sites) == 0 {
			if !quiet {
				fmt.Println("No managed sites.")
			}
			return nil
		}
		for _, site := range sites {
			if quiet {
				fmt.Println(site.Domain)
				continue
			}
			state := "disabled"
			if site.Enabled {
				state = "enabled"
			}
			fmt.Printf("%-35s %-40s %s\n", site.Domain, site.Upstream, state)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New("usage: rpctl proxy show DOMAIN")
		}
		site, err := s.Show(args[1])
		if err != nil {
			return err
		}
		b, err := proxy.Encode(site)
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil
	case "add", "edit":
		if len(args) < 2 {
			return fmt.Errorf("usage: rpctl proxy %s DOMAIN --upstream URL", args[0])
		}
		if err := root(); err != nil {
			return err
		}
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		upstream := flags.String("upstream", "", "HTTP(S) upstream URL with port")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if len(flags.Args()) != 0 || *upstream == "" {
			return fmt.Errorf("usage: rpctl proxy %s DOMAIN --upstream URL", args[0])
		}
		if args[0] == "add" {
			if err := s.Add(proxy.Site{Domain: args[1], Upstream: *upstream}); err != nil {
				return err
			}
		} else {
			if err := s.Update(args[1], *upstream); err != nil {
				return err
			}
		}
		fmt.Println("Proxy", args[0], "succeeded:", args[1])
		return nil
	case "delete", "enable", "disable":
		if len(args) != 2 {
			return fmt.Errorf("usage: rpctl proxy %s DOMAIN", args[0])
		}
		if err := root(); err != nil {
			return err
		}
		var err error
		switch args[0] {
		case "delete":
			err = s.Delete(args[1])
		case "enable":
			err = s.SetEnabled(args[1], true)
		case "disable":
			err = s.SetEnabled(args[1], false)
		}
		if err != nil {
			return err
		}
		fmt.Println("Proxy", args[0], "succeeded:", args[1])
		return nil
	default:
		return fmt.Errorf("unknown proxy command %q", args[0])
	}
}

func menu(s proxy.Store) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		serverIPs, vpnIPs := networkSummary()
		vpnMode := vpnmode.Detect()
		vpnMenuLabel := "VPN status"
		if vpnMode == vpnmode.WireGuard {
			vpnMenuLabel = "WireGuard peers"
		} else if vpnMode == vpnmode.Tailscale {
			vpnMenuLabel = "Tailscale status"
		}
		fmt.Print("\n------------------------------------------------------------\n")
		fmt.Println("# rpctl", version)
		fmt.Println("# Server IP:", serverIPs)
		fmt.Println("# VPN IP:   ", vpnIPs)
		fmt.Print("------------------------------------------------------------\n")
		fmt.Printf("1. Status\n2. List proxy domains\n3. Add proxy\n4. Edit proxy\n5. Enable proxy\n6. Disable proxy\n7. Delete proxy\n8. Test Nginx\n9. SSL certificates\n10. Install Webpanel Reverse Proxy\n11. Unblock Webpanel IP\n12. On-OFF Webpanel via IP:port\n13. %s\n14. Update to latest version\n0. Exit\n", vpnMenuLabel)
		fmt.Print("############################################################\nChoice: ")
		choice, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		choice = strings.TrimSpace(choice)
		if choice == "0" {
			return nil
		}
		var args []string
		var addedDomain string
		switch choice {
		case "1":
			args = []string{"status"}
		case "2":
			args = []string{"proxy", "list"}
		case "3", "4":
			domain := prompt(reader, "Domain: ")
			if err := proxy.ValidateDomain(domain); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
				printMenuGap()
				continue
			}
			upstream := prompt(reader, "Upstream (http://host:port): ")
			verb := "add"
			if choice == "4" {
				verb = "edit"
			} else {
				addedDomain = domain
			}
			args = []string{"proxy", verb, domain, "--upstream", upstream}
		case "5", "6", "7":
			verb := map[string]string{"5": "enable", "6": "disable", "7": "delete"}[choice]
			domain := prompt(reader, "Domain: ")
			if choice == "7" {
				confirm := strings.ToLower(prompt(reader, "Delete "+domain+"? [y/N]: "))
				if confirm != "y" && confirm != "yes" {
					fmt.Println("Delete cancelled.")
					printMenuGap()
					continue
				}
			}
			args = []string{"proxy", verb, domain}
		case "8":
			args = []string{"system", "nginx-test"}
		case "9":
			if err := sslMenu(reader, s); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
			}
			printMenuGap()
			continue
		case "10":
			if err := webCommand(s, []string{"install"}); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
			} else if config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
			} else if config.Domain != "" {
				afterProxyAdd(reader, s, config.Domain)
			}
			printMenuGap()
			continue
		case "11":
			if err := webBlockMenu(reader, s); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
			}
			printMenuGap()
			continue
		case "12":
			if err := webPublicAccessMenu(reader, s); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err)
			}
			printMenuGap()
			continue
		case "13":
			var vpnErr error
			switch vpnMode {
			case vpnmode.WireGuard:
				vpnErr = wireGuardPeerMenu(reader)
			case vpnmode.Tailscale:
				vpnErr = tailscaleCommand([]string{"status"})
			default:
				vpnErr = errors.New("no VPN backend is configured")
			}
			if vpnErr != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", vpnErr)
			}
			printMenuGap()
			continue
		case "14":
			confirm := strings.ToLower(prompt(reader, "Download and install the latest GitHub release? [y/N]: "))
			if confirm != "y" && confirm != "yes" {
				fmt.Println("Update cancelled.")
				printMenuGap()
				continue
			}
			args = []string{"update"}
		default:
			fmt.Println("Unknown choice.")
			printMenuGap()
			continue
		}
		if err := run(s, args); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
		} else if addedDomain != "" {
			afterProxyAdd(reader, s, addedDomain)
		}
		printMenuGap()
	}
}

func wireGuardPeerMenu(reader *bufio.Reader) error {
	fmt.Print("\n---------------- WireGuard peers ----------------\n")
	fmt.Print("1. List peers\n2. Add peer\n3. Show peer\n4. Delete peer\n5. Change peer mode\n0. Back\n")
	fmt.Print("-------------------------------------------------\nChoice: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	switch strings.TrimSpace(choice) {
	case "0", "":
		return nil
	case "1":
		return wgCommand([]string{"peer", "list"})
	case "2":
		name := strings.TrimSpace(prompt(reader, "Peer name (Enter = automatic): "))
		lastOctet := strings.TrimSpace(prompt(reader, "VPN IP Local (last number, 1-254; Enter = automatic): "))
		args := []string{"peer", "add"}
		if name != "" {
			args = append(args, name)
		}
		if lastOctet != "" {
			args = append(args, "--ip-last-octet", lastOctet)
		}
		return wgCommand(args)
	case "3":
		name := strings.TrimSpace(prompt(reader, "Peer name: "))
		return wgCommand([]string{"peer", "show", name})
	case "4":
		name := strings.TrimSpace(prompt(reader, "Peer name: "))
		confirm := strings.ToLower(prompt(reader, "Delete "+name+"? [y/N]: "))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Delete cancelled.")
			return nil
		}
		return wgCommand([]string{"peer", "delete", name})
	case "5":
		name := strings.TrimSpace(prompt(reader, "Peer name: "))
		choice := strings.TrimSpace(prompt(reader, "Mode: 1) Private network  2) Full tunnel [1]: "))
		mode := wireguard.ModePrivate
		if choice == "2" {
			mode = wireguard.ModeFull
		} else if choice != "" && choice != "1" {
			return errors.New("mode choice must be 1 or 2")
		}
		fmt.Println("After changing mode, deactivate the device tunnel, import the updated .conf file or scan its new QR code, then reactivate it.")
		confirm := strings.ToLower(prompt(reader, "Change mode and update the device configuration? [y/N]: "))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Mode change cancelled.")
			return nil
		}
		return wgCommand([]string{"peer", "mode", name, mode})
	default:
		return errors.New("unknown WireGuard peer choice")
	}
}

func webBlockMenu(reader *bufio.Reader, s proxy.Store) error {
	if err := root(); err != nil {
		return err
	}
	count, err := printBlockedWebIPs()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	value := strings.TrimSpace(prompt(reader, "IP to unblock (all = unblock all, Enter = cancel): "))
	if value == "" {
		fmt.Println("Unblock cancelled.")
		return nil
	}
	return run(s, []string{"web", "unblock", value})
}

func webPublicAccessMenu(reader *bufio.Reader, s proxy.Store) error {
	config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath)
	if err != nil {
		return fmt.Errorf("web panel is not ready: %w", err)
	}
	state := "OFF"
	preview := config
	preview.PublicAccess = true
	preview.Listen = webpanel.PublicListen
	address := webpanel.PublicURL(preview)
	if config.PublicAccess {
		state = "ON"
	}
	fmt.Printf("\n---------------- Web Panel IP:port ----------------\nStatus: %s\nAddress: %s\n", state, address)
	fmt.Print("1. ON\n2. OFF\n0. Back\n---------------------------------------------------\nChoice: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	switch strings.TrimSpace(choice) {
	case "0", "":
		return nil
	case "1":
		return run(s, []string{"web", "public-access", "enable"})
	case "2":
		return run(s, []string{"web", "public-access", "disable"})
	default:
		return errors.New("unknown Web Panel IP:port choice")
	}
}

func printMOTD() {
	serverIPs, vpnIPs := networkSummary()
	fmt.Println("************** Reverse Proxy & VPN Tunnel **************")
	fmt.Println("Server IP:", serverIPs)
	fmt.Println("VPN IP:   ", vpnIPs)
	if config, err := webpanel.LoadConfig(webpanel.DefaultConfigPath); err == nil {
		if config.Domain != "" {
			fmt.Println("Web Panel: https://" + config.Domain)
		}
		if publicURL := webpanel.PublicURL(config); publicURL != "" {
			fmt.Println("Web Panel IP:", publicURL)
		}
	}
	fmt.Println("Open menu: rp")
	fmt.Println("*******************************************************")
}

func printBlockedWebIPs() (int, error) {
	if _, err := webpanel.LoadConfig(webpanel.DefaultConfigPath); err != nil {
		return 0, fmt.Errorf("web panel is not ready: %w", err)
	}
	blocked, err := webpanel.DefaultIPBlockStore().List()
	if err != nil {
		return 0, err
	}
	if len(blocked) == 0 {
		fmt.Println("No blocked Web Panel IP addresses.")
		return 0, nil
	}
	for _, entry := range blocked {
		fmt.Printf("%-39s blocked %s after %d failures\n", entry.IP, entry.BlockedAt.Local().Format("2006-01-02 15:04:05 MST"), entry.Failures)
	}
	return len(blocked), nil
}

func afterProxyAdd(reader *bufio.Reader, s proxy.Store, domain string) {
	fmt.Println("Checking DNS and the HTTP route to this reverse proxy...")
	manager := certmgr.DefaultManager(s)
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}).DialContext,
		},
	}
	err := probeHTTPChallenge(client, manager.Webroot, "http://"+domain)
	if err != nil {
		serverIP := publicServerIPSummary()
		fmt.Printf("WARNING: %s does not reach the reverse proxy IP %s, so SSL cannot be issued yet.\n", domain, serverIP)
		fmt.Println("After updating DNS, issue SSL manually from menu item 9, SSL certificates.")
		fmt.Println("Check details:", err)
		return
	}

	fmt.Printf("%s reaches this reverse proxy and HTTP-01 is ready.\n", domain)
	answer := strings.ToLower(prompt(reader, "Issue the SSL certificate now? [Y/n]: "))
	if answer == "n" || answer == "no" {
		fmt.Println("SSL was skipped. You can issue it later from menu item 9, SSL certificates.")
		return
	}
	if err := run(s, []string{"ssl", "issue", domain}); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: automatic SSL issuance failed:", err)
		fmt.Println("The HTTP proxy remains active. Try again from menu item 9, SSL certificates.")
	}
}

func probeHTTPChallenge(client *http.Client, webroot, baseURL string) error {
	if client == nil {
		return errors.New("HTTP client is required")
	}
	challengeDir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0755); err != nil {
		return fmt.Errorf("creating HTTP-01 directory: %w", err)
	}
	info, err := os.Lstat(challengeDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("HTTP-01 challenge path is not a regular directory")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generating HTTP-01 token: %w", err)
	}
	token := "rpctl-check-" + hex.EncodeToString(random)
	path := filepath.Join(challengeDir, token)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("creating HTTP-01 token: %w", err)
	}
	removeToken := func() { _ = os.Remove(path) }
	defer removeToken()
	if _, err := f.WriteString(token); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	url := strings.TrimRight(baseURL, "/") + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rpctl-dns-check/"+version)
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("requesting %s: %w", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", url, response.StatusCode)
	}
	if string(body) != token {
		return errors.New("HTTP-01 response did not come from this VPS")
	}
	return nil
}

func publicServerIPSummary() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "(unavailable)"
	}
	var public, fallback []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isVPNInterfaceName(iface.Name) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !ip.IsGlobalUnicast() {
				continue
			}
			if ip.IsPrivate() {
				fallback = append(fallback, ip.String())
			} else {
				public = append(public, ip.String())
			}
		}
	}
	if len(public) == 0 {
		public = fallback
	}
	if len(public) == 0 {
		return "(unavailable)"
	}
	sort.Strings(public)
	return strings.Join(public, ", ")
}

func printMenuGap() {
	// Together with the leading newline of the next header, this leaves four
	// empty lines between an action result and the next menu block.
	fmt.Print("\n\n\n")
}

func sslMenu(reader *bufio.Reader, s proxy.Store) error {
	fmt.Print("\n------------------------ SSL ------------------------\n")
	fmt.Print("1. SSL status\n2. Issue certificate\n3. Renew certificate\n4. Disable SSL\n0. Back\n")
	fmt.Print("-----------------------------------------------------\nChoice: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice = strings.TrimSpace(choice)
	if choice == "0" {
		return nil
	}
	if choice == "1" {
		return run(s, []string{"ssl", "status"})
	}
	verb := map[string]string{"2": "issue", "3": "renew", "4": "disable"}[choice]
	if verb == "" {
		return errors.New("unknown SSL choice")
	}
	domain := prompt(reader, "Domain: ")
	return run(s, []string{"ssl", verb, domain})
}

type networkAddress struct {
	interfaceName string
	ip            net.IP
	up            bool
	loopback      bool
}

func networkSummary() (string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unavailable", "unavailable"
	}
	vpnInterfaces := make(map[string]struct{})
	var addresses []networkAddress
	for _, iface := range interfaces {
		if isVPNInterfaceName(iface.Name) {
			vpnInterfaces[iface.Name] = struct{}{}
		}
		interfaceAddresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range interfaceAddresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil {
				continue
			}
			addresses = append(addresses, networkAddress{
				interfaceName: iface.Name,
				ip:            ip,
				up:            iface.Flags&net.FlagUp != 0,
				loopback:      iface.Flags&net.FlagLoopback != 0,
			})
		}
	}
	if _, err := os.Stat(wgPath); err == nil {
		if out, err := exec.Command(wgPath, "show", "interfaces").Output(); err == nil {
			for _, name := range strings.Fields(string(out)) {
				vpnInterfaces[name] = struct{}{}
			}
		}
	}
	server, vpn := splitNetworkAddresses(addresses, vpnInterfaces)
	return formatNetworkAddresses(server, "not detected"), formatNetworkAddresses(vpn, "not configured")
}

func isVPNInterfaceName(name string) bool {
	return strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "tailscale")
}

func splitNetworkAddresses(addresses []networkAddress, vpnInterfaces map[string]struct{}) ([]string, []string) {
	var server, vpn []string
	seen := make(map[string]struct{})
	for _, address := range addresses {
		if address.loopback || !address.ip.IsGlobalUnicast() {
			continue
		}
		value := fmt.Sprintf("%s (%s)", address.ip.String(), address.interfaceName)
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		if _, ok := vpnInterfaces[address.interfaceName]; ok {
			vpn = append(vpn, value)
		} else if address.up {
			server = append(server, value)
		}
	}
	sort.Strings(server)
	sort.Strings(vpn)
	return server, vpn
}

func formatNetworkAddresses(addresses []string, empty string) string {
	if len(addresses) == 0 {
		return empty
	}
	return strings.Join(addresses, ", ")
}

func prompt(r *bufio.Reader, label string) string {
	fmt.Print(label)
	v, _ := r.ReadString('\n')
	return strings.TrimSpace(v)
}
