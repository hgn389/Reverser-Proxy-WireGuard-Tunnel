package webpanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"rpctl/internal/proxy"
)

const (
	webUser             = "rpweb"
	webStateDir         = "/var/lib/rpctl/web"
	webConfigDir        = "/etc/rpctl/web"
	webServicePath      = "/etc/systemd/system/rpctl-web.service"
	helperSocketPath    = "/etc/systemd/system/rpctl-web-helper.socket"
	helperServicePath   = "/etc/systemd/system/rpctl-web-helper@.service"
	sslRenewServicePath = "/etc/systemd/system/rpctl-ssl-renew.service"
	sslRenewDropInDir   = "/etc/systemd/system/rpctl-ssl-renew.service.d"
	sslRenewDropInPath  = "/etc/systemd/system/rpctl-ssl-renew.service.d/rpctl-nginx-runtime.conf"
	acmeExecutable      = "/opt/acme.sh/acme.sh"
	webFirewallMarker   = "/var/lib/rpctl/web-ufw-9080-managed"
)

type Installer struct {
	Store        proxy.Store
	SkipFirewall bool
}

func (i Installer) Install(domain, username string, password []byte) error {
	config := initialInstallConfig(domain, username)
	if domain != "" {
		if err := proxy.ValidateDomain(domain); err != nil {
			return err
		}
	}
	if !usernameRE.MatchString(username) {
		return errors.New("username must be 3-32 letters, numbers, dots, underscores, or hyphens")
	}
	if len(password) < 12 || len(password) > 72 {
		return errors.New("password must contain 12-72 bytes")
	}
	if domain != "" {
		acmeInfo, err := os.Stat(acmeExecutable)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("a domain-based Web Panel requires HTTPS; install acme.sh by rerunning the installer with --acme")
			}
			return err
		}
		if !acmeInfo.Mode().IsRegular() || acmeInfo.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("acme.sh path is not an executable regular file: %s", acmeExecutable)
		}
	}
	for _, path := range []string{DefaultConfigPath, webServicePath, helperSocketPath, helperServicePath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("web panel installation already exists at %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if domain != "" {
		if _, err := i.Store.Show(domain); err == nil {
			return fmt.Errorf("managed site %s already exists", domain)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	hash, err := bcrypt.GenerateFromPassword(password, 12)
	if err != nil {
		return err
	}
	config.PasswordHash = string(hash)
	if err := config.Validate(); err != nil {
		return err
	}
	uid, gid, userCreated, err := ensureWebUser()
	if err != nil {
		return err
	}
	created := []string{}
	completed := false
	cleanup := func() {
		_, _ = runSystemctl("disable", "--now", "rpctl-web.service", "rpctl-web-helper.socket")
		_, _ = setWebFirewall(false)
		for _, path := range created {
			_ = os.Remove(path)
		}
		_, _ = runSystemctl("daemon-reload")
		if userCreated {
			_ = exec.Command("/usr/sbin/userdel", webUser).Run()
			_ = exec.Command("/usr/sbin/groupdel", webUser).Run()
			_ = os.Remove(webConfigDir)
			_ = os.Remove(webStateDir)
		}
	}
	defer func() {
		if !completed {
			cleanup()
		}
	}()
	if err := os.MkdirAll(webStateDir, 0750); err != nil {
		return err
	}
	if err := os.Chown(webStateDir, uid, gid); err != nil {
		return err
	}
	if err := os.MkdirAll(webConfigDir, 0750); err != nil {
		return err
	}
	if err := os.Chown(webConfigDir, 0, gid); err != nil {
		return err
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	configBytes = append(configBytes, '\n')
	if err := writeOwnedAtomic(DefaultConfigPath, configBytes, 0640, 0, gid); err != nil {
		return err
	}
	created = append(created, DefaultConfigPath)
	units := map[string]string{
		webServicePath:    webServiceUnit,
		helperSocketPath:  helperSocketUnit,
		helperServicePath: helperServiceUnit,
	}
	for path, content := range units {
		if err := writeOwnedAtomic(path, []byte(content), 0644, 0, 0); err != nil {
			return err
		}
		created = append(created, path)
	}
	if _, err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := runSystemctl("enable", "--now", "rpctl-web-helper.socket", "rpctl-web.service"); err != nil {
		return err
	}
	if err := waitForWebHealth(); err != nil {
		return err
	}
	if config.PublicAccess && !i.SkipFirewall {
		if _, err := setWebFirewall(true); err != nil {
			return err
		}
	}
	if domain != "" {
		if err := i.Store.Add(proxy.Site{Domain: domain, Upstream: "http://127.0.0.1:9080"}); err != nil {
			return fmt.Errorf("creating panel reverse proxy: %w", err)
		}
	}
	completed = true
	return nil
}

func initialInstallConfig(domain, username string) Config {
	return Config{
		Listen:       PublicListen,
		Domain:       domain,
		PublicAccess: true,
		Username:     username,
		SessionTTL:   "30m",
	}
}

func (i Installer) SetEnabled(enabled bool) error {
	config, err := LoadConfig(DefaultConfigPath)
	if err != nil {
		return err
	}
	panelProxyEnabled := false
	if config.Domain != "" {
		site, err := i.Store.Show(config.Domain)
		if err != nil {
			return fmt.Errorf("reading Web Panel proxy state: %w", err)
		}
		panelProxyEnabled = site.Enabled
	}
	if enabled {
		if _, err := runSystemctl("enable", "--now", "rpctl-web-helper.socket", "rpctl-web.service"); err != nil {
			return err
		}
		if err := waitForWebHealth(); err != nil {
			_, _ = runSystemctl("disable", "--now", "rpctl-web.service", "rpctl-web-helper.socket")
			return err
		}
		if config.Domain != "" && !panelProxyEnabled {
			if err := i.Store.SetEnabled(config.Domain, true); err != nil {
				_, _ = runSystemctl("disable", "--now", "rpctl-web.service", "rpctl-web-helper.socket")
				return err
			}
		}
		return nil
	}
	if config.Domain != "" && panelProxyEnabled {
		if err := i.Store.SetEnabled(config.Domain, false); err != nil {
			return err
		}
	}
	if _, err = runSystemctl("disable", "--now", "rpctl-web.service", "rpctl-web-helper.socket"); err != nil {
		var rollbackFailures []string
		if _, startErr := runSystemctl("enable", "--now", "rpctl-web-helper.socket", "rpctl-web.service"); startErr != nil {
			rollbackFailures = append(rollbackFailures, "restarting Web Panel services: "+startErr.Error())
		}
		if config.Domain != "" && panelProxyEnabled {
			if proxyErr := i.Store.SetEnabled(config.Domain, true); proxyErr != nil {
				rollbackFailures = append(rollbackFailures, "restoring Web Panel proxy: "+proxyErr.Error())
			}
		}
		if len(rollbackFailures) > 0 {
			return fmt.Errorf("disabling Web Panel services: %w; rollback incomplete: %s", err, strings.Join(rollbackFailures, "; "))
		}
		return fmt.Errorf("disabling Web Panel services: %w; previous service and proxy state restored", err)
	}
	return nil
}

func (i Installer) RefreshUnits() error {
	if _, err := LoadConfig(DefaultConfigPath); err != nil {
		return fmt.Errorf("web panel is not installed: %w", err)
	}
	units := map[string]string{
		webServicePath:    webServiceUnit,
		helperSocketPath:  helperSocketUnit,
		helperServicePath: helperServiceUnit,
	}
	for path, content := range units {
		if err := writeOwnedAtomic(path, []byte(content), 0644, 0, 0); err != nil {
			return err
		}
	}
	if renewalUnit, err := os.ReadFile(sslRenewServicePath); err == nil {
		if strings.Contains(string(renewalUnit), "ExecStart=/usr/local/bin/rpctl ssl renew-all") {
			if err := os.MkdirAll(sslRenewDropInDir, 0755); err != nil {
				return err
			}
			if err := os.Chmod(sslRenewDropInDir, 0755); err != nil {
				return err
			}
			if err := writeOwnedAtomic(sslRenewDropInPath, []byte(sslRenewNginxRuntimeDropIn), 0644, 0, 0); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := runSystemctl("restart", "rpctl-web-helper.socket"); err != nil {
		return err
	}
	return nil
}

func Status() (string, error) {
	config, err := LoadConfig(DefaultConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "not installed", nil
		}
		return "", err
	}
	out, err := runSystemctl("is-active", "rpctl-web.service")
	state := strings.TrimSpace(string(out))
	if err != nil && state == "" {
		state = "inactive"
	}
	var addresses []string
	if config.Domain != "" {
		addresses = append(addresses, "https://"+config.Domain)
	}
	if publicURL := PublicURL(config); publicURL != "" {
		addresses = append(addresses, publicURL)
	}
	return fmt.Sprintf("%s (%s; %s)", state, config.Listen, strings.Join(addresses, ", ")), nil
}

func (i Installer) SetPublicAccess(enabled bool) (bool, error) {
	config, err := LoadConfig(DefaultConfigPath)
	if err != nil {
		return false, err
	}
	if config.PublicAccess == enabled {
		return setWebFirewall(enabled)
	}
	if !enabled && config.Domain == "" {
		return false, errors.New("cannot disable IP:port access until a Web Panel domain is configured")
	}
	previous := config
	config.PublicAccess = enabled
	if enabled {
		config.Listen = PublicListen
	} else {
		config.Listen = DefaultListen
	}
	if err := config.Validate(); err != nil {
		return false, err
	}
	writeConfig := func(value Config) error {
		group, err := user.LookupGroup(webUser)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return writeOwnedAtomic(DefaultConfigPath, append(data, '\n'), 0640, 0, gid)
	}
	if err := writeConfig(config); err != nil {
		return false, err
	}
	active := false
	if output, statusErr := runSystemctl("is-active", "rpctl-web.service"); statusErr == nil && strings.TrimSpace(string(output)) == "active" {
		active = true
	}
	rollback := func(cause error) (bool, error) {
		var rollbackFailures []string
		restored := true
		if restoreErr := writeConfig(previous); restoreErr != nil {
			restored = false
			rollbackFailures = append(rollbackFailures, "restoring Web Panel config: "+restoreErr.Error())
		}
		if active && restored {
			if _, restartErr := runSystemctl("restart", "rpctl-web.service"); restartErr != nil {
				rollbackFailures = append(rollbackFailures, "restarting Web Panel: "+restartErr.Error())
			} else if healthErr := waitForWebHealth(); healthErr != nil {
				rollbackFailures = append(rollbackFailures, "checking restored Web Panel: "+healthErr.Error())
			}
		}
		if len(rollbackFailures) > 0 && !previous.PublicAccess && config.PublicAccess {
			if _, stopErr := runSystemctl("stop", "rpctl-web.service"); stopErr != nil {
				rollbackFailures = append(rollbackFailures, "stopping potentially public Web Panel: "+stopErr.Error())
			}
		}
		if len(rollbackFailures) > 0 {
			return false, fmt.Errorf("%w; rollback incomplete: %s", cause, strings.Join(rollbackFailures, "; "))
		}
		return false, cause
	}
	if active {
		if _, err := runSystemctl("restart", "rpctl-web.service"); err != nil {
			return rollback(err)
		}
		if err := waitForWebHealth(); err != nil {
			return rollback(err)
		}
	}
	firewallChanged, err := setWebFirewall(enabled)
	if err != nil {
		return rollback(err)
	}
	return firewallChanged, nil
}

func PublicURL(config Config) string {
	if !config.PublicAccess {
		return ""
	}
	_, port, err := net.SplitHostPort(config.Listen)
	if err != nil {
		return ""
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var public, private []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "tailscale") {
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
				private = append(private, ip.String())
			} else {
				public = append(public, ip.String())
			}
		}
	}
	if len(public) == 0 {
		public = private
	}
	if len(public) == 0 {
		return ""
	}
	sort.Strings(public)
	return "http://" + net.JoinHostPort(public[0], port)
}

func setWebFirewall(enabled bool) (bool, error) {
	if _, err := os.Stat("/usr/sbin/ufw"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	status, err := exec.Command("/usr/sbin/ufw", "status").CombinedOutput()
	if err != nil || !strings.Contains(string(status), "Status: active") {
		return false, nil
	}
	_, markerErr := os.Lstat(webFirewallMarker)
	managed := markerErr == nil
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return false, markerErr
	}
	if enabled {
		if ufwHasRule(status, "9080/tcp") {
			return false, nil
		}
		if output, err := exec.Command("/usr/sbin/ufw", "allow", "9080/tcp", "comment", "rpctl Web Panel").CombinedOutput(); err != nil {
			return false, fmt.Errorf("opening UFW port 9080/tcp: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if err := os.WriteFile(webFirewallMarker, []byte("managed by rpctl\n"), 0600); err != nil {
			_, _ = exec.Command("/usr/sbin/ufw", "--force", "delete", "allow", "9080/tcp").CombinedOutput()
			return false, err
		}
		return true, nil
	}
	if !managed {
		return false, nil
	}
	if output, err := exec.Command("/usr/sbin/ufw", "--force", "delete", "allow", "9080/tcp").CombinedOutput(); err != nil {
		return false, fmt.Errorf("closing UFW port 9080/tcp: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Remove(webFirewallMarker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func ufwHasRule(status []byte, rule string) bool {
	for _, line := range strings.Split(string(status), "\n") {
		for _, field := range strings.Fields(line) {
			if field == rule {
				return true
			}
		}
	}
	return false
}

func PublicFirewallManaged() bool {
	info, err := os.Lstat(webFirewallMarker)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func ensureWebUser() (int, int, bool, error) {
	_, err := user.Lookup(webUser)
	created := false
	if err == nil {
		return 0, 0, false, fmt.Errorf("system account %s already exists without an rpctl Web Panel installation; refusing to reuse it", webUser)
	}
	var unknownUser user.UnknownUserError
	if !errors.As(err, &unknownUser) {
		return 0, 0, false, err
	}
	command := exec.Command("/usr/sbin/useradd", "--system", "--user-group", "--home-dir", webStateDir, "--create-home", "--shell", "/usr/sbin/nologin", webUser)
	if out, runErr := command.CombinedOutput(); runErr != nil {
		return 0, 0, false, fmt.Errorf("creating %s user: %w: %s", webUser, runErr, strings.TrimSpace(string(out)))
	}
	created = true
	cleanupCreatedUser := func() {
		_ = exec.Command("/usr/sbin/userdel", webUser).Run()
		_ = exec.Command("/usr/sbin/groupdel", webUser).Run()
	}
	account, err := user.Lookup(webUser)
	if err != nil {
		cleanupCreatedUser()
		return 0, 0, created, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		cleanupCreatedUser()
		return 0, 0, created, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		cleanupCreatedUser()
		return 0, 0, created, err
	}
	group, groupErr := user.LookupGroup(webUser)
	groupMatches := groupErr == nil && group.Gid == account.Gid
	if uid == 0 || uid >= 1000 || account.HomeDir != webStateDir || !groupMatches {
		cleanupCreatedUser()
		return 0, 0, created, fmt.Errorf("existing %s account is not a dedicated system user/group", webUser)
	}
	return uid, gid, created, nil
}

func waitForWebHealth() error {
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		response, err := client.Get("http://" + DefaultListen + "/login")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("health endpoint returned HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("web panel failed its localhost health check: %w", lastErr)
}

func runSystemctl(args ...string) ([]byte, error) {
	command := exec.Command("/usr/bin/systemctl", args...)
	out, err := command.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func writeOwnedAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".rpctl-web-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

const webServiceUnit = `[Unit]
Description=rpctl Web Panel
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=rpweb
Group=rpweb
ExecStart=/usr/local/bin/rpctl serve
Restart=on-failure
RestartSec=3s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=/var/lib/rpctl/web
MemoryMax=64M

[Install]
WantedBy=multi-user.target
`

const helperSocketUnit = `[Unit]
Description=rpctl restricted privileged helper socket

[Socket]
ListenStream=/run/rpctl/web-helper.sock
Accept=yes
SocketUser=root
SocketGroup=rpweb
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=true

[Install]
WantedBy=sockets.target
`

const helperServiceUnit = `[Unit]
Description=rpctl restricted privileged helper

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/local/bin/rpctl privileged-once
TimeoutStartSec=5min
StandardInput=socket
StandardOutput=socket
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=/etc/rpctl/sites /etc/nginx/sites-available /etc/nginx/sites-enabled /var/lib/rpctl/rollback /run/rpctl
ReadWritePaths=-/etc/rpctl/certs -/etc/rpctl/acme -/var/lib/rpctl/acme-webroot -/etc/rpctl/wireguard -/etc/wireguard
ReadWritePaths=-/var/log/nginx -/run/nginx.pid
`

const sslRenewNginxRuntimeDropIn = `# Managed by rpctl.
[Service]
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
ReadWritePaths=-/var/log/nginx -/run/nginx.pid
`
