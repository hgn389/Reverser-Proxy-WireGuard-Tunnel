package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type CommandRunner struct{}

const maxRollbackArchives = 50

func (CommandRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type Store struct {
	SitesDir      string
	AvailableDir  string
	EnabledDir    string
	RollbackDir   string
	LockPath      string
	NginxPath     string
	SystemctlPath string
	Runner        Runner
}

func DefaultStore() Store {
	return Store{
		SitesDir:      "/etc/rpctl/sites",
		AvailableDir:  "/etc/nginx/sites-available",
		EnabledDir:    "/etc/nginx/sites-enabled",
		RollbackDir:   "/var/lib/rpctl/rollback",
		LockPath:      "/run/rpctl/operation.lock",
		NginxPath:     "/usr/sbin/nginx",
		SystemctlPath: "/usr/bin/systemctl",
		Runner:        CommandRunner{},
	}
}

func (s Store) paths(domain string) (string, string, string, error) {
	if err := ValidateDomain(domain); err != nil {
		return "", "", "", err
	}
	stateName := domain + ".json"
	if len(stateName) > 255 {
		stateName = "rpctl-sha256-" + configDigest([]byte(domain)) + ".json"
	}
	configName := "rpctl-" + domain + ".conf"
	if len(configName) > 255 {
		configName = "rpctl-sha256-" + configDigest([]byte(domain)) + ".conf"
	}
	return filepath.Join(s.SitesDir, stateName), filepath.Join(s.AvailableDir, configName), filepath.Join(s.EnabledDir, configName), nil
}

func (s Store) List() ([]Site, error) {
	entries, err := os.ReadDir(s.SitesDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sites []Site
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.SitesDir, entry.Name())
		b, err := readRegular(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		site, err := Decode(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		expected, _, _, err := s.paths(site.Domain)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if expected != path {
			return nil, fmt.Errorf("%s: site filename and domain disagree", entry.Name())
		}
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites, nil
}

func (s Store) Show(domain string) (Site, error) {
	var zero Site
	state, _, _, err := s.paths(domain)
	if err != nil {
		return zero, err
	}
	b, err := readRegular(state)
	if err != nil {
		return zero, err
	}
	site, err := Decode(b)
	if err != nil {
		return zero, err
	}
	if site.Domain != domain {
		return zero, errors.New("site filename and domain disagree")
	}
	return site, nil
}

func (s Store) Add(site Site) error {
	if err := site.Validate(); err != nil {
		return err
	}
	site.Enabled = true
	return s.change(site.Domain, func(old *Site) (*Site, error) {
		if old != nil {
			return nil, errors.New("site already exists")
		}
		return &site, nil
	})
}

func (s Store) Delete(domain string) error {
	return s.change(domain, func(old *Site) (*Site, error) {
		if old == nil {
			return nil, fmt.Errorf("site %s does not exist", domain)
		}
		return nil, nil
	})
}

func (s Store) SetEnabled(domain string, enabled bool) error {
	return s.change(domain, func(old *Site) (*Site, error) {
		if old == nil {
			return nil, fmt.Errorf("site %s does not exist", domain)
		}
		old.Enabled = enabled
		return old, nil
	})
}

func (s Store) Update(domain, upstream string) error {
	if err := ValidateUpstream(upstream); err != nil {
		return err
	}
	return s.change(domain, func(old *Site) (*Site, error) {
		if old == nil {
			return nil, fmt.Errorf("site %s does not exist", domain)
		}
		old.Upstream = upstream
		return old, nil
	})
}

// Refresh safely regenerates a managed Nginx file from canonical state.
func (s Store) Refresh(domain string) error {
	return s.change(domain, func(old *Site) (*Site, error) {
		if old == nil {
			return nil, fmt.Errorf("site %s does not exist", domain)
		}
		return old, nil
	})
}

// SetSSL enables or disables the managed HTTPS listener and redirect.
func (s Store) SetSSL(domain string, enabled bool) error {
	return s.change(domain, func(old *Site) (*Site, error) {
		if old == nil {
			return nil, fmt.Errorf("site %s does not exist", domain)
		}
		old.SSLEnabled = enabled
		old.HTTPSRedirect = enabled
		return old, nil
	})
}

type snapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func takeSnapshot(path string) (snapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot{}, nil
	}
	if err != nil {
		return snapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return snapshot{}, fmt.Errorf("refusing non-regular file %s", path)
	}
	b, err := os.ReadFile(path)
	return snapshot{exists: true, data: b, mode: info.Mode().Perm()}, err
}

func restore(path string, snap snapshot) error {
	if !snap.exists {
		return removeFile(path)
	}
	return atomicWrite(path, snap.data, snap.mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rpctl-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func removeFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readRegular(path string) ([]byte, error) {
	snap, err := takeSnapshot(path)
	if err != nil {
		return nil, err
	}
	if !snap.exists {
		return nil, os.ErrNotExist
	}
	return snap.data, nil
}

func (s Store) runner() Runner {
	if s.Runner == nil {
		return CommandRunner{}
	}
	return s.Runner
}

func (s Store) nginxPath() string {
	if s.NginxPath != "" {
		return s.NginxPath
	}
	return "/usr/sbin/nginx"
}

func (s Store) systemctlPath() string {
	if s.SystemctlPath != "" {
		return s.SystemctlPath
	}
	return "/usr/bin/systemctl"
}

func (s Store) NginxTest() error {
	out, err := s.runner().Run(s.nginxPath(), "-t")
	if err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(string(out)), "conflicting server name") {
		return fmt.Errorf("nginx reported a conflicting server name: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (s Store) Reload() error {
	if err := s.NginxTest(); err != nil {
		return err
	}
	_, err := s.runner().Run(s.systemctlPath(), "reload", "nginx")
	return err
}

// Recover restores an interrupted proxy update, if one exists.
func (s Store) Recover() error {
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := os.MkdirAll(s.RollbackDir, 0700); err != nil {
		return err
	}
	return s.recoverPending()
}

func (s Store) lock() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(s.LockPath), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s Store) change(domain string, transform func(*Site) (*Site, error)) error {
	statePath, configPath, linkPath, err := s.paths(domain)
	if err != nil {
		return err
	}
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	if err := os.MkdirAll(s.SitesDir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(s.SitesDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.RollbackDir, 0700); err != nil {
		return err
	}
	for _, dir := range []string{s.AvailableDir, s.EnabledDir} {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("nginx directory %s: %w", dir, err)
		}
	}
	if err := s.recoverPending(); err != nil {
		return fmt.Errorf("recovering interrupted transaction: %w", err)
	}
	stateBefore, err := takeSnapshot(statePath)
	if err != nil {
		return err
	}
	configBefore, err := takeSnapshot(configPath)
	if err != nil {
		return err
	}
	var old *Site
	if stateBefore.exists {
		decoded, err := Decode(stateBefore.data)
		if err != nil {
			return fmt.Errorf("invalid managed state for %s: %w", domain, err)
		}
		if decoded.Domain != domain {
			return fmt.Errorf("site filename and domain disagree for %s", domain)
		}
		old = &decoded
	}
	if old != nil {
		if !configBefore.exists {
			return fmt.Errorf("missing managed Nginx config %s", configPath)
		}
		matches := old.ConfigSHA256 != "" && configDigest(configBefore.data) == old.ConfigSHA256
		if old.ConfigSHA256 == "" {
			expected, err := Render(*old)
			if err != nil {
				return err
			}
			legacy, err := renderLegacyV1(*old)
			if err != nil {
				return err
			}
			matches = string(configBefore.data) == string(expected) || string(configBefore.data) == string(legacy)
		}
		if !matches {
			return fmt.Errorf("managed Nginx config %s was changed outside rpctl", configPath)
		}
	} else if configBefore.exists {
		return fmt.Errorf("refusing unmanaged Nginx config %s", configPath)
	}
	linkExists, err := inspectLink(linkPath, configPath)
	if err != nil {
		return err
	}
	if old != nil && old.Enabled != linkExists || old == nil && linkExists {
		return fmt.Errorf("managed state and Nginx link disagree for %s", domain)
	}
	next, err := transform(old)
	if err != nil {
		return err
	}
	if next != nil {
		if err := next.Validate(); err != nil {
			return err
		}
	}
	if err := s.NginxTest(); err != nil {
		return fmt.Errorf("existing nginx configuration is invalid: %w", err)
	}
	var newState, newConfig []byte
	if next != nil {
		newConfig, err = Render(*next)
		if err != nil {
			return err
		}
		next.ConfigSHA256 = configDigest(newConfig)
		newState, err = Encode(*next)
		if err != nil {
			return err
		}
		if err := s.pretest(newConfig); err != nil {
			return fmt.Errorf("candidate Nginx configuration failed: %w", err)
		}
	}
	if err := s.pruneRollbackArchives(maxRollbackArchives - 1); err != nil {
		return fmt.Errorf("pruning old rollback archives: %w", err)
	}
	archive, err := s.saveRollback(domain, stateBefore, configBefore, linkExists)
	if err != nil {
		return err
	}
	if err := s.markPending(archive); err != nil {
		return err
	}
	rollback := func(cause error) error {
		var failures []string
		if err := restore(statePath, stateBefore); err != nil {
			failures = append(failures, err.Error())
		}
		if err := restore(configPath, configBefore); err != nil {
			failures = append(failures, err.Error())
		}
		if err := setLink(linkPath, configPath, linkExists); err != nil {
			failures = append(failures, err.Error())
		}
		if err := s.NginxTest(); err != nil {
			failures = append(failures, "rollback nginx test: "+err.Error())
		}
		if len(failures) == 0 {
			if _, err := s.runner().Run(s.systemctlPath(), "reload", "nginx"); err != nil {
				failures = append(failures, "rollback reload: "+err.Error())
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("%w; rollback incomplete: %s", cause, strings.Join(failures, "; "))
		}
		if err := s.clearPending(); err != nil {
			return fmt.Errorf("%w; previous configuration restored but transaction marker remains: %v", cause, err)
		}
		return fmt.Errorf("%w; previous configuration restored", cause)
	}
	if next == nil {
		if err := setLink(linkPath, configPath, false); err != nil {
			return rollback(err)
		}
		if err := removeFile(configPath); err != nil {
			return rollback(err)
		}
		if err := removeFile(statePath); err != nil {
			return rollback(err)
		}
	} else {
		if err := atomicWrite(configPath, newConfig, 0644); err != nil {
			return rollback(err)
		}
		if err := atomicWrite(statePath, newState, 0644); err != nil {
			return rollback(err)
		}
		if err := setLink(linkPath, configPath, next.Enabled); err != nil {
			return rollback(err)
		}
	}
	if err := s.NginxTest(); err != nil {
		return rollback(fmt.Errorf("nginx -t failed: %w", err))
	}
	if _, err := s.runner().Run(s.systemctlPath(), "reload", "nginx"); err != nil {
		return rollback(fmt.Errorf("nginx reload failed: %w", err))
	}
	if err := s.clearPending(); err != nil {
		return rollback(fmt.Errorf("configuration applied but transaction cleanup failed: %w", err))
	}
	return nil
}

func inspectLink(path, expected string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("refusing non-symlink %s", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false, err
	}
	if target != expected {
		return false, fmt.Errorf("refusing unexpected symlink target %s", path)
	}
	return true, nil
}

func setLink(path, target string, enabled bool) error {
	if !enabled {
		return removeFile(path)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".rpctl-link-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (s Store) pretest(config []byte) error {
	dir, err := os.MkdirTemp("", "rpctl-nginx-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "candidate.conf")
	if err := os.WriteFile(file, config, 0600); err != nil {
		return err
	}
	root := filepath.Join(dir, "nginx.conf")
	content := []byte("pid " + filepath.Join(dir, "nginx.pid") + ";\n" +
		"error_log /dev/stderr;\nevents {}\nhttp {\n" +
		"access_log off;\n" +
		"client_body_temp_path " + filepath.Join(dir, "body") + ";\n" +
		"proxy_temp_path " + filepath.Join(dir, "proxy") + ";\n" +
		"fastcgi_temp_path " + filepath.Join(dir, "fastcgi") + ";\n" +
		"uwsgi_temp_path " + filepath.Join(dir, "uwsgi") + ";\n" +
		"scgi_temp_path " + filepath.Join(dir, "scgi") + ";\n" +
		"include " + file + ";\n}\n")
	if err := os.WriteFile(root, content, 0600); err != nil {
		return err
	}
	_, err = s.runner().Run(s.nginxPath(), "-t", "-c", root, "-p", dir)
	return err
}

type transactionManifest struct {
	Domain       string      `json:"domain"`
	StateExists  bool        `json:"state_exists"`
	StateMode    os.FileMode `json:"state_mode"`
	ConfigExists bool        `json:"config_exists"`
	ConfigMode   os.FileMode `json:"config_mode"`
	Enabled      bool        `json:"enabled"`
}

type pendingTransaction struct {
	Archive string `json:"archive"`
}

func (s Store) saveRollback(domain string, state, config snapshot, enabled bool) (string, error) {
	prefix := time.Now().UTC().Format("20060102T150405.000000000") + "-" + configDigest([]byte(domain))[:16] + "-"
	dir, err := os.MkdirTemp(s.RollbackDir, prefix)
	if err != nil {
		return "", err
	}
	archive := filepath.Base(dir)
	if state.exists {
		if err := atomicWrite(filepath.Join(dir, "site.json"), state.data, 0600); err != nil {
			return "", err
		}
	}
	if config.exists {
		if err := atomicWrite(filepath.Join(dir, "site.conf"), config.data, 0600); err != nil {
			return "", err
		}
	}
	manifest, err := json.Marshal(transactionManifest{
		Domain:       domain,
		StateExists:  state.exists,
		StateMode:    state.mode,
		ConfigExists: config.exists,
		ConfigMode:   config.mode,
		Enabled:      enabled,
	})
	if err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(dir, "manifest.json"), append(manifest, '\n'), 0600); err != nil {
		return "", err
	}
	if err := syncDir(s.RollbackDir); err != nil {
		return "", err
	}
	return archive, nil
}

func (s Store) pendingPath() string {
	return filepath.Join(s.RollbackDir, "pending.json")
}

func (s Store) markPending(archive string) error {
	b, err := json.Marshal(pendingTransaction{Archive: archive})
	if err != nil {
		return err
	}
	return atomicWrite(s.pendingPath(), append(b, '\n'), 0600)
}

func (s Store) clearPending() error {
	return removeFile(s.pendingPath())
}

func (s Store) pruneRollbackArchives(keep int) error {
	entries, err := os.ReadDir(s.RollbackDir)
	if err != nil {
		return err
	}
	var archives []string
	for _, entry := range entries {
		if entry.IsDir() && isRollbackArchiveName(entry.Name()) {
			archives = append(archives, entry.Name())
		}
	}
	if len(archives) <= keep {
		return nil
	}
	sort.Strings(archives)
	for _, name := range archives[:len(archives)-keep] {
		if err := os.RemoveAll(filepath.Join(s.RollbackDir, name)); err != nil {
			return err
		}
	}
	return syncDir(s.RollbackDir)
}

func isRollbackArchiveName(name string) bool {
	parts := strings.SplitN(name, "-", 3)
	if len(parts) != 3 || len(parts[1]) != 16 || parts[2] == "" {
		return false
	}
	if _, err := time.Parse("20060102T150405.000000000", parts[0]); err != nil {
		return false
	}
	for _, ch := range parts[1] {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

// recoverPending restores the last complete snapshot after an interrupted
// multi-file update. The caller must hold the store lock.
func (s Store) recoverPending() error {
	b, err := readRegular(s.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending pendingTransaction
	if err := json.Unmarshal(b, &pending); err != nil {
		return fmt.Errorf("invalid pending transaction: %w", err)
	}
	if pending.Archive == "" || filepath.Base(pending.Archive) != pending.Archive || strings.Contains(pending.Archive, "..") {
		return errors.New("invalid pending transaction archive")
	}
	dir := filepath.Join(s.RollbackDir, pending.Archive)
	manifestBytes, err := readRegular(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest transactionManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("invalid transaction manifest: %w", err)
	}
	statePath, configPath, linkPath, err := s.paths(manifest.Domain)
	if err != nil {
		return err
	}
	state := snapshot{exists: manifest.StateExists, mode: manifest.StateMode}
	if state.exists {
		state.data, err = readRegular(filepath.Join(dir, "site.json"))
		if err != nil {
			return err
		}
	}
	config := snapshot{exists: manifest.ConfigExists, mode: manifest.ConfigMode}
	if config.exists {
		config.data, err = readRegular(filepath.Join(dir, "site.conf"))
		if err != nil {
			return err
		}
	}
	if err := restore(statePath, state); err != nil {
		return err
	}
	if err := restore(configPath, config); err != nil {
		return err
	}
	if err := setLink(linkPath, configPath, manifest.Enabled); err != nil {
		return err
	}
	if err := s.NginxTest(); err != nil {
		return fmt.Errorf("restored configuration failed nginx test: %w", err)
	}
	if _, err := s.runner().Run(s.systemctlPath(), "reload", "nginx"); err != nil {
		return fmt.Errorf("reloading restored configuration: %w", err)
	}
	return s.clearPending()
}
