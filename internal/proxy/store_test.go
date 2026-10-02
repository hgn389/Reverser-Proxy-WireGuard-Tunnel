package proxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls          []string
	failReloadOnce bool
	failLiveTestAt int
	liveTests      int
	nginxTestOut   string
	nginxTestOutAt int
}

func (r *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if name == "systemctl" && r.failReloadOnce {
		r.failReloadOnce = false
		return nil, errors.New("reload failed")
	}
	if call == "nginx -t" {
		r.liveTests++
		if r.liveTests == r.failLiveTestAt {
			return nil, errors.New("invalid combined config")
		}
		if r.nginxTestOutAt == 0 || r.liveTests == r.nginxTestOutAt {
			return []byte(r.nginxTestOut), nil
		}
		return nil, nil
	}
	return nil, nil
}

func testStore(t *testing.T, runner Runner) Store {
	t.Helper()
	base := t.TempDir()
	s := Store{
		SitesDir:      filepath.Join(base, "sites"),
		AvailableDir:  filepath.Join(base, "available"),
		EnabledDir:    filepath.Join(base, "enabled"),
		RollbackDir:   filepath.Join(base, "rollback"),
		LockPath:      filepath.Join(base, "rpctl.lock"),
		NginxPath:     "nginx",
		SystemctlPath: "systemctl",
		Runner:        runner,
	}
	for _, dir := range []string{s.SitesDir, s.AvailableDir, s.EnabledDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestAddAndDisable(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://203.0.113.10:8080"}); err != nil {
		t.Fatal(err)
	}
	state, conf, link, _ := s.paths("app.example.com")
	info, err := os.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("site state mode = %o, want 644", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(s.SitesDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Fatalf("sites directory mode = %o, want 755", dirInfo.Mode().Perm())
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled("app.example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("link still exists: %v", err)
	}
	if _, err := os.Stat(conf); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("app.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Show("app.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("site still exists: %v", err)
	}
}

func TestSetSSLUpdatesCanonicalState(t *testing.T) {
	s := testStore(t, &fakeRunner{})
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSSL("app.example.com", true); err != nil {
		t.Fatal(err)
	}
	site, err := s.Show("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !site.SSLEnabled || !site.HTTPSRedirect {
		t.Fatalf("SSL state was not enabled: %+v", site)
	}
	if err := s.SetSSL("app.example.com", false); err != nil {
		t.Fatal(err)
	}
	site, err = s.Show("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if site.SSLEnabled || site.HTTPSRedirect {
		t.Fatalf("SSL state was not disabled: %+v", site)
	}
}

func TestListSorted(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	for _, domain := range []string{"z.example.com", "a.example.com"} {
		if err := s.Add(Site{Domain: domain, Upstream: "http://127.0.0.1:8080"}); err != nil {
			t.Fatal(err)
		}
	}
	sites, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 || sites[0].Domain != "a.example.com" || sites[1].Domain != "z.example.com" {
		t.Fatalf("unexpected site order: %+v", sites)
	}
}

func TestMaximumLengthDomainUsesSafeFilenames(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(domain) != 253 {
		t.Fatalf("test domain length = %d", len(domain))
	}
	if err := s.Add(Site{Domain: domain, Upstream: "http://127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	state, config, link, err := s.paths(domain)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{state, config, link} {
		if len(filepath.Base(path)) > 255 {
			t.Fatalf("unsafe filename length %d: %s", len(filepath.Base(path)), path)
		}
	}
	sites, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Domain != domain {
		t.Fatalf("long domain was not listed: %+v", sites)
	}
}

func TestRollbackArchivesArePruned(t *testing.T) {
	s := testStore(t, &fakeRunner{})
	if err := os.MkdirAll(s.RollbackDir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxRollbackArchives+5; i++ {
		name := "20260101T000000." + fmt.Sprintf("%09d", i) + "-0123456789abcdef-test"
		if err := os.Mkdir(filepath.Join(s.RollbackDir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(s.RollbackDir, "keep-this-directory")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.pruneRollbackArchives(maxRollbackArchives); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.RollbackDir)
	if err != nil {
		t.Fatal(err)
	}
	archives := 0
	for _, entry := range entries {
		if isRollbackArchiveName(entry.Name()) {
			archives++
		}
	}
	if archives != maxRollbackArchives {
		t.Fatalf("rollback archive count = %d, want %d", archives, maxRollbackArchives)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown directory was removed: %v", err)
	}
}

func TestReloadFailureRestoresPriorSite(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://203.0.113.10:8080"}); err != nil {
		t.Fatal(err)
	}
	state, conf, link, _ := s.paths("app.example.com")
	beforeState, _ := os.ReadFile(state)
	beforeConf, _ := os.ReadFile(conf)
	r.failReloadOnce = true
	if err := s.Update("app.example.com", "http://other.example.com:9000"); err == nil {
		t.Fatal("expected reload error")
	}
	afterState, _ := os.ReadFile(state)
	afterConf, _ := os.ReadFile(conf)
	if string(beforeState) != string(afterState) || string(beforeConf) != string(afterConf) {
		t.Fatal("prior files were not restored")
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatal("enabled link not restored:", err)
	}
}

func TestNginxTestFailureRestoresNewSite(t *testing.T) {
	r := &fakeRunner{failLiveTestAt: 2}
	s := testStore(t, r)
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("expected combined config test failure")
	}
	state, conf, link, _ := s.paths("app.example.com")
	for _, path := range []string{state, conf, link} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
}

func TestNginxConflictWarningStopsChange(t *testing.T) {
	r := &fakeRunner{
		nginxTestOut:   `nginx: [warn] conflicting server name "app.example.com" on 0.0.0.0:80, ignored`,
		nginxTestOutAt: 2,
	}
	s := testStore(t, r)
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("accepted a conflicting Nginx server name")
	}
	state, conf, link, _ := s.paths("app.example.com")
	for _, path := range []string{state, conf, link} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after rejected conflict: %v", path, err)
		}
	}
}

func TestRejectUnmanagedConfig(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	_, conf, _, _ := s.paths("app.example.com")
	if err := os.WriteFile(conf, []byte("# user config\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("overwrote unmanaged config")
	}
	b, _ := os.ReadFile(conf)
	if string(b) != "# user config\n" {
		t.Fatal("unmanaged file changed")
	}
}

func TestRejectManualChangeToManagedConfig(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	if err := s.Add(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	_, conf, _, _ := s.paths("app.example.com")
	if err := os.WriteFile(conf, []byte("# Managed by rpctl.\n# manually edited\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Update("app.example.com", "http://127.0.0.1:9000"); err == nil {
		t.Fatal("overwrote manually edited config")
	}
}

func TestCandidateWithRealNginx(t *testing.T) {
	nginxPath, err := exec.LookPath("nginx")
	if err != nil {
		t.Skip("nginx is not available")
	}
	config, err := Render(Site{Domain: "app.example.com", Upstream: "https://203.0.113.10:443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (Store{Runner: CommandRunner{}, NginxPath: nginxPath}).pretest(config); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverInterruptedTransaction(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	want := Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080", Enabled: true}
	if err := s.Add(want); err != nil {
		t.Fatal(err)
	}
	want, err := s.Show(want.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if want.ConfigSHA256 == "" {
		t.Fatal("site state does not contain a config digest")
	}
	statePath, configPath, linkPath, _ := s.paths(want.Domain)
	stateBefore, err := takeSnapshot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, err := takeSnapshot(configPath)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := s.saveRollback(want.Domain, stateBefore, configBefore, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.markPending(archive); err != nil {
		t.Fatal(err)
	}
	changed := Site{Domain: want.Domain, Upstream: "http://127.0.0.1:9000", Enabled: false}
	changedState, _ := Encode(changed)
	changedConfig, _ := Render(changed)
	if err := atomicWrite(statePath, changedState, 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(configPath, changedConfig, 0644); err != nil {
		t.Fatal(err)
	}
	if err := setLink(linkPath, configPath, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(); err != nil {
		t.Fatal(err)
	}
	got, err := s.Show(want.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("recovered site = %+v, want %+v", got, want)
	}
	if _, err := os.Readlink(linkPath); err != nil {
		t.Fatalf("enabled symlink was not restored: %v", err)
	}
	if _, err := os.Stat(s.pendingPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending marker remains: %v", err)
	}
}

func TestLegacyConfigMigratesToDigest(t *testing.T) {
	r := &fakeRunner{}
	s := testStore(t, r)
	legacySite := Site{Domain: "app.example.com", Upstream: "https://203.0.113.10:443", Enabled: true}
	state, err := Encode(legacySite)
	if err != nil {
		t.Fatal(err)
	}
	config, err := renderLegacyV1(legacySite)
	if err != nil {
		t.Fatal(err)
	}
	statePath, configPath, linkPath, _ := s.paths(legacySite.Domain)
	if err := atomicWrite(statePath, state, 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(configPath, config, 0644); err != nil {
		t.Fatal(err)
	}
	if err := setLink(linkPath, configPath, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEnabled(legacySite.Domain, false); err != nil {
		t.Fatal(err)
	}
	migrated, err := s.Show(legacySite.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.ConfigSHA256 == "" {
		t.Fatal("legacy state was not migrated to a config digest")
	}
}
