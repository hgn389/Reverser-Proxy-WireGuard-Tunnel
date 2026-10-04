package webpanel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"rpctl/internal/certmgr"
	"rpctl/internal/proxy"
	"rpctl/internal/tailscale"
	"rpctl/internal/wireguard"
	webassets "rpctl/web"
)

type testRunner struct{}

func (testRunner) Run(string, ...string) ([]byte, error) { return nil, nil }

type failingNginxRunner struct{}

func (failingNginxRunner) Run(name string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "-t" {
		return []byte("nginx configuration is invalid"), errors.New("nginx test failed")
	}
	return nil, nil
}

func testStore(t *testing.T) proxy.Store {
	t.Helper()
	base := t.TempDir()
	store := proxy.Store{
		SitesDir:      filepath.Join(base, "sites"),
		AvailableDir:  filepath.Join(base, "available"),
		EnabledDir:    filepath.Join(base, "enabled"),
		RollbackDir:   filepath.Join(base, "rollback"),
		LockPath:      filepath.Join(base, "operation.lock"),
		NginxPath:     "nginx",
		SystemctlPath: "systemctl",
		Runner:        testRunner{},
	}
	for _, dir := range []string{store.SitesDir, store.AvailableDir, store.EnabledDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func testConfig(t *testing.T) Config {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Listen: DefaultListen, Domain: "panel.example.com", Username: "admin", PasswordHash: string(hash), SessionTTL: "30m"}
}

func TestConfigValidation(t *testing.T) {
	valid := testConfig(t)
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	publicOnly := valid
	publicOnly.Listen = PublicListen
	publicOnly.Domain = ""
	publicOnly.PublicAccess = true
	if err := publicOnly.Validate(); err != nil {
		t.Fatalf("valid public-only config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"public bind without switch": func(c *Config) { c.Listen = "0.0.0.0:9080" },
		"public switch on loopback":  func(c *Config) { c.PublicAccess = true },
		"no access method":           func(c *Config) { c.Domain = "" },
		"bad port":                   func(c *Config) { c.Listen = "127.0.0.1:http" },
		"bad domain":                 func(c *Config) { c.Domain = "../panel" },
		"bad username":               func(c *Config) { c.Username = "a" },
		"plain hash":                 func(c *Config) { c.PasswordHash = "password" },
		"long session":               func(c *Config) { c.SessionTTL = "48h" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}

func TestInitialInstallConfigEnablesDirectAccessWithDomain(t *testing.T) {
	config := initialInstallConfig("panel.example.com", "admin")
	if config.Listen != PublicListen || !config.PublicAccess {
		t.Fatalf("new Web Panel must enable direct IP:port access: %+v", config)
	}
	if config.Domain != "panel.example.com" || config.Username != "admin" {
		t.Fatalf("new Web Panel lost installation values: %+v", config)
	}
}

func TestPrivilegedHelperAllowsNginxRuntimeFiles(t *testing.T) {
	if !strings.HasPrefix(sslRenewNginxRuntimeDropIn, "# Managed by rpctl.\n") {
		t.Fatal("SSL renewal drop-in is missing its ownership marker")
	}
	for _, path := range []string{"-/var/log/nginx", "-/run/nginx.pid"} {
		if !strings.Contains(helperServiceUnit, path) {
			t.Fatalf("privileged helper cannot run nginx -t: missing writable path %s", path)
		}
		if !strings.Contains(sslRenewNginxRuntimeDropIn, path) {
			t.Fatalf("SSL renewal cannot reload Nginx: missing writable path %s", path)
		}
	}
	for _, setting := range []string{"UMask=0077", "NoNewPrivileges=true", "PrivateDevices=true", "ProtectSystem=strict", "RestrictSUIDSGID=true"} {
		if !strings.Contains(sslRenewNginxRuntimeDropIn, setting) {
			t.Fatalf("SSL renewal drop-in is missing hardening setting %s", setting)
		}
	}
}

func TestUFWRuleDetectionRequiresExactPort(t *testing.T) {
	status := []byte("Status: active\n\nTo                         Action      From\n--                         ------      ----\n19080/tcp                  ALLOW       Anywhere\n[ 2] 9080/tcp              ALLOW       203.0.113.0/24\n")
	if !ufwHasRule(status, "9080/tcp") {
		t.Fatal("exact Web Panel port rule was not detected")
	}
	if ufwHasRule(status, "80/tcp") {
		t.Fatal("substring of another port was accepted as a rule")
	}
}

func TestDirectHTTPUsesNonSecureCookies(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	loginPage := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9080/login", nil)
	handler.ServeHTTP(loginPage, request)
	csrf := findCookie(t, loginPage.Result().Cookies(), plainLoginCSRFCookie)
	if csrf.Secure {
		t.Fatal("direct HTTP CSRF cookie must not use Secure")
	}
	form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "csrf": {csrf.Value}}
	login := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9080/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrf)
	handler.ServeHTTP(login, request)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	session := findCookie(t, login.Result().Cookies(), plainSessionCookie)
	if session.Secure {
		t.Fatal("direct HTTP session cookie must not use Secure")
	}
}

func TestLoadConfigRejectsTrailingJSON(t *testing.T) {
	config := testConfig(t)
	b, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, append(b, []byte("\n{}")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestPrivilegedRequestValidation(t *testing.T) {
	valid := []PrivilegedRequest{
		{Operation: "proxy_add", Domain: "app.example.com", Upstream: "http://10.77.0.2:80"},
		{Operation: "proxy_delete", Domain: "app.example.com"},
		{Operation: "ssl_issue", Domain: "app.example.com"},
		{Operation: "ssl_renew", Domain: "app.example.com"},
		{Operation: "ssl_status_all"},
		{Operation: "nginx_test"},
		{Operation: "system_restart_nginx"},
		{Operation: "system_reboot"},
		{Operation: "system_update"},
		{Operation: "wg_peer_list"},
		{Operation: "wg_peer_add"},
		{Operation: "wg_peer_add", Peer: "origin-3"},
		{Operation: "wg_peer_delete", Peer: "origin-3"},
		{Operation: "wg_peer_config", Peer: "origin-3"},
	}
	for _, request := range valid {
		if err := request.Validate(); err != nil {
			t.Errorf("valid request %+v: %v", request, err)
		}
	}
	invalid := []PrivilegedRequest{
		{Operation: "shell", Domain: "app.example.com"},
		{Operation: "proxy_add", Domain: "../app", Upstream: "http://10.77.0.2:80"},
		{Operation: "proxy_add", Domain: "app.example.com", Upstream: "10.77.0.2:80"},
		{Operation: "proxy_delete", Domain: "app.example.com", Upstream: "http://10.77.0.2:80"},
		{Operation: "system_reboot", Domain: "app.example.com"},
		{Operation: "ssl_status_all", Domain: "app.example.com"},
		{Operation: "wg_peer_list", Peer: "client2"},
		{Operation: "wg_peer_add", Peer: "../client2"},
		{Operation: "wg_peer_delete"},
		{Operation: "proxy_delete", Domain: "app.example.com", Peer: "client2"},
	}
	for _, request := range invalid {
		if err := request.Validate(); err == nil {
			t.Errorf("invalid request was accepted: %+v", request)
		}
	}
}

func TestServePrivilegedOnceProxyAdd(t *testing.T) {
	store := testStore(t)
	request := `{"operation":"proxy_add","domain":"app.example.com","upstream":"http://10.77.0.2:80"}`
	var output bytes.Buffer
	if err := ServePrivilegedOnce(strings.NewReader(request), &output, store, certmgr.Manager{}); err != nil {
		t.Fatal(err)
	}
	var response privilegedResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("helper response: %+v", response)
	}
	site, err := store.Show("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if site.Upstream != "http://10.77.0.2:80" {
		t.Fatalf("unexpected site: %+v", site)
	}
}

func TestServePrivilegedOnceSSLStatusAll(t *testing.T) {
	store := testStore(t)
	var output bytes.Buffer
	request := `{"operation":"ssl_status_all"}`
	if err := ServePrivilegedOnce(strings.NewReader(request), &output, store, certmgr.Manager{Store: store}); err != nil {
		t.Fatal(err)
	}
	var response privilegedResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Data != "[]" {
		t.Fatalf("unexpected helper response: %+v", response)
	}
}

type recordingClient struct {
	requests []PrivilegedRequest
	err      error
	data     map[string]string
}

type recordingSystemManager struct {
	restarts int
	reboots  int
}

func (m *recordingSystemManager) RestartNginx() error {
	m.restarts++
	return nil
}

func (m *recordingSystemManager) ScheduleReboot() error {
	m.reboots++
	return nil
}

func TestServePrivilegedOnceSystemOperations(t *testing.T) {
	system := &recordingSystemManager{}
	for _, operation := range []string{"system_restart_nginx", "system_reboot"} {
		var output bytes.Buffer
		request := `{"operation":"` + operation + `"}`
		if err := servePrivilegedOnce(strings.NewReader(request), &output, testStore(t), certmgr.Manager{}, system); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		var response privilegedResponse
		if err := json.Unmarshal(output.Bytes(), &response); err != nil || !response.OK {
			t.Fatalf("%s response=%+v err=%v", operation, response, err)
		}
	}
	if system.restarts != 1 || system.reboots != 1 {
		t.Fatalf("unexpected system calls: %+v", system)
	}
}

func TestRestartNginxStopsWhenConfigTestFails(t *testing.T) {
	store := testStore(t)
	store.Runner = failingNginxRunner{}
	system := &recordingSystemManager{}
	var output bytes.Buffer
	err := servePrivilegedOnce(strings.NewReader(`{"operation":"system_restart_nginx"}`), &output, store, certmgr.Manager{}, system)
	if err == nil {
		t.Fatal("restart succeeded after nginx test failure")
	}
	if system.restarts != 0 {
		t.Fatalf("Nginx was restarted %d time(s) after a failed test", system.restarts)
	}
	var response privilegedResponse
	if decodeErr := json.Unmarshal(output.Bytes(), &response); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if response.OK || response.Error == "" {
		t.Fatalf("unexpected helper response: %+v", response)
	}
}

func TestPrivilegedProtocolRespondsBeforeClientCloses(t *testing.T) {
	system := &recordingSystemManager{}
	store := testStore(t)
	serverConnection, clientConnection := net.Pipe()
	defer clientConnection.Close()
	done := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		done <- servePrivilegedOnce(serverConnection, serverConnection, store, certmgr.Manager{}, system)
	}()
	if err := json.NewEncoder(clientConnection).Encode(PrivilegedRequest{Operation: "system_restart_nginx"}); err != nil {
		t.Fatal(err)
	}
	if err := clientConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var response privilegedResponse
	if err := json.NewDecoder(clientConnection).Decode(&response); err != nil {
		t.Fatalf("helper did not respond while the client connection remained open: %v", err)
	}
	if !response.OK || system.restarts != 1 {
		t.Fatalf("response=%+v system=%+v", response, system)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func (c *recordingClient) Execute(request PrivilegedRequest) error {
	c.requests = append(c.requests, request)
	return c.err
}

func (c *recordingClient) ExecuteData(request PrivilegedRequest) (string, error) {
	c.requests = append(c.requests, request)
	if c.err != nil {
		return "", c.err
	}
	if value, ok := c.data[request.Operation]; ok {
		return value, nil
	}
	switch request.Operation {
	case "ssl_status_all":
		return "[]", nil
	case "wg_peer_list":
		return "[]", nil
	case "wg_peer_add":
		return `{"name":"client2","address":"10.77.0.3/32","public_key":"public","config_path":"/etc/rpctl/wireguard/peers/client2.conf"}`, nil
	case "wg_peer_config":
		return "[Interface]\nAddress = 10.77.0.3/32\n", nil
	default:
		return "", nil
	}
}

func TestLoginSessionAndCSRF(t *testing.T) {
	client := &recordingClient{}
	server, err := NewServer(testConfig(t), "test", testStore(t), client)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}

	loginPage := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://panel.example.com/login", nil)
	handler.ServeHTTP(loginPage, request)
	if loginPage.Code != http.StatusOK {
		t.Fatalf("login page status = %d", loginPage.Code)
	}
	loginCSRF := findCookie(t, loginPage.Result().Cookies(), loginCSRFCookie)

	form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "csrf": {loginCSRF.Value}}
	login := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://panel.example.com/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(loginCSRF)
	handler.ServeHTTP(login, request)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body=%s", login.Code, login.Body.String())
	}
	sessionCookieValue := findCookie(t, login.Result().Cookies(), sessionCookie)
	server.sessionsMu.Lock()
	current, ok := server.sessions[sessionCookieValue.Value]
	server.sessionsMu.Unlock()
	if !ok {
		t.Fatal("session was not recorded")
	}

	dashboard := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://panel.example.com/", nil)
	request.AddCookie(sessionCookieValue)
	handler.ServeHTTP(dashboard, request)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "Reverse proxies") {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}
	guide := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://panel.example.com/guide", nil)
	request.AddCookie(sessionCookieValue)
	handler.ServeHTTP(guide, request)
	if guide.Code != http.StatusOK || !strings.Contains(guide.Body.String(), "VPS-N") {
		t.Fatalf("guide status=%d body=%s", guide.Code, guide.Body.String())
	}
	if !strings.Contains(guide.Body.String(), "Configuration Guide") || !strings.Contains(guide.Body.String(), "VPS-2 or Orange Pi") || !strings.Contains(guide.Body.String(), "Connect a Windows Computer") || !strings.Contains(guide.Body.String(), "iPhone, iPad, or Android") {
		t.Fatalf("guide is missing English content: %s", guide.Body.String())
	}

	badAction := httptest.NewRecorder()
	request = formRequest("https://panel.example.com/system/nginx-restart", url.Values{"csrf": {"wrong"}}, sessionCookieValue)
	handler.ServeHTTP(badAction, request)
	if badAction.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status = %d", badAction.Code)
	}

	goodAction := httptest.NewRecorder()
	request = formRequest("https://panel.example.com/system/nginx-restart", url.Values{"csrf": {current.CSRF}}, sessionCookieValue)
	handler.ServeHTTP(goodAction, request)
	if goodAction.Code != http.StatusSeeOther {
		t.Fatalf("valid action status = %d body=%s", goodAction.Code, goodAction.Body.String())
	}
	reboot := httptest.NewRecorder()
	request = formRequest("https://panel.example.com/system/reboot", url.Values{"csrf": {current.CSRF}}, sessionCookieValue)
	handler.ServeHTTP(reboot, request)
	if reboot.Code != http.StatusSeeOther {
		t.Fatalf("reboot action status = %d body=%s", reboot.Code, reboot.Body.String())
	}
	renew := httptest.NewRecorder()
	request = formRequest("https://panel.example.com/ssl/renew", url.Values{"csrf": {current.CSRF}, "domain": {"app.example.com"}}, sessionCookieValue)
	handler.ServeHTTP(renew, request)
	if renew.Code != http.StatusSeeOther {
		t.Fatalf("SSL renew status = %d body=%s", renew.Code, renew.Body.String())
	}
	if len(client.requests) != 5 || client.requests[0].Operation != "wg_peer_list" || client.requests[1].Operation != "ssl_status_all" || client.requests[2].Operation != "system_restart_nginx" || client.requests[3].Operation != "system_reboot" || client.requests[4].Operation != "ssl_renew" {
		t.Fatalf("unexpected privileged requests: %+v", client.requests)
	}
}

func TestLoginRateLimit(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	server.attempts["192.0.2.1"] = loginAttempt{Failures: 5, ResetAt: time.Now().Add(time.Minute)}
	if !server.loginBlocked("192.0.2.1") {
		t.Fatal("five failed attempts were not blocked")
	}
}

func TestInvalidHostIsRejected(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://attacker.example/login", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("invalid host status = %d", response.Code)
	}
}

func TestDashboardSSLControlsAndResponsiveAssets(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	err = server.templates.ExecuteTemplate(&rendered, "dashboard.html", dashboardData{
		Version:     "test",
		PanelDomain: "panel.example.com",
		PublicURL:   "http://203.0.113.1:9080",
		CSRF:        "token",
		Sites: []dashboardSite{
			{Site: proxy.Site{Domain: "plain.example.com", Upstream: "http://10.77.0.2:80", Enabled: true}, SSLDays: "—", SSLDaysClass: "muted"},
			{Site: proxy.Site{Domain: "secure.example.com", Upstream: "http://10.77.0.3:80", Enabled: true, SSLEnabled: true}, SSLDays: "45 days", SSLExpiry: "2026-11-16", SSLDaysClass: "healthy"},
			{Site: proxy.Site{Domain: "panel.example.com", Upstream: "http://127.0.0.1:9080", Enabled: true, SSLEnabled: true}, SSLDays: "12 days", SSLExpiry: "2026-10-14", SSLDaysClass: "warning"},
		},
		Peers:   []wireguard.Peer{{Name: "client2", Address: "10.77.0.3/32", ConfigPath: "/etc/rpctl/wireguard/peers/client2.conf"}},
		Metrics: systemMetrics{ServerIP: "203.0.113.1", VPNIP: "10.77.0.1", CPU: "1 vCPU", RAM: "128 / 512 MB used", Swap: "1.0 GB", SSD: "5.0 / 20.0 GB used"},
	})
	if err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	for _, expected := range []string{"/ssl/issue", "/ssl/renew", "Issue certificate", "Renew certificate", "45 days", "Expires 2026-11-16", "12 days", "class=\"proxy-table\"", "class=\"ssl-content\"", "class=\"actions-content\"", "Reverse Proxy &amp; VPN Tunnel", "Configuration Guide", "https://github.com/hgn389/Reverser-Proxy-WireGuard-Tunnel", "rpctl vtest", "Nam Hoàng", "203.0.113.1", "10.77.0.1", "1 vCPU", "128 / 512 MB used", "1.0 GB", "5.0 / 20.0 GB used", "Webpanel Dashboard", "http://203.0.113.1:9080", "/system/nginx-restart", "/system/update", "/system/reboot", "/wireguard/peer/add", "/wireguard/peer/download", "/wireguard/peer/delete", "WireGuard peers - Add a device", "the name of the newly added device", "the private VPN IP address that VPS-1 assigns", "Setup guide", "Use the QR code to connect a mobile device quickly", "shop.example.com", "10.10.10.25:80", "10.10.10.212:3000", "the public hostname that visitors use", "The website or application must already be running", "use the <strong>Reverse proxies</strong> section", "data-qr-peer=\"client2\"", "View QR", "wireguard-qr-dialog", "/static/app.js", "client2", "10.77.0.3/32", "/static/favicon.svg"} {
		if !strings.Contains(html, expected) {
			t.Errorf("dashboard is missing %q", expected)
		}
	}
	if strings.Contains(html, "/wireguard/peer/qr?peer=client2") {
		t.Fatal("dashboard eagerly loads a peer QR code")
	}
	if strings.Index(html, "<th>QR</th>") > strings.Index(html, "<th>Client configuration</th>") {
		t.Fatal("QR column must appear before Client configuration")
	}
	if strings.Contains(html, ">Days<") || strings.Contains(html, ">enabled</span>") {
		t.Fatal("dashboard still renders a separate Days column or redundant SSL enabled label")
	}
	css, err := fs.ReadFile(webassets.Files, "static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"max-width: 1680px", "@media (max-width: 760px)", ".proxy-table { min-width: 1040px; }", ".peer-table { min-width: 860px; table-layout: fixed; }", ".peer-config-column { width: 34%; }", ".peer-help, .proxy-help { color: #6e7681; font-size: 11px; text-align: left; }", ".peer-help ul, .proxy-help ul { display: block;", ".qr-dialog::backdrop", "width: clamp(170px, 18vw, 260px)", "flex-wrap: nowrap", "height: 2.6rem"} {
		if !strings.Contains(string(css), expected) {
			t.Errorf("responsive stylesheet is missing %q", expected)
		}
	}
	javascript, err := fs.ReadFile(webassets.Files, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"encodeURIComponent(peer)", "/wireguard/peer/qr?peer=", "dialog.showModal()", "image.removeAttribute(\"src\")"} {
		if !strings.Contains(string(javascript), expected) {
			t.Errorf("QR dialog script is missing %q", expected)
		}
	}
	favicon, err := fs.ReadFile(webassets.Files, "static/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(favicon), "#d1242f") || !strings.Contains(string(favicon), "aria-label=\"Red lock\"") {
		t.Fatal("red lock favicon is missing its expected shape or color")
	}
}

func TestDashboardTailscaleModeAndUpdateNotification(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	err = server.templates.ExecuteTemplate(&rendered, "dashboard.html", dashboardData{
		Version: "test",
		CSRF:    "session-token",
		VPNMode: "tailscale",
		Tailscale: tailscale.Status{
			BackendState: "Running",
			Tailnet:      "example.com",
			Self:         tailscale.Device{Name: "vps-1", IPs: []string{"100.64.0.1"}, Online: true},
			Peers:        []tailscale.Device{{Name: "iphone", DNSName: "iphone.example.ts.net", IPs: []string{"100.64.0.2"}, OS: "iOS", Online: true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	for _, expected := range []string{"Tailscale network", "example.com", "100.64.0.1", "iphone", "100.64.0.2", "Open Admin Console", "update-banner", "Update now!", "id=\"version-check\"", "title=\"Check for updates\"", "id=\"version-check-status\""} {
		if !strings.Contains(html, expected) {
			t.Errorf("Tailscale dashboard is missing %q", expected)
		}
	}
	for _, unexpected := range []string{"WireGuard peers - Add a device", "/wireguard/peer/add", "wireguard-qr-dialog"} {
		if strings.Contains(html, unexpected) {
			t.Errorf("Tailscale dashboard contains WireGuard control %q", unexpected)
		}
	}
	javascript, err := fs.ReadFile(webassets.Files, "static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"/system/update-status", "/system/update-status?refresh=1", "60 * 60 * 1000", "sessionStorage", "checked_at", "Checking for updates...", "is up to date.", "Update check failed. Try again.", `versionCheck.addEventListener("click"`} {
		if !strings.Contains(string(javascript), expected) {
			t.Errorf("update notification script is missing %q", expected)
		}
	}
}

func TestBuildDashboardSitesFormatsCertificateDays(t *testing.T) {
	now := time.Now()
	sites := []proxy.Site{
		{Domain: "plain.example.com"},
		{Domain: "healthy.example.com", SSLEnabled: true},
		{Domain: "warning.example.com", SSLEnabled: true},
		{Domain: "expired.example.com", SSLEnabled: true},
	}
	statuses := []certificateStatus{
		{Domain: "healthy.example.com", Enabled: true, Issued: true, NotAfter: now.Add(60 * 24 * time.Hour), DaysLeft: 60},
		{Domain: "warning.example.com", Enabled: true, Issued: true, NotAfter: now.Add(10 * 24 * time.Hour), DaysLeft: 10},
		{Domain: "expired.example.com", Enabled: true, Issued: true, NotAfter: now.Add(-time.Hour), DaysLeft: 0},
	}
	rows := buildDashboardSites(sites, statuses, "")
	if len(rows) != 4 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].SSLDays != "—" || rows[0].SSLDaysClass != "muted" {
		t.Fatalf("plain row: %+v", rows[0])
	}
	if rows[1].SSLDays != "60 days" || rows[1].SSLDaysClass != "healthy" {
		t.Fatalf("healthy row: %+v", rows[1])
	}
	if rows[2].SSLDays != "10 days" || rows[2].SSLDaysClass != "warning" {
		t.Fatalf("warning row: %+v", rows[2])
	}
	if rows[3].SSLDays != "Expired" || rows[3].SSLDaysClass != "expired" {
		t.Fatalf("expired row: %+v", rows[3])
	}
}

func TestWireGuardPeerWebActions(t *testing.T) {
	client := &recordingClient{}
	server, err := NewServer(testConfig(t), "test", testStore(t), client)
	if err != nil {
		t.Fatal(err)
	}

	add := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/add", strings.NewReader(url.Values{"peer": {"client2"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.wgPeerAdd(add, request)
	if add.Code != http.StatusSeeOther || len(client.requests) != 1 || client.requests[0].Operation != "wg_peer_add" {
		t.Fatalf("add status=%d requests=%+v", add.Code, client.requests)
	}

	download := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/download", strings.NewReader(url.Values{"peer": {"client2"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.wgPeerDownload(download, request)
	if download.Code != http.StatusOK || !strings.Contains(download.Header().Get("Content-Disposition"), "client2.conf") || !strings.Contains(download.Body.String(), "10.77.0.3/32") {
		t.Fatalf("download status=%d headers=%v body=%s", download.Code, download.Header(), download.Body.String())
	}

	qr := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://panel.example.com/wireguard/peer/qr?peer=client2", nil)
	server.wgPeerQR(qr, request)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(qr.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("QR status=%d headers=%v", qr.Code, qr.Header())
	}

	remove := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/delete", strings.NewReader(url.Values{"peer": {"client2"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.wgPeerDelete(remove, request)
	if remove.Code != http.StatusSeeOther || client.requests[len(client.requests)-1].Operation != "wg_peer_delete" {
		t.Fatalf("delete status=%d requests=%+v", remove.Code, client.requests)
	}
}

func TestIPBlockStoreLifecycleAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	store := IPBlockStore{Path: filepath.Join(dir, "blocked.json")}
	var group sync.WaitGroup
	for index := 1; index <= 20; index++ {
		group.Add(1)
		go func(lastOctet int) {
			defer group.Done()
			if err := store.Block("192.0.2."+strconv.Itoa(lastOctet), 5); err != nil {
				t.Errorf("Block: %v", err)
			}
		}(index)
	}
	group.Wait()
	blocked, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 20 {
		t.Fatalf("blocked count = %d", len(blocked))
	}
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("blocked state mode = %o", info.Mode().Perm())
	}
	removed, err := store.Unblock("192.0.2.10")
	if err != nil || !removed {
		t.Fatalf("Unblock removed=%v err=%v", removed, err)
	}
	if blocked, err := store.IsBlocked("192.0.2.10"); err != nil || blocked {
		t.Fatalf("address remains blocked=%v err=%v", blocked, err)
	}
	count, err := store.UnblockAll()
	if err != nil || count != 19 {
		t.Fatalf("UnblockAll count=%d err=%v", count, err)
	}
}

func TestIPBlockStoreRejectsSymlinkLock(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("do not touch"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "blocked.json")
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := (IPBlockStore{Path: path}).List(); err == nil {
		t.Fatal("symlink lock was accepted")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "do not touch" {
		t.Fatal("symlink target was modified")
	}
}

func TestFiveFailedLoginsPersistBlockAndUnblock(t *testing.T) {
	server, err := NewServer(testConfig(t), "test", testStore(t), &recordingClient{})
	if err != nil {
		t.Fatal(err)
	}
	server.blocks = IPBlockStore{Path: filepath.Join(t.TempDir(), "blocked.json")}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	const source = "198.51.100.20:4321"
	for attempt := 1; attempt <= 5; attempt++ {
		page := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://panel.example.com/login", nil)
		request.RemoteAddr = source
		handler.ServeHTTP(page, request)
		csrfCookie := findCookie(t, page.Result().Cookies(), loginCSRFCookie)
		form := url.Values{"username": {"admin"}, "password": {"wrong password"}, "csrf": {csrfCookie.Value}}
		response := httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodPost, "https://panel.example.com/login", strings.NewReader(form.Encode()))
		request.RemoteAddr = source
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(csrfCookie)
		handler.ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if attempt == 5 {
			want = http.StatusForbidden
		}
		if response.Code != want {
			t.Fatalf("attempt %d status=%d, want %d", attempt, response.Code, want)
		}
		if attempt < 5 && response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("attempt %d returned a non-HTML login page: %q", attempt, response.Header().Get("Content-Type"))
		}
	}
	if blocked, err := server.blocks.IsBlocked("198.51.100.20"); err != nil || !blocked {
		t.Fatalf("persisted block=%v err=%v", blocked, err)
	}
	if removed, err := server.blocks.Unblock("198.51.100.20"); err != nil || !removed {
		t.Fatalf("unblock removed=%v err=%v", removed, err)
	}

	page := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://panel.example.com/login", nil)
	request.RemoteAddr = source
	handler.ServeHTTP(page, request)
	csrfCookie := findCookie(t, page.Result().Cookies(), loginCSRFCookie)
	form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}, "csrf": {csrfCookie.Value}}
	response := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://panel.example.com/login", strings.NewReader(form.Encode()))
	request.RemoteAddr = source
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("login after unblock status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestClientIPTrustsCloudflareOnlyFromCloudflare(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://panel.example.com/login", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Real-IP", "104.16.1.2")
	request.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := clientIP(request); got != "203.0.113.9" {
		t.Fatalf("Cloudflare client IP = %q", got)
	}

	request.Header.Set("X-Real-IP", "198.51.100.8")
	request.Header.Set("CF-Connecting-IP", "203.0.113.10")
	if got := clientIP(request); got != "198.51.100.8" {
		t.Fatalf("spoofed Cloudflare header was trusted: %q", got)
	}

	request.RemoteAddr = "198.51.100.11:1234"
	request.Header.Set("X-Real-IP", "104.16.1.2")
	if got := clientIP(request); got != "198.51.100.11" {
		t.Fatalf("proxy headers from a direct client were trusted: %q", got)
	}
}

func formRequest(target string, form url.Values, cookie *http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	return request
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %s not found", name)
	return nil
}

func TestSocketClientRejectsInvalidRequestBeforeDial(t *testing.T) {
	client := SocketClient{Path: filepath.Join(t.TempDir(), "missing.sock")}
	err := client.Execute(PrivilegedRequest{Operation: "proxy_add", Domain: "bad/domain", Upstream: "http://10.77.0.2:80"})
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected error: %v", err)
	}
}
