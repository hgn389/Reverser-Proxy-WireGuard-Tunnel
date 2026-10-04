package webpanel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"rpctl/internal/proxy"
	"rpctl/internal/tailscale"
	"rpctl/internal/updater"
	"rpctl/internal/vpnmode"
	"rpctl/internal/wireguard"
	webassets "rpctl/web"
)

const (
	sessionCookie        = "__Host-rpctl_session"
	plainSessionCookie   = "rpctl_session"
	loginCSRFCookie      = "__Host-rpctl_login_csrf"
	plainLoginCSRFCookie = "rpctl_login_csrf"
	maxFormSize          = 64 << 10
)

type session struct {
	CSRF    string
	Expires time.Time
}

type loginAttempt struct {
	Failures int
	ResetAt  time.Time
}

type Server struct {
	config     Config
	version    string
	store      proxy.Store
	privileged PrivilegedClient
	templates  *template.Template
	sessionsMu sync.Mutex
	sessions   map[string]session
	attemptsMu sync.Mutex
	attempts   map[string]loginAttempt
	blocks     IPBlockStore
	loginSlots chan struct{}
	updateMu   sync.Mutex
	updateInfo updater.Status
	updateErr  string
	updateTime time.Time
}

type dashboardData struct {
	Version        string
	PanelDomain    string
	PublicURL      string
	CSRF           string
	Message        string
	Sites          []dashboardSite
	Peers          []wireguard.Peer
	PeerError      string
	VPNMode        string
	Tailscale      tailscale.Status
	TailscaleError string
	Metrics        systemMetrics
}

type dashboardSite struct {
	proxy.Site
	SSLDays      string
	SSLExpiry    string
	SSLDaysClass string
	SSLError     string
}

type loginData struct {
	Version string
	CSRF    string
	Error   string
}

type guideData struct {
	Version string
	CSRF    string
	VPNMode string
}

type systemMetrics struct {
	ServerIP string
	VPNIP    string
	CPU      string
	RAM      string
	SSD      string
	Swap     string
	Uptime   string
}

func NewServer(config Config, version string, store proxy.Store, privileged PrivilegedClient) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if privileged == nil {
		return nil, errors.New("privileged client is required")
	}
	templates, err := template.ParseFS(webassets.Files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		config:     config,
		version:    version,
		store:      store,
		privileged: privileged,
		templates:  templates,
		sessions:   make(map[string]session),
		attempts:   make(map[string]loginAttempt),
		blocks:     DefaultIPBlockStore(),
		loginSlots: make(chan struct{}, 1),
	}, nil
}

func (s *Server) Run() error {
	handler, err := s.Handler()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              s.config.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("INFO web panel listening on %s", s.config.Listen)
	go s.updateCheckLoop()
	return server.ListenAndServe()
}

func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	staticFS, err := fs.Sub(webassets.Files, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.Handle("GET /", s.auth(http.HandlerFunc(s.dashboard)))
	mux.Handle("GET /guide", s.auth(http.HandlerFunc(s.guide)))
	mux.Handle("POST /logout", s.auth(s.csrf(http.HandlerFunc(s.logout))))
	mux.Handle("POST /proxy/add", s.auth(s.csrf(http.HandlerFunc(s.proxyAdd))))
	mux.Handle("POST /proxy/edit", s.auth(s.csrf(http.HandlerFunc(s.proxyEdit))))
	mux.Handle("POST /proxy/enable", s.auth(s.csrf(http.HandlerFunc(s.proxyEnable))))
	mux.Handle("POST /proxy/disable", s.auth(s.csrf(http.HandlerFunc(s.proxyDisable))))
	mux.Handle("POST /proxy/delete", s.auth(s.csrf(http.HandlerFunc(s.proxyDelete))))
	mux.Handle("POST /ssl/issue", s.auth(s.csrf(http.HandlerFunc(s.sslIssue))))
	mux.Handle("POST /ssl/renew", s.auth(s.csrf(http.HandlerFunc(s.sslRenew))))
	mux.Handle("POST /wireguard/peer/add", s.auth(s.csrf(http.HandlerFunc(s.wgPeerAdd))))
	mux.Handle("POST /wireguard/peer/delete", s.auth(s.csrf(http.HandlerFunc(s.wgPeerDelete))))
	mux.Handle("POST /wireguard/peer/download", s.auth(s.csrf(http.HandlerFunc(s.wgPeerDownload))))
	mux.Handle("GET /wireguard/peer/qr", s.auth(http.HandlerFunc(s.wgPeerQR)))
	mux.Handle("POST /system/nginx-restart", s.auth(s.csrf(http.HandlerFunc(s.nginxRestart))))
	mux.Handle("POST /system/update", s.auth(s.csrf(http.HandlerFunc(s.systemUpdate))))
	mux.Handle("GET /system/update-status", s.auth(http.HandlerFunc(s.systemUpdateStatus)))
	mux.Handle("POST /system/reboot", s.auth(s.csrf(http.HandlerFunc(s.systemReboot))))

	return s.securityHeaders(s.validHost(mux)), nil
}

func (s *Server) validHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = strings.Trim(parsed, "[]")
		}
		allowed := host == "127.0.0.1" || host == "::1" || (s.config.Domain != "" && host == s.config.Domain)
		if !allowed && s.config.PublicAccess {
			allowed = isAssignedInterfaceIP(host)
		}
		if !allowed {
			http.Error(w, "invalid host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cookieName, secure := loginCookieForRequest(r)
	http.SetCookie(w, authCookie(cookieName, token, 10*time.Minute, secure))
	s.render(w, "login.html", loginData{Version: s.version, CSRF: token})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	sourceIP := clientIP(r)
	blocked, err := s.blocks.IsBlocked(sourceIP)
	if err != nil {
		log.Printf("ERROR reading blocked IP state: %v", err)
		http.Error(w, "login protection is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if blocked {
		http.Error(w, "this IP address is blocked; use menu item 11 on the VPS to unblock it", http.StatusForbidden)
		return
	}
	if s.loginBlocked(sourceIP) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if err := parseForm(w, r); err != nil {
		return
	}
	loginCookieName, secure := loginCookieForRequest(r)
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || !constantEqual(cookie.Value, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		http.Error(w, "another login check is in progress; try again shortly", http.StatusTooManyRequests)
		return
	}
	usernameOK := constantEqual(s.config.Username, r.FormValue("username"))
	passwordOK := bcrypt.CompareHashAndPassword([]byte(s.config.PasswordHash), []byte(r.FormValue("password"))) == nil
	if !usernameOK || !passwordOK {
		failures := s.recordLoginFailure(sourceIP)
		if failures >= 5 {
			if err := s.blocks.Block(sourceIP, failures); err != nil {
				log.Printf("ERROR persisting blocked IP %q: %v", sourceIP, err)
				http.Error(w, "too many login attempts; login protection is temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			s.clearLoginFailures(sourceIP)
			log.Printf("AUDIT action=block_login_ip source=%q failures=%d", sourceIP, failures)
			http.Error(w, "this IP address is blocked after 5 failed login attempts; use menu item 11 on the VPS to unblock it", http.StatusForbidden)
			return
		}
		token, tokenErr := randomToken(32)
		if tokenErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, authCookie(loginCookieName, token, 10*time.Minute, secure))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login.html", loginData{Version: s.version, CSRF: token, Error: "Invalid username or password."})
		return
	}
	s.clearLoginFailures(sourceIP)
	sessionToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ttl, _ := s.config.SessionDuration()
	s.sessionsMu.Lock()
	s.cleanupSessionsLocked()
	if len(s.sessions) >= 1024 {
		for existing := range s.sessions {
			delete(s.sessions, existing)
			break
		}
	}
	s.sessions[sessionToken] = session{CSRF: csrfToken, Expires: time.Now().Add(ttl)}
	s.sessionsMu.Unlock()
	sessionCookieName, secure := sessionCookieForRequest(r)
	http.SetCookie(w, authCookie(sessionCookieName, sessionToken, ttl, secure))
	http.SetCookie(w, expireCookie(loginCookieName, secure))
	log.Printf("AUDIT user=%q action=login source=%q", s.config.Username, sourceIP)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	current, _ := s.currentSession(r)
	sites, err := s.store.List()
	if err != nil {
		http.Error(w, "could not read managed sites", http.StatusInternalServerError)
		return
	}
	mode := vpnmode.Detect()
	var peers []wireguard.Peer
	var peerError string
	var tailscaleStatus tailscale.Status
	var tailscaleError string
	if mode == vpnmode.WireGuard {
		peers, peerError = s.wireGuardPeers()
	} else if mode == vpnmode.Tailscale {
		tailscaleStatus, tailscaleError = s.tailscaleStatus()
	}
	certificateStatuses, certificateError := s.certificateStatuses()
	s.render(w, "dashboard.html", dashboardData{
		Version:        s.version,
		PanelDomain:    s.config.Domain,
		PublicURL:      PublicURL(s.config),
		CSRF:           current.CSRF,
		Message:        r.URL.Query().Get("message"),
		Sites:          buildDashboardSites(sites, certificateStatuses, certificateError),
		Peers:          peers,
		PeerError:      peerError,
		VPNMode:        string(mode),
		Tailscale:      tailscaleStatus,
		TailscaleError: tailscaleError,
		Metrics:        readSystemMetrics(),
	})
}

func (s *Server) certificateStatuses() ([]certificateStatus, string) {
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		return nil, "Certificate status is unavailable."
	}
	data, err := client.ExecuteData(PrivilegedRequest{Operation: "ssl_status_all"})
	if err != nil {
		return nil, err.Error()
	}
	var statuses []certificateStatus
	if err := json.Unmarshal([]byte(data), &statuses); err != nil {
		return nil, "The privileged helper returned invalid certificate status data."
	}
	return statuses, ""
}

func buildDashboardSites(sites []proxy.Site, statuses []certificateStatus, statusError string) []dashboardSite {
	byDomain := make(map[string]certificateStatus, len(statuses))
	for _, status := range statuses {
		byDomain[status.Domain] = status
	}
	rows := make([]dashboardSite, 0, len(sites))
	for _, site := range sites {
		row := dashboardSite{Site: site, SSLDays: "—", SSLDaysClass: "muted"}
		if !site.SSLEnabled {
			rows = append(rows, row)
			continue
		}
		status, found := byDomain[site.Domain]
		if statusError != "" {
			row.SSLDays = "Unknown"
			row.SSLError = statusError
		} else if !found {
			row.SSLDays = "Unknown"
			row.SSLError = "No certificate status was returned."
		} else if status.Error != "" {
			row.SSLDays = "Error"
			row.SSLError = status.Error
		} else if !status.Issued || status.NotAfter.IsZero() {
			row.SSLDays = "Missing"
			row.SSLError = "The managed certificate file was not found."
		} else {
			row.SSLExpiry = status.NotAfter.UTC().Format("2006-01-02")
			switch {
			case !status.NotAfter.After(time.Now()):
				row.SSLDays = "Expired"
				row.SSLDaysClass = "expired"
			case status.DaysLeft < 1:
				row.SSLDays = "<1 day"
				row.SSLDaysClass = "warning"
			case status.DaysLeft == 1:
				row.SSLDays = "1 day"
				row.SSLDaysClass = "warning"
			default:
				row.SSLDays = strconv.Itoa(status.DaysLeft) + " days"
				if status.DaysLeft <= 30 {
					row.SSLDaysClass = "warning"
				} else {
					row.SSLDaysClass = "healthy"
				}
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) guide(w http.ResponseWriter, r *http.Request) {
	current, _ := s.currentSession(r)
	s.render(w, "guide.html", guideData{
		Version: s.version,
		CSRF:    current.CSRF,
		VPNMode: string(vpnmode.Detect()),
	})
}

func (s *Server) tailscaleStatus() (tailscale.Status, string) {
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		return tailscale.Status{}, "Tailscale status is unavailable."
	}
	data, err := client.ExecuteData(PrivilegedRequest{Operation: "tailscale_status"})
	if err != nil {
		return tailscale.Status{}, err.Error()
	}
	var status tailscale.Status
	if err := json.Unmarshal([]byte(data), &status); err != nil {
		return tailscale.Status{}, "The privileged helper returned invalid Tailscale status data."
	}
	return status, ""
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sessionCookieName, secure := sessionCookieForRequest(r)
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, expireCookie(sessionCookieName, secure))
	log.Printf("AUDIT user=%q action=logout", s.config.Username)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) proxyAdd(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "proxy_add", Domain: r.FormValue("domain"), Upstream: r.FormValue("upstream")})
}

func (s *Server) proxyEdit(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "proxy_edit", Domain: r.FormValue("domain"), Upstream: r.FormValue("upstream")})
}

func (s *Server) proxyEnable(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "proxy_enable", Domain: r.FormValue("domain")})
}

func (s *Server) proxyDisable(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "proxy_disable", Domain: r.FormValue("domain")})
}

func (s *Server) proxyDelete(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "proxy_delete", Domain: r.FormValue("domain")})
}

func (s *Server) sslIssue(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "ssl_issue", Domain: r.FormValue("domain")})
}

func (s *Server) sslRenew(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "ssl_renew", Domain: r.FormValue("domain")})
}

func (s *Server) wireGuardPeers() ([]wireguard.Peer, string) {
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		return nil, "WireGuard peer management is unavailable."
	}
	data, err := client.ExecuteData(PrivilegedRequest{Operation: "wg_peer_list"})
	if err != nil {
		return nil, err.Error()
	}
	var peers []wireguard.Peer
	if err := json.Unmarshal([]byte(data), &peers); err != nil {
		return nil, "The privileged helper returned invalid WireGuard peer data."
	}
	return peers, ""
}

func (s *Server) wgPeerAdd(w http.ResponseWriter, r *http.Request) {
	request := PrivilegedRequest{Operation: "wg_peer_add", Peer: strings.TrimSpace(r.FormValue("peer"))}
	if err := request.Validate(); err != nil {
		redirectMessage(w, r, "ERROR: "+err.Error())
		return
	}
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		redirectMessage(w, r, "ERROR: WireGuard peer management is unavailable")
		return
	}
	data, err := client.ExecuteData(request)
	if err != nil {
		redirectMessage(w, r, "ERROR: "+err.Error())
		return
	}
	var peer wireguard.Peer
	if err := json.Unmarshal([]byte(data), &peer); err != nil {
		redirectMessage(w, r, "ERROR: the privileged helper returned invalid peer data")
		return
	}
	log.Printf("AUDIT user=%q action=%q peer=%q", s.config.Username, request.Operation, peer.Name)
	redirectMessage(w, r, fmt.Sprintf("WireGuard peer %s created with address %s.", peer.Name, peer.Address))
}

func (s *Server) wgPeerDelete(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "wg_peer_delete", Peer: r.FormValue("peer")})
}

func (s *Server) wgPeerDownload(w http.ResponseWriter, r *http.Request) {
	request := PrivilegedRequest{Operation: "wg_peer_config", Peer: r.FormValue("peer")}
	if err := request.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		http.Error(w, "WireGuard peer download is unavailable", http.StatusServiceUnavailable)
		return
	}
	config, err := client.ExecuteData(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("AUDIT user=%q action=%q peer=%q", s.config.Username, request.Operation, request.Peer)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, request.Peer))
	w.Header().Set("Content-Length", strconv.Itoa(len(config)))
	_, _ = w.Write([]byte(config))
}

func (s *Server) wgPeerQR(w http.ResponseWriter, r *http.Request) {
	request := PrivilegedRequest{Operation: "wg_peer_config", Peer: r.URL.Query().Get("peer")}
	if err := request.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		http.Error(w, "WireGuard QR generation is unavailable", http.StatusServiceUnavailable)
		return
	}
	config, err := client.ExecuteData(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(config, qrcode.Medium, 320)
	if err != nil {
		http.Error(w, "could not generate WireGuard QR code", http.StatusInternalServerError)
		return
	}
	log.Printf("AUDIT user=%q action=%q peer=%q", s.config.Username, "wg_peer_qr", request.Peer)
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s-qr.png"`, request.Peer))
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
}

func (s *Server) nginxRestart(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "system_restart_nginx"})
}

func (s *Server) systemUpdate(w http.ResponseWriter, r *http.Request) {
	request := PrivilegedRequest{Operation: "system_update"}
	client, ok := s.privileged.(PrivilegedDataClient)
	if !ok {
		redirectMessage(w, r, "ERROR: system update is unavailable")
		return
	}
	message, err := client.ExecuteData(request)
	if err != nil {
		redirectMessage(w, r, "ERROR: "+err.Error())
		return
	}
	log.Printf("AUDIT user=%q action=%q", s.config.Username, request.Operation)
	redirectMessage(w, r, message)
}

func (s *Server) systemUpdateStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.latestUpdateStatus(r.Context())
	if err != nil {
		http.Error(w, "update check is temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("ERROR encoding update status: %v", err)
	}
}

func (s *Server) latestUpdateStatus(ctx context.Context) (updater.Status, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if !s.updateTime.IsZero() && time.Since(s.updateTime) < time.Hour {
		return s.updateInfo, errorFromMessage(s.updateErr)
	}
	checkContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	status, err := updater.DefaultManager().CheckLatest(checkContext, s.version)
	s.updateTime = time.Now()
	s.updateInfo = status
	s.updateErr = ""
	if err != nil {
		s.updateErr = err.Error()
		log.Printf("WARNING update check failed: %v", err)
	}
	return status, err
}

func (s *Server) updateCheckLoop() {
	_, _ = s.latestUpdateStatus(context.Background())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.updateMu.Lock()
		s.updateTime = time.Time{}
		s.updateMu.Unlock()
		_, _ = s.latestUpdateStatus(context.Background())
	}
}

func errorFromMessage(message string) error {
	if message == "" {
		return nil
	}
	return errors.New(message)
}

func (s *Server) systemReboot(w http.ResponseWriter, r *http.Request) {
	s.executeForm(w, r, PrivilegedRequest{Operation: "system_reboot"})
}

func (s *Server) executeForm(w http.ResponseWriter, r *http.Request, request PrivilegedRequest) {
	if err := parseForm(w, r); err != nil {
		return
	}
	if request.Domain == s.config.Domain && (request.Operation == "proxy_edit" || request.Operation == "proxy_disable" || request.Operation == "proxy_delete") {
		redirectMessage(w, r, "ERROR: manage the web panel proxy with rpctl web commands")
		return
	}
	if err := request.Validate(); err != nil {
		redirectMessage(w, r, "ERROR: "+err.Error())
		return
	}
	err := s.privileged.Execute(request)
	if err != nil {
		redirectMessage(w, r, "ERROR: "+err.Error())
		return
	}
	log.Printf("AUDIT user=%q action=%q domain=%q peer=%q", s.config.Username, request.Operation, request.Domain, request.Peer)
	redirectMessage(w, r, "Operation completed successfully.")
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.currentSession(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := parseForm(w, r); err != nil {
			return
		}
		current, ok := s.currentSession(r)
		if !ok || !constantEqual(current.CSRF, r.FormValue("csrf")) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) currentSession(r *http.Request) (session, bool) {
	cookieName, _ := sessionCookieForRequest(r)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.cleanupSessionsLocked()
	current, ok := s.sessions[cookie.Value]
	return current, ok
}

func (s *Server) cleanupSessionsLocked() {
	now := time.Now()
	for token, current := range s.sessions {
		if !current.Expires.After(now) {
			delete(s.sessions, token)
		}
	}
}

func (s *Server) loginBlocked(ip string) bool {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	s.cleanupLoginAttemptsLocked()
	attempt := s.attempts[ip]
	if time.Now().After(attempt.ResetAt) {
		delete(s.attempts, ip)
		return false
	}
	return attempt.Failures >= 5
}

func (s *Server) recordLoginFailure(ip string) int {
	s.attemptsMu.Lock()
	defer s.attemptsMu.Unlock()
	s.cleanupLoginAttemptsLocked()
	if len(s.attempts) >= 4096 {
		for existing := range s.attempts {
			delete(s.attempts, existing)
			break
		}
	}
	attempt := s.attempts[ip]
	if time.Now().After(attempt.ResetAt) {
		attempt = loginAttempt{ResetAt: time.Now().Add(5 * time.Minute)}
	}
	attempt.Failures++
	s.attempts[ip] = attempt
	return attempt.Failures
}

func (s *Server) cleanupLoginAttemptsLocked() {
	now := time.Now()
	for ip, attempt := range s.attempts {
		if !attempt.ResetAt.After(now) {
			delete(s.attempts, ip)
		}
	}
}

func (s *Server) clearLoginFailures(ip string) {
	s.attemptsMu.Lock()
	delete(s.attempts, ip)
	s.attemptsMu.Unlock()
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("ERROR rendering template %s: %v", name, err)
	}
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return err
	}
	return nil
}

func authCookie(name, value string, ttl time.Duration, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())}
}

func expireCookie(name string, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: "", Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1}
}

func loginCookieForRequest(r *http.Request) (string, bool) {
	if requestIsHTTPS(r) {
		return loginCSRFCookie, true
	}
	return plainLoginCSRFCookie, false
}

func sessionCookieForRequest(r *http.Request) (string, bool) {
	if requestIsHTTPS(r) {
		return sessionCookie, true
	}
	return plainSessionCookie, false
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return net.ParseIP(host).IsLoopback() && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func redirectMessage(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/?message="+url.QueryEscape(message), http.StatusSeeOther)
}

func readSystemMetrics() systemMetrics {
	serverIP, vpnIP := interfaceIPSummary()
	metrics := systemMetrics{
		ServerIP: serverIP,
		VPNIP:    vpnIP,
		CPU:      fmt.Sprintf("%d vCPU", runtime.NumCPU()),
		RAM:      "unavailable",
		SSD:      "unavailable",
		Swap:     "unavailable",
		Uptime:   "unavailable",
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available, swapTotal uint64
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			switch strings.TrimSuffix(fields[0], ":") {
			case "MemTotal":
				total = value
			case "MemAvailable":
				available = value
			case "SwapTotal":
				swapTotal = value
			}
		}
		if total > 0 {
			metrics.RAM = fmt.Sprintf("%d / %d MB used", (total-available)/1024, total/1024)
		}
		metrics.Swap = formatStorage(swapTotal * 1024)
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs("/", &disk); err == nil && disk.Blocks > 0 {
		total := disk.Blocks * uint64(disk.Bsize)
		used := (disk.Blocks - disk.Bfree) * uint64(disk.Bsize)
		metrics.SSD = fmt.Sprintf("%.1f / %.1f GB used", float64(used)/(1<<30), float64(total)/(1<<30))
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			seconds, _ := strconv.ParseFloat(fields[0], 64)
			metrics.Uptime = (time.Duration(seconds) * time.Second).Truncate(time.Minute).String()
		}
	}
	return metrics
}

func formatStorage(bytes uint64) string {
	if bytes == 0 {
		return "0 GB"
	}
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
	}
	return fmt.Sprintf("%d MB", bytes/(1<<20))
}

func isAssignedInterfaceIP(host string) bool {
	wanted := net.ParseIP(host)
	if wanted == nil {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.Equal(wanted) {
				return true
			}
		}
	}
	return false
}

func interfaceIPSummary() (string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unavailable", "unavailable"
	}
	var server, vpn []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || !ip.IsGlobalUnicast() {
				continue
			}
			entry := fmt.Sprintf("%s (%s)", ip.String(), iface.Name)
			if strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "tailscale") {
				vpn = append(vpn, entry)
			} else {
				server = append(server, entry)
			}
		}
	}
	sort.Strings(server)
	sort.Strings(vpn)
	if len(server) == 0 {
		server = []string{"unavailable"}
	}
	if len(vpn) == 0 {
		vpn = []string{"not connected"}
	}
	return strings.Join(server, ", "), strings.Join(vpn, ", ")
}
