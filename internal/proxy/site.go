package proxy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var labelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Site is the canonical state. Generated Nginx files are derived from it.
type Site struct {
	Domain        string `json:"domain"`
	Upstream      string `json:"upstream"`
	Enabled       bool   `json:"enabled"`
	SSLEnabled    bool   `json:"ssl_enabled,omitempty"`
	HTTPSRedirect bool   `json:"https_redirect,omitempty"`
	ConfigSHA256  string `json:"config_sha256,omitempty"`
}

func ValidateDomain(domain string) error {
	if len(domain) > 253 || domain != strings.ToLower(domain) || !strings.Contains(domain, ".") {
		return errors.New("domain must be a lowercase DNS name")
	}
	for _, label := range strings.Split(domain, ".") {
		if !labelRE.MatchString(label) {
			return fmt.Errorf("invalid DNS label %q", label)
		}
	}
	if net.ParseIP(domain) != nil {
		return errors.New("site domain must be a DNS name")
	}
	return nil
}

func ValidateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return errors.New("invalid upstream URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("upstream scheme must be http or https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Opaque != "" {
		return errors.New("upstream must contain only scheme, host and port")
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(u.Host, " 	\r\n\\;{}$#") {
		return errors.New("invalid upstream host")
	}
	if net.ParseIP(host) == nil {
		if err := validateHostname(host, false); err != nil {
			return fmt.Errorf("invalid upstream hostname: %w", err)
		}
	}
	port := u.Port()
	if port == "" {
		return errors.New("upstream port is required")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("upstream port must be 1-65535")
	}
	if u.Host != net.JoinHostPort(host, port) && u.Host != host+":"+port {
		return errors.New("invalid upstream address")
	}
	return nil
}

func validateHostname(host string, requireDot bool) error {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) || (requireDot && !strings.Contains(host, ".")) {
		return errors.New("invalid DNS hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if !labelRE.MatchString(label) {
			return fmt.Errorf("invalid DNS label %q", label)
		}
	}
	return nil
}

func (s Site) Validate() error {
	if err := ValidateDomain(s.Domain); err != nil {
		return err
	}
	if err := ValidateUpstream(s.Upstream); err != nil {
		return err
	}
	if s.ConfigSHA256 != "" {
		if len(s.ConfigSHA256) != 64 {
			return errors.New("config_sha256 must contain 64 lowercase hexadecimal characters")
		}
		for _, ch := range s.ConfigSHA256 {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return errors.New("config_sha256 must contain 64 lowercase hexadecimal characters")
			}
		}
	}
	return nil
}

func configDigest(config []byte) string {
	sum := sha256.Sum256(config)
	return fmt.Sprintf("%x", sum[:])
}

func Encode(s Site) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func Decode(b []byte) (Site, error) {
	var s Site
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return s, errors.New("site file must contain exactly one JSON object")
	}
	if err := s.Validate(); err != nil {
		return s, err
	}
	return s, nil
}

func Render(s Site) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	u, err := url.Parse(s.Upstream)
	if err != nil {
		return nil, err
	}
	var upstreamTLS string
	if u.Scheme == "https" {
		upstreamTLS = fmt.Sprintf(`        proxy_ssl_server_name on;
        proxy_ssl_name %s;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_verify_depth 5;
`, u.Hostname())
	}
	proxyLocation := fmt.Sprintf(`    location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
%s
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
    }
`, s.Upstream, upstreamTLS)
	httpLocation := proxyLocation
	if s.SSLEnabled && s.HTTPSRedirect {
		httpLocation = `    location / {
        return 301 https://$host$request_uri;
    }
`
	}
	var httpsServer string
	if s.SSLEnabled {
		httpsServer = fmt.Sprintf(`
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name %s;

    ssl_certificate /etc/rpctl/certs/%s/fullchain.pem;
    ssl_certificate_key /etc/rpctl/certs/%s/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:rpctl_TLS:1m;
    ssl_session_timeout 1d;

%s}
`, s.Domain, s.Domain, s.Domain, proxyLocation)
	}
	// All interpolated fields are validated above. No raw Nginx directives are accepted.
	return []byte(fmt.Sprintf(`# Managed by rpctl. Manual changes may be overwritten.
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location ^~ /.well-known/acme-challenge/ {
        root /var/lib/rpctl/acme-webroot;
        default_type text/plain;
        try_files $uri =404;
    }

%s}%s`, s.Domain, httpLocation, httpsServer)), nil
}

// renderLegacyV1 is kept only to recognize configs produced before the state
// file recorded a digest. It must not be used to generate new configuration.
func renderLegacyV1(s Site) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`# Managed by rpctl. Manual changes may be overwritten.
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
    }
}
`, s.Domain, s.Upstream)), nil
}
