package proxy

import (
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	for _, domain := range []string{"a.b", "example.com", "api-1.example.com"} {
		if err := ValidateDomain(domain); err != nil {
			t.Errorf("%q: %v", domain, err)
		}
	}
	for _, domain := range []string{"", "localhost", "EXAMPLE.COM", "*.example.com", "a..com", "-a.com", "a-.com", "example.com;return", "example.com/path", "../example.com", "127.0.0.1", "a.com\nserver{}"} {
		if err := ValidateDomain(domain); err == nil {
			t.Errorf("accepted %q", domain)
		}
	}
}

func TestValidateUpstream(t *testing.T) {
	for _, upstream := range []string{"http://127.0.0.1:8080", "https://backend.example.com:443", "http://[2001:db8::1]:8080", "http://nas:3000", "http://203.0.113.10:80"} {
		if err := ValidateUpstream(upstream); err != nil {
			t.Errorf("%q: %v", upstream, err)
		}
	}
	for _, upstream := range []string{"", "10.77.0.2", "10.77.0.2:80", "ftp://example.com:21", "http://example.com", "http://example.com:0", "http://example.com:65536", "http://user:pass@example.com:80", "http://example.com:80/path", "http://example.com:80?x=y", "http://bad;name:80", "http://example.com:80/#foo", "http://example.com:80\nserver{}"} {
		if err := ValidateUpstream(upstream); err == nil {
			t.Errorf("accepted %q", upstream)
		}
	}
}

func TestSiteRoundTripAndRender(t *testing.T) {
	want := Site{Domain: "app.example.com", Upstream: "https://203.0.113.10:8443", Enabled: true}
	b, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip: got %+v, want %+v", got, want)
	}
	conf, err := Render(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "server_name app.example.com;") || !strings.Contains(string(conf), "proxy_pass https://203.0.113.10:8443;") {
		t.Fatalf("unexpected Nginx config: %s", conf)
	}
	if !strings.Contains(string(conf), "proxy_ssl_verify on;") || !strings.Contains(string(conf), "proxy_ssl_name 203.0.113.10;") {
		t.Fatalf("HTTPS upstream is missing TLS verification: %s", conf)
	}
}

func TestRejectInvalidConfigDigest(t *testing.T) {
	site := Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080", ConfigSHA256: strings.Repeat("A", 64)}
	if err := site.Validate(); err == nil {
		t.Fatal("accepted invalid config digest")
	}
}

func TestHTTPRenderDoesNotAddTLSDirectives(t *testing.T) {
	conf, err := Render(Site{Domain: "app.example.com", Upstream: "http://127.0.0.1:8080", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(conf), "proxy_ssl_") {
		t.Fatalf("HTTP upstream contains TLS directives: %s", conf)
	}
}

func TestSSLRenderIncludesHTTPSRedirectAndChallenge(t *testing.T) {
	conf, err := Render(Site{
		Domain:        "app.example.com",
		Upstream:      "http://10.77.0.2:80",
		Enabled:       true,
		SSLEnabled:    true,
		HTTPSRedirect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(conf)
	for _, want := range []string{
		"location ^~ /.well-known/acme-challenge/",
		"return 301 https://$host$request_uri;",
		"listen 443 ssl;",
		"ssl_certificate /etc/rpctl/certs/app.example.com/fullchain.pem;",
		"ssl_certificate_key /etc/rpctl/certs/app.example.com/key.pem;",
		"proxy_pass http://10.77.0.2:80;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("SSL config is missing %q:\n%s", want, text)
		}
	}
}

func FuzzValidateDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "a.b", "../example.com", "a.com\nserver{}", "*.example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, domain string) {
		if ValidateDomain(domain) != nil {
			return
		}
		config, err := Render(Site{Domain: domain, Upstream: "http://127.0.0.1:8080"})
		if err != nil {
			t.Fatalf("validated domain failed to render: %v", err)
		}
		if strings.ContainsAny(domain, " \t\r\n/\\;{}$#") {
			t.Fatalf("accepted unsafe domain %q; config: %s", domain, config)
		}
	})
}

func FuzzValidateUpstream(f *testing.F) {
	for _, seed := range []string{"http://127.0.0.1:8080", "https://backend.example.com:443", "http://bad;name:80", "http://a:80/path"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, upstream string) {
		if ValidateUpstream(upstream) != nil {
			return
		}
		config, err := Render(Site{Domain: "app.example.com", Upstream: upstream})
		if err != nil {
			t.Fatalf("validated upstream failed to render: %v", err)
		}
		if strings.ContainsAny(upstream, " \t\r\n\\;{}$#") {
			t.Fatalf("accepted unsafe upstream %q; config: %s", upstream, config)
		}
	})
}
