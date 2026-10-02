package certmgr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"rpctl/internal/proxy"
)

type Manager struct {
	Store      proxy.Store
	Runner     proxy.Runner
	AcmePath   string
	AcmeHome   string
	ConfigHome string
	CertHome   string
	CertRoot   string
	Webroot    string
}

type Status struct {
	Domain   string
	Enabled  bool
	Issued   bool
	NotAfter time.Time
	DaysLeft int
}

func DefaultManager(store proxy.Store) Manager {
	return Manager{
		Store:      store,
		Runner:     proxy.CommandRunner{},
		AcmePath:   "/opt/acme.sh/acme.sh",
		AcmeHome:   "/opt/acme.sh",
		ConfigHome: "/etc/rpctl/acme",
		CertHome:   "/etc/rpctl/acme/certs",
		CertRoot:   "/etc/rpctl/certs",
		Webroot:    "/var/lib/rpctl/acme-webroot",
	}
}

func (m Manager) runner() proxy.Runner {
	if m.Runner == nil {
		return proxy.CommandRunner{}
	}
	return m.Runner
}

func (m Manager) certPaths(domain string) (string, string, error) {
	if err := proxy.ValidateDomain(domain); err != nil {
		return "", "", err
	}
	dir := filepath.Join(m.CertRoot, domain)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem"), nil
}

func (m Manager) prepare() error {
	info, err := os.Stat(m.AcmePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("acme.sh is not installed; rerun the rpctl installer with --acme")
		}
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("acme.sh path is not an executable regular file: %s", m.AcmePath)
	}
	for _, dir := range []string{m.ConfigHome, m.CertHome} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(m.Webroot, 0755); err != nil {
		return err
	}
	return os.Chmod(m.Webroot, 0755)
}

func (m Manager) acmeArgs(action ...string) []string {
	base := []string{"--home", m.AcmeHome, "--config-home", m.ConfigHome, "--cert-home", m.CertHome}
	return append(base, action...)
}

func (m Manager) Issue(domain string) error {
	if err := proxy.ValidateDomain(domain); err != nil {
		return err
	}
	site, err := m.Store.Show(domain)
	if err != nil {
		return fmt.Errorf("managed site %s: %w", domain, err)
	}
	if !site.Enabled {
		return errors.New("enable the proxy site before issuing its certificate")
	}
	if site.SSLEnabled {
		return errors.New("SSL is already enabled; use rpctl ssl renew " + domain)
	}
	if err := m.prepare(); err != nil {
		return err
	}
	// Refresh installs the local HTTP-01 location before the CA challenge.
	if err := m.Store.Refresh(domain); err != nil {
		return fmt.Errorf("preparing HTTP-01 challenge: %w", err)
	}
	args := m.acmeArgs("--server", "letsencrypt", "--issue", "--webroot", m.Webroot, "-d", domain, "--keylength", "ec-256")
	if _, err := m.runner().Run(m.AcmePath, args...); err != nil {
		return fmt.Errorf("certificate issuance failed: %w", err)
	}
	cert, key, err := m.loadCertificate(domain)
	if err != nil {
		return err
	}
	certPath, keyPath, _ := m.certPaths(domain)
	oldCert, err := snapshotFile(certPath)
	if err != nil {
		return err
	}
	oldKey, err := snapshotFile(keyPath)
	if err != nil {
		return err
	}
	if err := installPair(certPath, keyPath, cert, key); err != nil {
		if restoreErr := restorePair(certPath, keyPath, oldCert, oldKey); restoreErr != nil {
			return fmt.Errorf("installing certificate: %w; rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("installing certificate: %w; previous files restored", err)
	}
	if err := m.Store.SetSSL(domain, true); err != nil {
		if restoreErr := restorePair(certPath, keyPath, oldCert, oldKey); restoreErr != nil {
			return fmt.Errorf("enabling HTTPS: %w; certificate rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("enabling HTTPS: %w", err)
	}
	return nil
}

func (m Manager) Renew(domain string) error {
	site, err := m.Store.Show(domain)
	if err != nil {
		return fmt.Errorf("managed site %s: %w", domain, err)
	}
	if !site.SSLEnabled {
		return errors.New("SSL is not enabled for " + domain)
	}
	if err := m.prepare(); err != nil {
		return err
	}
	if _, err := m.runner().Run(m.AcmePath, m.acmeArgs("--renew", "-d", domain, "--ecc")...); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return nil
		}
		return fmt.Errorf("certificate renewal failed: %w", err)
	}
	cert, key, err := m.loadCertificate(domain)
	if err != nil {
		return err
	}
	certPath, keyPath, _ := m.certPaths(domain)
	oldCert, err := snapshotFile(certPath)
	if err != nil {
		return err
	}
	oldKey, err := snapshotFile(keyPath)
	if err != nil {
		return err
	}
	if err := installPair(certPath, keyPath, cert, key); err != nil {
		if restoreErr := restorePair(certPath, keyPath, oldCert, oldKey); restoreErr != nil {
			return fmt.Errorf("installing renewed certificate: %w; rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("installing renewed certificate: %w; previous files restored", err)
	}
	if err := m.Store.Reload(); err != nil {
		restoreErr := restorePair(certPath, keyPath, oldCert, oldKey)
		if restoreErr == nil {
			restoreErr = m.Store.Reload()
		}
		if restoreErr != nil {
			return fmt.Errorf("reloading renewed certificate: %w; certificate rollback failed: %v", err, restoreErr)
		}
		return fmt.Errorf("reloading renewed certificate: %w; previous certificate restored", err)
	}
	return nil
}

func restorePair(certPath, keyPath string, cert, key fileSnapshot) error {
	var failures []string
	if err := restoreFile(keyPath, key, 0600); err != nil {
		failures = append(failures, err.Error())
	}
	if err := restoreFile(certPath, cert, 0644); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (m Manager) Disable(domain string) error {
	return m.Store.SetSSL(domain, false)
}

func (m Manager) Status(domain string) (Status, error) {
	site, err := m.Store.Show(domain)
	if err != nil {
		return Status{}, err
	}
	status := Status{Domain: domain, Enabled: site.SSLEnabled}
	certPath, _, err := m.certPaths(domain)
	if err != nil {
		return status, err
	}
	b, err := os.ReadFile(certPath)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	cert, err := parseLeaf(b)
	if err != nil {
		return status, err
	}
	if err := cert.VerifyHostname(domain); err != nil {
		return status, fmt.Errorf("certificate hostname: %w", err)
	}
	status.Issued = true
	status.NotAfter = cert.NotAfter
	status.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	return status, nil
}

func (m Manager) loadCertificate(domain string) ([]byte, []byte, error) {
	if err := proxy.ValidateDomain(domain); err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(m.CertHome, domain+"_ecc")
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, domain+".key")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return nil, nil, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	leaf, err := parseLeaf(cert)
	if err != nil {
		return nil, nil, err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, nil, fmt.Errorf("issued certificate hostname: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore.Add(-5*time.Minute)) || !now.Before(leaf.NotAfter) {
		return nil, nil, errors.New("issued certificate is outside its validity period")
	}
	return cert, key, nil
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate file does not contain a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

type fileSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func snapshotFile(path string) (fileSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileSnapshot{}, nil
	}
	if err != nil {
		return fileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return fileSnapshot{}, fmt.Errorf("refusing non-regular certificate path %s", path)
	}
	b, err := os.ReadFile(path)
	return fileSnapshot{exists: true, data: b, mode: info.Mode().Perm()}, err
}

func restoreFile(path string, snap fileSnapshot, defaultMode os.FileMode) error {
	if !snap.exists {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	mode := snap.mode
	if mode == 0 {
		mode = defaultMode
	}
	return writeAtomic(path, snap.data, mode)
}

func installPair(certPath, keyPath string, cert, key []byte) error {
	if !strings.HasSuffix(certPath, "/fullchain.pem") || !strings.HasSuffix(keyPath, "/key.pem") {
		return errors.New("invalid certificate destination")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(certPath), 0700); err != nil {
		return err
	}
	if err := writeAtomic(keyPath, key, 0600); err != nil {
		return err
	}
	return writeAtomic(certPath, cert, 0644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rpctl-cert-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
