package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAndValidateCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		DNSNames:     []string{"app.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := parseLeaf(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("app.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("other.example.com"); err == nil {
		t.Fatal("certificate unexpectedly matched another hostname")
	}
}

func TestInstallPairPermissionsAndSymlinkRejection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "example.com")
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := installPair(certPath, keyPath, []byte("certificate"), []byte("private-key")); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{certPath: 0644, keyPath: 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	link := filepath.Join(dir, "linked.pem")
	if err := os.Symlink(certPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotFile(link); err == nil {
		t.Fatal("accepted a symlink certificate path")
	}
}

func TestParseLeafRejectsNonCertificatePEM(t *testing.T) {
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})
	if _, err := parseLeaf(key); err == nil {
		t.Fatal("accepted a non-certificate PEM block")
	}
}
