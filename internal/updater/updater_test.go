package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVersionComparison(t *testing.T) {
	for _, test := range []struct {
		left  string
		right string
		want  int
	}{
		{left: "v1.0.3", right: "v1.0.2", want: 1},
		{left: "v1.0.3", right: "v1.0.3", want: 0},
		{left: "v1.0.2", right: "v1.0.3", want: -1},
		{left: "v2.0.0", right: "v1.99.99", want: 1},
	} {
		got, err := compareVersions(test.left, test.right)
		if err != nil {
			t.Fatalf("compareVersions(%q, %q): %v", test.left, test.right, err)
		}
		if got != test.want {
			t.Errorf("compareVersions(%q, %q)=%d, want %d", test.left, test.right, got, test.want)
		}
	}
	for _, invalid := range []string{"", "1.0.3", "v1.0", "v1.0.3-beta", "v1.x.3"} {
		if _, err := parseVersion(invalid); err == nil {
			t.Errorf("invalid version %q was accepted", invalid)
		}
	}
}

func TestLatestReleaseRedirect(t *testing.T) {
	for _, location := range []string{
		"/hgn389/Reverser-Proxy-WireGuard-Tunnel/releases/tag/v1.0.7",
		"https://github.com/hgn389/Reverser-Proxy-WireGuard-Tunnel/releases/tag/v1.0.7",
	} {
		version, err := releaseVersionFromRedirect("hgn389/Reverser-Proxy-WireGuard-Tunnel", location)
		if err != nil {
			t.Fatal(err)
		}
		if version != "v1.0.7" {
			t.Fatalf("version=%q, want v1.0.7", version)
		}
	}
	for _, location := range []string{
		"https://example.com/hgn389/Reverser-Proxy-WireGuard-Tunnel/releases/tag/v1.0.7",
		"https://github.com/other/repo/releases/tag/v1.0.7",
		"https://github.com/hgn389/Reverser-Proxy-WireGuard-Tunnel/releases/tag/latest",
		"https://github.com/hgn389/Reverser-Proxy-WireGuard-Tunnel/releases/tag/v1.0.7/extra",
	} {
		if _, err := releaseVersionFromRedirect("hgn389/Reverser-Proxy-WireGuard-Tunnel", location); err == nil {
			t.Errorf("invalid redirect %q was accepted", location)
		}
	}
}

func TestChecksumForAsset(t *testing.T) {
	digest := "b37d6e3e48f12f5f88aa987d5f57c252a94d9c99eab8ceba0e27bfd8e4ee7751"
	data := []byte(digest + "  rpctl-linux-amd64\n" + digest + " *rpctl-linux-arm64\n")
	for _, asset := range []string{"rpctl-linux-amd64", "rpctl-linux-arm64"} {
		got, err := checksumForAsset(data, asset)
		if err != nil {
			t.Fatal(err)
		}
		if got != digest {
			t.Fatalf("checksum=%q, want %q", got, digest)
		}
	}
	if _, err := checksumForAsset(data, "missing"); err == nil {
		t.Fatal("missing asset checksum was accepted")
	}
}

func TestUpdateInputValidation(t *testing.T) {
	for _, repository := range []string{"owner/repo", "owner.name/repo-name"} {
		if err := validateRepository(repository); err != nil {
			t.Errorf("valid repository %q: %v", repository, err)
		}
	}
	for _, repository := range []string{"", "owner", "owner/repo/extra", "owner/repo?x=1", "../owner/repo"} {
		if err := validateRepository(repository); err == nil {
			t.Errorf("invalid repository %q was accepted", repository)
		}
	}
	for _, host := range []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} {
		if !allowedDownloadHost(host) {
			t.Errorf("GitHub download host %q was rejected", host)
		}
	}
	for _, host := range []string{"github.com.example.com", "githubusercontent.com.evil.test", "example.com"} {
		if allowedDownloadHost(host) {
			t.Errorf("non-GitHub host %q was accepted", host)
		}
	}
}

func TestAtomicCopy(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicCopy(source, destination, 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new binary" {
		t.Fatalf("destination=%q", data)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("destination mode=%o", info.Mode().Perm())
	}
}
