package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerSupportsDocumentedUbuntuReleases(t *testing.T) {
	installerPath := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	installer := string(content)
	for _, supported := range []string{"ubuntu:22.04", "ubuntu:24.04"} {
		if !strings.Contains(installer, supported) {
			t.Errorf("installer does not accept documented platform %s", supported)
		}
	}
	if strings.Contains(installer, "Only Ubuntu Server 24.04 is supported.") {
		t.Error("installer still contains the obsolete Ubuntu 24.04-only rejection")
	}
}
