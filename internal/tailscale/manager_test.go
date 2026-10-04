package tailscale

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStatusParsesTailscaleJSON(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "tailscale")
	script := `#!/bin/sh
cat <<'JSON'
{"BackendState":"Running","MagicDNSSuffix":"example.ts.net","CurrentTailnet":{"Name":"example.com"},"Self":{"HostName":"vps-1","DNSName":"vps-1.example.ts.net.","TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],"OS":"linux","Online":true},"Peer":{"node-b":{"HostName":"vps-3","DNSName":"vps-3.example.ts.net.","TailscaleIPs":["100.64.0.3"],"OS":"linux","Online":false},"node-a":{"HostName":"iphone","DNSName":"iphone.example.ts.net.","TailscaleIPs":["100.64.0.2"],"OS":"iOS","Online":true}}}
JSON
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	status, err := (Manager{Binary: binary}).Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.BackendState != "Running" || status.Tailnet != "example.com" || status.Self.Name != "vps-1" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if len(status.Self.IPs) != 2 || len(status.Peers) != 2 {
		t.Fatalf("unexpected addresses or peers: %+v", status)
	}
	if status.Peers[0].Name != "iphone" || !status.Peers[0].Online || status.Peers[1].Name != "vps-3" || status.Peers[1].Online {
		t.Fatalf("peers were not parsed and sorted correctly: %+v", status.Peers)
	}
}
