package webpanel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWireGuardPeerModeRequiresValidModeAndAcknowledgement(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      string
		confirmed string
		peer      string
		allowed   bool
	}{
		{"full", "full", "yes", "iphone", true},
		{"private", "private", "yes", "iphone", true},
		{"unconfirmed", "full", "", "iphone", false},
		{"invalid-mode", "full; reboot", "yes", "iphone", false},
		{"invalid-peer", "full", "yes", "../iphone", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &recordingClient{}
			server, err := NewServer(testConfig(t), "test", testStore(t), client)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/mode", strings.NewReader(url.Values{
				"peer": {test.peer}, "mode": {test.mode}, "confirmed": {test.confirmed},
			}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			server.wgPeerMode(response, request)
			if response.Code != http.StatusSeeOther {
				t.Fatalf("status=%d", response.Code)
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			message := location.Query().Get("message")
			if test.allowed {
				if len(client.requests) != 1 || client.requests[0].Operation != "wg_peer_mode" || client.requests[0].Peer != test.peer || client.requests[0].Mode != test.mode {
					t.Fatalf("unexpected helper requests: %+v", client.requests)
				}
				if !strings.Contains(message, "new .conf file") || !strings.Contains(message, "new QR code") || strings.HasPrefix(message, "ERROR") {
					t.Fatalf("missing device update instructions: %s", message)
				}
			} else if len(client.requests) != 0 || !strings.HasPrefix(message, "ERROR") {
				t.Fatalf("invalid request reached helper: %+v message=%q", client.requests, message)
			}
		})
	}
}

func TestWireGuardPeerModeRequiresAuthenticationAndCSRF(t *testing.T) {
	client := &recordingClient{}
	server, err := NewServer(testConfig(t), "test", testStore(t), client)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	server.sessions["session-token"] = session{CSRF: "csrf-token", Expires: time.Now().Add(time.Minute)}
	for _, test := range []struct {
		name          string
		authenticated bool
		csrf          string
		want          int
	}{
		{"unauthenticated", false, "csrf-token", http.StatusSeeOther},
		{"missing-csrf", true, "", http.StatusForbidden},
		{"invalid-csrf", true, "wrong-token", http.StatusForbidden},
		{"confirmed", true, "csrf-token", http.StatusSeeOther},
	} {
		t.Run(test.name, func(t *testing.T) {
			client.requests = nil
			request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/mode", strings.NewReader(url.Values{
				"peer": {"iphone"}, "mode": {"full"}, "confirmed": {"yes"}, "csrf": {test.csrf},
			}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.authenticated {
				request.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-token"})
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d; want %d", response.Code, test.want)
			}
			allowed := test.authenticated && test.csrf == "csrf-token"
			if !allowed && len(client.requests) != 0 {
				t.Fatal("untrusted mode change reached privileged helper")
			}
			if allowed && len(client.requests) != 1 {
				t.Fatal("valid mode change was not applied")
			}
		})
	}
}

func TestWireGuardPeerModeReportsRoutingFailure(t *testing.T) {
	client := &recordingClient{err: errors.New("enabling full-tunnel routing failed")}
	server, err := NewServer(testConfig(t), "test", testStore(t), client)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/wireguard/peer/mode", strings.NewReader("peer=iphone&mode=full&confirmed=yes"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.wgPeerMode(response, request)
	location, _ := url.Parse(response.Header().Get("Location"))
	message := location.Query().Get("message")
	if !strings.HasPrefix(message, "ERROR") || !strings.Contains(message, "routing failed") {
		t.Fatalf("routing failure reported as success: %s", message)
	}
}
