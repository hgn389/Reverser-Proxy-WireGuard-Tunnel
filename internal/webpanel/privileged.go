package webpanel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"rpctl/internal/certmgr"
	"rpctl/internal/proxy"
	"rpctl/internal/tailscale"
	"rpctl/internal/updater"
	"rpctl/internal/wireguard"
)

const maxPrivilegedResponseSize = 1 << 20

type PrivilegedRequest struct {
	Operation      string `json:"operation"`
	Domain         string `json:"domain,omitempty"`
	Upstream       string `json:"upstream,omitempty"`
	Peer           string `json:"peer,omitempty"`
	VPNIPLastOctet int    `json:"vpn_ip_last_octet,omitempty"`
	Mode           string `json:"mode,omitempty"`
}

type privilegedResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  string `json:"data,omitempty"`
}

type certificateStatus struct {
	Domain   string    `json:"domain"`
	Enabled  bool      `json:"enabled"`
	Issued   bool      `json:"issued"`
	NotAfter time.Time `json:"not_after,omitempty"`
	DaysLeft int       `json:"days_left"`
	Error    string    `json:"error,omitempty"`
}

func (r PrivilegedRequest) Validate() error {
	if r.Mode != "" && r.Operation != "wg_peer_mode" {
		return errors.New("mode is allowed only when changing a WireGuard peer mode")
	}
	if r.VPNIPLastOctet != 0 && r.Operation != "wg_peer_add" {
		return errors.New("VPN IP Local is allowed only when adding a WireGuard peer")
	}
	switch r.Operation {
	case "proxy_add", "proxy_edit":
		if r.Peer != "" {
			return errors.New("peer is not allowed for this operation")
		}
		if err := proxy.ValidateDomain(r.Domain); err != nil {
			return err
		}
		return proxy.ValidateUpstream(r.Upstream)
	case "proxy_delete", "proxy_enable", "proxy_disable", "ssl_issue", "ssl_renew":
		if r.Upstream != "" || r.Peer != "" {
			return errors.New("upstream is not allowed for this operation")
		}
		return proxy.ValidateDomain(r.Domain)
	case "nginx_test", "system_restart_nginx", "system_reboot", "system_update", "ssl_status_all", "tailscale_status":
		if r.Domain != "" || r.Upstream != "" || r.Peer != "" {
			return fmt.Errorf("%s does not accept arguments", r.Operation)
		}
		return nil
	case "wg_peer_list":
		if r.Domain != "" || r.Upstream != "" || r.Peer != "" {
			return errors.New("wg_peer_list does not accept arguments")
		}
		return nil
	case "wg_peer_add":
		if r.Domain != "" || r.Upstream != "" {
			return errors.New("wg_peer_add accepts only a peer name and VPN IP Local")
		}
		if r.VPNIPLastOctet < 0 || r.VPNIPLastOctet > 254 {
			return errors.New("VPN IP Local must be a whole number from 1 to 254")
		}
		if r.Peer == "" {
			return nil
		}
		return wireguard.ValidatePeerName(r.Peer)
	case "wg_peer_delete", "wg_peer_config":
		if r.Domain != "" || r.Upstream != "" {
			return fmt.Errorf("%s accepts only a peer name", r.Operation)
		}
		return wireguard.ValidatePeerName(r.Peer)
	case "wg_peer_mode":
		if r.Domain != "" || r.Upstream != "" {
			return errors.New("wg_peer_mode accepts only a peer name and mode")
		}
		if err := wireguard.ValidatePeerName(r.Peer); err != nil {
			return err
		}
		return wireguard.ValidatePeerMode(r.Mode)
	default:
		return errors.New("operation is not allowed")
	}
}

type PrivilegedClient interface {
	Execute(PrivilegedRequest) error
}

type PrivilegedDataClient interface {
	ExecuteData(PrivilegedRequest) (string, error)
}

type SocketClient struct {
	Path    string
	Timeout time.Duration
}

func (c SocketClient) Execute(request PrivilegedRequest) error {
	_, err := c.execute(request)
	return err
}

func (c SocketClient) ExecuteData(request PrivilegedRequest) (string, error) {
	response, err := c.execute(request)
	return response.Data, err
}

func (c SocketClient) execute(request PrivilegedRequest) (privilegedResponse, error) {
	if err := request.Validate(); err != nil {
		return privilegedResponse{}, err
	}
	path := c.Path
	if path == "" {
		path = DefaultSocketPath
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 4 * time.Minute
	}
	connection, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return privilegedResponse{}, fmt.Errorf("connecting to privileged helper: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return privilegedResponse{}, err
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return privilegedResponse{}, err
	}
	var response privilegedResponse
	decoder := json.NewDecoder(io.LimitReader(connection, maxPrivilegedResponseSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return privilegedResponse{}, fmt.Errorf("reading privileged helper response: %w", err)
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "privileged operation failed"
		}
		return privilegedResponse{}, errors.New(response.Error)
	}
	return response, nil
}

type systemManager interface {
	RestartNginx() error
	ScheduleReboot() error
}

type nativeSystemManager struct{}

func (nativeSystemManager) RestartNginx() error {
	return runFixedCommand("/usr/bin/systemctl", "restart", "nginx")
}

func (nativeSystemManager) ScheduleReboot() error {
	return runFixedCommand("/usr/bin/systemd-run", "--collect", "--on-active=3s", "/usr/bin/systemctl", "reboot")
}

func runFixedCommand(path string, args ...string) error {
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return fmt.Errorf("%s: %w: %s", path, err, message)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func ServePrivilegedOnce(reader io.Reader, writer io.Writer, store proxy.Store, certificates certmgr.Manager) error {
	return servePrivilegedOnce(reader, writer, store, certificates, nativeSystemManager{})
}

func servePrivilegedOnce(reader io.Reader, writer io.Writer, store proxy.Store, certificates certmgr.Manager, system systemManager) error {
	request, operationErr := decodePrivilegedRequest(reader)
	var responseData string
	if operationErr == nil {
		operationErr = request.Validate()
	}
	if operationErr == nil {
		switch request.Operation {
		case "proxy_add":
			operationErr = store.Add(proxy.Site{Domain: request.Domain, Upstream: request.Upstream})
		case "proxy_edit":
			operationErr = store.Update(request.Domain, request.Upstream)
		case "proxy_delete":
			operationErr = store.Delete(request.Domain)
		case "proxy_enable":
			operationErr = store.SetEnabled(request.Domain, true)
		case "proxy_disable":
			operationErr = store.SetEnabled(request.Domain, false)
		case "ssl_issue":
			operationErr = certificates.Issue(request.Domain)
		case "ssl_renew":
			operationErr = certificates.Renew(request.Domain)
		case "ssl_status_all":
			var sites []proxy.Site
			sites, operationErr = store.List()
			if operationErr == nil {
				statuses := make([]certificateStatus, 0, len(sites))
				for _, site := range sites {
					status, statusErr := certificates.Status(site.Domain)
					item := certificateStatus{
						Domain:   site.Domain,
						Enabled:  status.Enabled,
						Issued:   status.Issued,
						NotAfter: status.NotAfter,
						DaysLeft: status.DaysLeft,
					}
					if statusErr != nil {
						item.Error = statusErr.Error()
					}
					statuses = append(statuses, item)
				}
				var encoded []byte
				encoded, operationErr = json.Marshal(statuses)
				responseData = string(encoded)
			}
		case "nginx_test":
			operationErr = store.NginxTest()
		case "system_restart_nginx":
			// A manually edited unmanaged file can make the complete Nginx
			// configuration invalid after the last rpctl operation. Never turn
			// a validation error into downtime by restarting first.
			operationErr = store.NginxTest()
			if operationErr == nil {
				operationErr = system.RestartNginx()
			}
		case "system_reboot":
			operationErr = system.ScheduleReboot()
		case "system_update":
			var result updater.Result
			result, operationErr = updater.DefaultManager().UpdateLatest(context.Background())
			if operationErr == nil {
				if result.Updated {
					responseData = fmt.Sprintf("rpctl updated successfully from %s to %s. The Web Panel will restart shortly.", result.Previous, result.Current)
				} else {
					responseData = fmt.Sprintf("rpctl %s is already the latest release.", result.Current)
				}
				if result.Warning != "" {
					responseData += " WARNING: " + result.Warning
				}
			}
		case "tailscale_status":
			var status tailscale.Status
			status, operationErr = tailscale.DefaultManager().Status(context.Background())
			if operationErr == nil {
				var encoded []byte
				encoded, operationErr = json.Marshal(status)
				responseData = string(encoded)
			}
		case "wg_peer_list":
			var peers []wireguard.Peer
			peers, operationErr = wireguard.DefaultManager().List()
			if operationErr == nil {
				var encoded []byte
				encoded, operationErr = json.Marshal(peers)
				responseData = string(encoded)
			}
		case "wg_peer_add":
			var peer wireguard.Peer
			peer, operationErr = wireguard.DefaultManager().AddWithLastOctet(request.Peer, request.VPNIPLastOctet)
			if operationErr == nil {
				var encoded []byte
				encoded, operationErr = json.Marshal(peer)
				responseData = string(encoded)
			}
		case "wg_peer_delete":
			operationErr = wireguard.DefaultManager().Delete(request.Peer)
		case "wg_peer_mode":
			var peer wireguard.Peer
			peer, operationErr = wireguard.DefaultManager().SetPeerMode(request.Peer, request.Mode)
			if operationErr == nil {
				var encoded []byte
				encoded, operationErr = json.Marshal(peer)
				responseData = string(encoded)
			}
		case "wg_peer_config":
			var config []byte
			config, operationErr = wireguard.DefaultManager().Config(request.Peer)
			responseData = string(config)
		}
	}
	response := privilegedResponse{OK: operationErr == nil, Data: responseData}
	if operationErr != nil {
		response.Error = strings.TrimSpace(operationErr.Error())
	}
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		return err
	}
	return operationErr
}

func decodePrivilegedRequest(reader io.Reader) (PrivilegedRequest, error) {
	const maxRequestSize = 16 << 10
	line, err := bufio.NewReader(io.LimitReader(reader, maxRequestSize+1)).ReadBytes('\n')
	if err != nil && err != io.EOF {
		return PrivilegedRequest{}, err
	}
	if len(line) == 0 {
		return PrivilegedRequest{}, io.ErrUnexpectedEOF
	}
	if len(line) > maxRequestSize {
		return PrivilegedRequest{}, errors.New("request is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var request PrivilegedRequest
	if err := decoder.Decode(&request); err != nil {
		return PrivilegedRequest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return PrivilegedRequest{}, errors.New("request must contain exactly one JSON object")
	}
	return request, nil
}
