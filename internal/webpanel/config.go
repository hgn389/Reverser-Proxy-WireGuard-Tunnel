package webpanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"rpctl/internal/proxy"
)

const (
	DefaultListen     = "127.0.0.1:9080"
	PublicListen      = "0.0.0.0:9080"
	DefaultConfigPath = "/etc/rpctl/web/config.json"
	DefaultSocketPath = "/run/rpctl/web-helper.sock"
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,32}$`)

type Config struct {
	Listen       string `json:"listen"`
	Domain       string `json:"domain"`
	PublicAccess bool   `json:"public_access,omitempty"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	SessionTTL   string `json:"session_ttl"`
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return errors.New("web listen address must contain an IP and port")
	}
	if c.PublicAccess {
		if host != "0.0.0.0" {
			return errors.New("public Web Panel access must listen on 0.0.0.0")
		}
	} else if host != "127.0.0.1" && host != "::1" {
		return errors.New("private Web Panel access must use a loopback IP")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return errors.New("web listen port must be 1-65535")
	}
	if c.Domain == "" {
		if !c.PublicAccess {
			return errors.New("a Web Panel domain or public IP:port access is required")
		}
	} else if err := proxy.ValidateDomain(c.Domain); err != nil {
		return fmt.Errorf("web panel domain: %w", err)
	}
	if !usernameRE.MatchString(c.Username) {
		return errors.New("username must be 3-32 letters, numbers, dots, underscores, or hyphens")
	}
	if !strings.HasPrefix(c.PasswordHash, "$2") {
		return errors.New("password hash is not bcrypt")
	}
	if _, err := c.SessionDuration(); err != nil {
		return err
	}
	return nil
}

func (c Config) SessionDuration() (duration time.Duration, err error) {
	if c.SessionTTL == "" {
		return 30 * time.Minute, nil
	}
	duration, err = time.ParseDuration(c.SessionTTL)
	if err != nil || duration < 5*time.Minute || duration > 24*time.Hour {
		return 0, errors.New("session_ttl must be between 5m and 24h")
	}
	return duration, nil
}

func LoadConfig(path string) (Config, error) {
	var config Config
	info, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if !info.Mode().IsRegular() {
		return config, fmt.Errorf("refusing non-regular web config %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return config, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return config, errors.New("web config must contain exactly one JSON object")
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}
