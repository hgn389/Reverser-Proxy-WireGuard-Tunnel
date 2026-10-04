package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultRepository  = "hgn389/Reverser-Proxy-WireGuard-Tunnel"
	defaultInstallPath = "/usr/local/bin/rpctl"
	defaultLockPath    = "/run/rpctl/update.lock"
	maxBinarySize      = 50 << 20
	maxChecksumSize    = 1 << 20
)

type Result struct {
	Previous string
	Current  string
	Updated  bool
	Warning  string
}

type Manager struct {
	Repository  string
	InstallPath string
	LockPath    string
	Client      *http.Client
}

func DefaultManager() Manager {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return Manager{
		Repository:  defaultRepository,
		InstallPath: defaultInstallPath,
		LockPath:    defaultLockPath,
		Client: &http.Client{
			Timeout:   4 * time.Minute,
			Transport: transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many redirects")
				}
				if request.URL.Scheme != "https" || !allowedDownloadHost(request.URL.Hostname()) {
					return errors.New("release download redirected outside GitHub HTTPS hosts")
				}
				return nil
			},
		},
	}
}

func (m Manager) UpdateLatest(ctx context.Context) (Result, error) {
	if os.Geteuid() != 0 {
		return Result{}, errors.New("update needs root privileges")
	}
	if m.Repository == "" {
		m.Repository = defaultRepository
	}
	if m.InstallPath == "" {
		m.InstallPath = defaultInstallPath
	}
	if m.LockPath == "" {
		m.LockPath = defaultLockPath
	}
	if m.Client == nil {
		m.Client = DefaultManager().Client
	}
	if err := validateRepository(m.Repository); err != nil {
		return Result{}, err
	}
	if err := validateInstalledBinary(m.InstallPath); err != nil {
		return Result{}, err
	}

	unlock, err := lockUpdate(m.LockPath)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	previous, err := binaryVersion(ctx, m.InstallPath)
	if err != nil {
		return Result{}, fmt.Errorf("reading installed version: %w", err)
	}
	asset, err := releaseAssetName()
	if err != nil {
		return Result{}, err
	}
	baseURL := "https://github.com/" + m.Repository + "/releases/latest/download/"
	checksumData, err := m.download(ctx, baseURL+"SHA256SUMS", maxChecksumSize)
	if err != nil {
		return Result{}, fmt.Errorf("downloading release checksums: %w", err)
	}
	expected, err := checksumForAsset(checksumData, asset)
	if err != nil {
		return Result{}, err
	}
	binaryData, err := m.download(ctx, baseURL+asset, maxBinarySize)
	if err != nil {
		return Result{}, fmt.Errorf("downloading release binary: %w", err)
	}
	actual := sha256.Sum256(binaryData)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), expected) {
		return Result{}, errors.New("release checksum mismatch; update was not installed")
	}

	directory := filepath.Dir(m.InstallPath)
	candidate, err := os.CreateTemp(directory, ".rpctl-update-*")
	if err != nil {
		return Result{}, err
	}
	candidatePath := candidate.Name()
	defer os.Remove(candidatePath)
	if _, err := candidate.Write(binaryData); err != nil {
		candidate.Close()
		return Result{}, err
	}
	if err := candidate.Chmod(0755); err != nil {
		candidate.Close()
		return Result{}, err
	}
	if err := candidate.Sync(); err != nil {
		candidate.Close()
		return Result{}, err
	}
	if err := candidate.Close(); err != nil {
		return Result{}, err
	}
	current, err := binaryVersion(ctx, candidatePath)
	if err != nil {
		return Result{}, fmt.Errorf("validating downloaded binary: %w", err)
	}
	comparison, err := compareVersions(current, previous)
	if err != nil {
		return Result{}, err
	}
	if comparison == 0 {
		return Result{Previous: previous, Current: current}, nil
	}
	if comparison < 0 {
		return Result{}, fmt.Errorf("latest GitHub release %s is older than installed version %s", current, previous)
	}

	backupPath := m.InstallPath + ".previous"
	if err := atomicCopy(m.InstallPath, backupPath, 0755); err != nil {
		return Result{}, fmt.Errorf("saving previous binary: %w", err)
	}
	if err := os.Rename(candidatePath, m.InstallPath); err != nil {
		return Result{}, fmt.Errorf("installing update: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		_ = atomicCopy(backupPath, m.InstallPath, 0755)
		return Result{}, fmt.Errorf("syncing installed update: %w", err)
	}

	rollback := func(cause error) (Result, error) {
		if restoreErr := atomicCopy(backupPath, m.InstallPath, 0755); restoreErr != nil {
			return Result{}, fmt.Errorf("%w; restoring previous binary failed: %v", cause, restoreErr)
		}
		return Result{}, fmt.Errorf("%w; previous binary %s was restored", cause, previous)
	}

	webInstalled := false
	if info, statErr := os.Lstat("/etc/rpctl/web/config.json"); statErr == nil {
		if !info.Mode().IsRegular() {
			return rollback(errors.New("web panel configuration is not a regular file"))
		}
		webInstalled = true
		output, refreshErr := exec.CommandContext(ctx, m.InstallPath, "web", "refresh").CombinedOutput()
		if refreshErr != nil {
			message := strings.TrimSpace(string(output))
			if message != "" {
				refreshErr = fmt.Errorf("%w: %s", refreshErr, message)
			}
			return rollback(fmt.Errorf("refreshing Web Panel units: %w", refreshErr))
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return rollback(fmt.Errorf("checking Web Panel installation: %w", statErr))
	}

	result := Result{Previous: previous, Current: current, Updated: true}
	if webInstalled && serviceActive(ctx, "rpctl-web.service") {
		unitName := "rpctl-update-restart-" + strconv.Itoa(os.Getpid())
		output, scheduleErr := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--unit="+unitName, "--collect", "--on-active=3s", "/usr/bin/systemctl", "restart", "rpctl-web.service").CombinedOutput()
		if scheduleErr != nil {
			result.Warning = "update installed, but the Web Panel restart could not be scheduled"
			if message := strings.TrimSpace(string(output)); message != "" {
				result.Warning += ": " + message
			}
		}
	}
	return result, nil
}

func (m Manager) download(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "rpctl-updater")
	response, err := m.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("release file exceeds the allowed size")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("release file exceeds the allowed size")
	}
	return data, nil
}

func allowedDownloadHost(host string) bool {
	host = strings.ToLower(host)
	return host == "github.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

func validateRepository(repository string) error {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || !safeRepositoryPart(parts[0]) || !safeRepositoryPart(parts[1]) {
		return errors.New("update repository must use owner/name format")
	}
	return nil
}

func safeRepositoryPart(value string) bool {
	if value == "" || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_.-", character) {
			continue
		}
		return false
	}
	return true
}

func validateInstalledBinary(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to replace a non-regular rpctl installation")
	}
	return nil
}

func releaseAssetName() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return "rpctl-linux-" + runtime.GOARCH, nil
	default:
		return "", fmt.Errorf("unsupported update architecture %s", runtime.GOARCH)
	}
}

func checksumForAsset(data []byte, asset string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		if len(fields[0]) != 64 {
			break
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			break
		}
		return strings.ToLower(fields[0]), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("SHA256SUMS does not contain a valid checksum for %s", asset)
}

func binaryVersion(ctx context.Context, path string) (string, error) {
	output, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) != 2 || fields[0] != "rpctl" {
		return "", errors.New("binary returned an invalid version string")
	}
	if _, err := parseVersion(fields[1]); err != nil {
		return "", err
	}
	return fields[1], nil
}

func compareVersions(left, right string) (int, error) {
	l, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	r, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	for index := range l {
		if l[index] < r[index] {
			return -1, nil
		}
		if l[index] > r[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(value string) ([3]int, error) {
	var parsed [3]int
	if !strings.HasPrefix(value, "v") {
		return parsed, fmt.Errorf("invalid release version %q", value)
	}
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return parsed, fmt.Errorf("invalid release version %q", value)
	}
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return parsed, fmt.Errorf("invalid release version %q", value)
		}
		parsed[index] = number
	}
	return parsed, nil
}

func lockUpdate(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another rpctl update is already running")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func atomicCopy(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".rpctl-copy-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func serviceActive(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", name).Run() == nil
}
