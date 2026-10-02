package webpanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultBlockedIPsPath = "/var/lib/rpctl/web/blocked_ips.json"
	defaultIPBlockVersion = 1
	maxIPBlockFileSize    = 1 << 20
)

type BlockedIP struct {
	IP        string    `json:"ip"`
	BlockedAt time.Time `json:"blocked_at"`
	Failures  int       `json:"failures"`
}

type ipBlockState struct {
	Version int                  `json:"version"`
	Blocked map[string]BlockedIP `json:"blocked"`
}

type IPBlockStore struct {
	Path string
}

func DefaultIPBlockStore() IPBlockStore {
	return IPBlockStore{Path: DefaultBlockedIPsPath}
}

func (s IPBlockStore) IsBlocked(rawIP string) (bool, error) {
	ip, err := normalizeIP(rawIP)
	if err != nil {
		return false, err
	}
	blocked := false
	err = s.withLock(func(state *ipBlockState) error {
		_, blocked = state.Blocked[ip]
		return nil
	})
	return blocked, err
}

func (s IPBlockStore) Block(rawIP string, failures int) error {
	ip, err := normalizeIP(rawIP)
	if err != nil {
		return err
	}
	if failures < 1 {
		failures = 1
	}
	return s.withLock(func(state *ipBlockState) error {
		if existing, ok := state.Blocked[ip]; ok {
			if failures > existing.Failures {
				existing.Failures = failures
				state.Blocked[ip] = existing
			}
			return s.writeState(*state)
		}
		state.Blocked[ip] = BlockedIP{IP: ip, BlockedAt: time.Now().UTC(), Failures: failures}
		return s.writeState(*state)
	})
}

func (s IPBlockStore) List() ([]BlockedIP, error) {
	var blocked []BlockedIP
	err := s.withLock(func(state *ipBlockState) error {
		for _, entry := range state.Blocked {
			blocked = append(blocked, entry)
		}
		return nil
	})
	sort.Slice(blocked, func(i, j int) bool {
		if blocked[i].BlockedAt.Equal(blocked[j].BlockedAt) {
			return blocked[i].IP < blocked[j].IP
		}
		return blocked[i].BlockedAt.Before(blocked[j].BlockedAt)
	})
	return blocked, err
}

func (s IPBlockStore) Unblock(rawIP string) (bool, error) {
	ip, err := normalizeIP(rawIP)
	if err != nil {
		return false, err
	}
	removed := false
	err = s.withLock(func(state *ipBlockState) error {
		if _, ok := state.Blocked[ip]; !ok {
			return nil
		}
		delete(state.Blocked, ip)
		removed = true
		return s.writeState(*state)
	})
	return removed, err
}

func (s IPBlockStore) UnblockAll() (int, error) {
	removed := 0
	err := s.withLock(func(state *ipBlockState) error {
		removed = len(state.Blocked)
		if removed == 0 {
			return nil
		}
		state.Blocked = make(map[string]BlockedIP)
		return s.writeState(*state)
	})
	return removed, err
}

func (s IPBlockStore) withLock(action func(*ipBlockState) error) error {
	path := s.Path
	if path == "" {
		path = DefaultBlockedIPsPath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	lockFD, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(lockFD), path+".lock")
	if lock == nil {
		unix.Close(lockFD) //nolint:errcheck
		return errors.New("could not open blocked IP lock")
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil {
		return err
	}
	if !lockInfo.Mode().IsRegular() {
		return errors.New("blocked IP lock is not a regular file")
	}
	if os.Geteuid() == 0 {
		dirInfo, statErr := os.Stat(dir)
		if statErr != nil {
			return statErr
		}
		stat, ok := dirInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("could not determine Web Panel state owner")
		}
		if err := lock.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck
	state, err := readIPBlockState(path)
	if err != nil {
		return err
	}
	return action(&state)
}

func readIPBlockState(path string) (ipBlockState, error) {
	state := ipBlockState{Version: defaultIPBlockVersion, Blocked: make(map[string]BlockedIP)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxIPBlockFileSize {
		return state, errors.New("blocked IP state is not a valid regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxIPBlockFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return state, errors.New("blocked IP state must contain exactly one JSON object")
	}
	if state.Version != defaultIPBlockVersion || state.Blocked == nil {
		return state, errors.New("unsupported blocked IP state format")
	}
	for key, entry := range state.Blocked {
		normalized, err := normalizeIP(key)
		if err != nil || normalized != key || entry.IP != key || entry.Failures < 1 || entry.BlockedAt.IsZero() {
			return state, fmt.Errorf("invalid blocked IP record %q", key)
		}
	}
	return state, nil
}

func (s IPBlockStore) writeState(state ipBlockState) error {
	path := s.Path
	if path == "" {
		path = DefaultBlockedIPsPath
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".blocked-ips-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if os.Geteuid() == 0 {
		dirInfo, statErr := os.Stat(dir)
		if statErr != nil {
			file.Close()
			return statErr
		}
		stat, ok := dirInfo.Sys().(*syscall.Stat_t)
		if !ok {
			file.Close()
			return errors.New("could not determine Web Panel state owner")
		}
		if err := file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			file.Close()
			return err
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func normalizeIP(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", errors.New("invalid IP address")
	}
	return ip.String(), nil
}
