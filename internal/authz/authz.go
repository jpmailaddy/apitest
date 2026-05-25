package authz

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Request struct {
	Target        string
	PreAuthorized bool
	Reason        string
}

type Attestation struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Target    string    `json:"target"`
	Host      string    `json:"host"`
	ResolvedA []string  `json:"resolved_a,omitempty"`
	Reason    string    `json:"reason"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

func Confirm(req Request) (*Attestation, error) {
	u, err := url.Parse(req.Target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid URL %q", req.Target)
	}

	host := u.Hostname()
	addrs, _ := net.LookupHost(host)

	reason := req.Reason
	if !req.PreAuthorized {
		fmt.Fprintln(os.Stderr, "==== AUTHORIZATION REQUIRED ====")
		fmt.Fprintf(os.Stderr, "Target:   %s\n", req.Target)
		fmt.Fprintf(os.Stderr, "Host:     %s\n", host)
		if len(addrs) > 0 {
			fmt.Fprintf(os.Stderr, "Resolves: %s\n", strings.Join(addrs, ", "))
		}
		fmt.Fprintln(os.Stderr, "Only proceed if you are authorized to test this target.")
		fmt.Fprint(os.Stderr, "Type 'yes' to confirm: ")

		sc := bufio.NewScanner(os.Stdin)
		if !sc.Scan() || strings.TrimSpace(sc.Text()) != "yes" {
			return nil, fmt.Errorf("authorization declined")
		}
		if reason == "" {
			fmt.Fprint(os.Stderr, "Reason / scope (one line): ")
			if sc.Scan() {
				reason = strings.TrimSpace(sc.Text())
			}
		}
	}
	if reason == "" {
		return nil, fmt.Errorf("authorization reason is required")
	}

	att := &Attestation{
		Timestamp: time.Now().UTC(),
		User:      currentUser(),
		Target:    req.Target,
		Host:      host,
		ResolvedA: addrs,
		Reason:    reason,
	}
	if err := appendLog(att); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return att, nil
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func logPath() (string, error) {
	dir := filepath.Join(os.Getenv("HOME"), ".apitest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "scans.log"), nil
}

func lastHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	last := ""
	for sc.Scan() {
		last = sc.Text()
	}
	if last == "" {
		return ""
	}
	var prev Attestation
	if err := json.Unmarshal([]byte(last), &prev); err != nil {
		return ""
	}
	return prev.Hash
}

func appendLog(att *Attestation) error {
	path, err := logPath()
	if err != nil {
		return err
	}
	att.PrevHash = lastHash(path)
	att.ID = shortID(att)
	att.Hash = computeHash(att)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(att)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func computeHash(att *Attestation) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", att.PrevHash, att.Timestamp.Format(time.RFC3339Nano), att.User, att.Target, att.Reason)
	return hex.EncodeToString(h.Sum(nil))
}

func shortID(att *Attestation) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d", att.Target, att.Timestamp.UnixNano())
	return hex.EncodeToString(h.Sum(nil))[:12]
}
