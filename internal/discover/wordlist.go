package discover

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Finding struct {
	Path        string         `json:"path"`
	Status      int            `json:"status"`
	ContentType string         `json:"content_type,omitempty"`
	Length      int64          `json:"length"`
	BodyHash    string         `json:"body_hash,omitempty"`
	Interesting bool           `json:"interesting"`
	Replay      string         `json:"replay,omitempty"`
	Methods     []MethodResult `json:"methods,omitempty"`
}

type Options struct {
	Target       string
	WordlistPath string   // if empty, uses built-in mini-list
	Wordlist     []string // explicit override; takes precedence
	Concurrency  int      // default 100
	Progress     bool     // print progress to stderr
	ExtraHeaders []string // "Name: value" lines, applied to every request
}

type Result struct {
	Endpoints     []Finding `json:"endpoints"`
	WordsTotal    int       `json:"words_total"`
	WordsTried    int       `json:"words_tried"`
	CrawledHits   int       `json:"crawled_hits"`
	BaselineStatus int      `json:"baseline_status,omitempty"`
	BaselineLen    int64    `json:"baseline_length,omitempty"`
	BaselineHash   string   `json:"baseline_hash,omitempty"`
	Duration       string   `json:"duration"`
}

func Run(ctx context.Context, client *http.Client, opts Options) (*Result, error) {
	start := time.Now()
	if opts.Concurrency <= 0 {
		opts.Concurrency = 100
	}

	base, err := url.Parse(opts.Target)
	if err != nil {
		return nil, err
	}

	words := opts.Wordlist
	if len(words) == 0 {
		if opts.WordlistPath != "" {
			words, err = loadWordlist(opts.WordlistPath)
			if err != nil {
				return nil, fmt.Errorf("load wordlist: %w", err)
			}
		} else {
			words = builtinMiniList()
		}
	}

	headers := opts.ExtraHeaders
	bl := baseline(ctx, client, base, headers)
	res := &Result{
		WordsTotal:     len(words),
		BaselineStatus: bl.Status,
		BaselineLen:    bl.Length,
		BaselineHash:   bl.BodyHash,
	}

	jobs := make(chan string, opts.Concurrency*2)
	var mu sync.Mutex
	var tried int64
	triedSet := make(map[string]struct{}, len(words))
	for _, w := range words {
		p := w
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		triedSet[p] = struct{}{}
	}

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				f, ok := probe(ctx, client, base, path, headers)
				atomic.AddInt64(&tried, 1)
				if !ok {
					continue
				}
				if isSoftNotFound(f, bl) {
					continue
				}
				f.Interesting = interesting(f)
				f.Replay = buildCurl(base, f.Path, "GET", headers, false)
				mu.Lock()
				res.Endpoints = append(res.Endpoints, f)
				mu.Unlock()
			}
		}()
	}

	var progDone chan struct{}
	if opts.Progress {
		progDone = make(chan struct{})
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-progDone:
					return
				case <-t.C:
					n := atomic.LoadInt64(&tried)
					fmt.Fprintf(os.Stderr, "[discover] %d/%d (%d hits)\n", n, len(words), len(res.Endpoints))
				}
			}
		}()
	}

	for _, w := range words {
		select {
		case <-ctx.Done():
			break
		default:
		}
		jobs <- w
	}
	close(jobs)
	wg.Wait()
	if progDone != nil {
		close(progDone)
	}

	res.WordsTried = int(atomic.LoadInt64(&tried))

	if opts.Progress {
		fmt.Fprintf(os.Stderr, "[discover] crawling HTML hits for additional paths...\n")
	}
	blRef := baselineResp{Status: res.BaselineStatus, Length: res.BaselineLen, BodyHash: res.BaselineHash}
	extra := crawlHTMLFindings(ctx, client, base, res.Endpoints, triedSet, blRef, headers)
	res.CrawledHits = len(extra)
	res.Endpoints = append(res.Endpoints, extra...)

	if opts.Progress {
		fmt.Fprintf(os.Stderr, "[discover] probing additional HTTP methods on interesting endpoints...\n")
	}
	res.Endpoints = probeMethodsForFindings(ctx, client, base, res.Endpoints, headers)

	res.Duration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

type baselineResp struct {
	Status   int
	Length   int64
	BodyHash string
}

func baseline(ctx context.Context, client *http.Client, base *url.URL, headers []string) baselineResp {
	var samples []baselineResp
	for i := 0; i < 2; i++ {
		p := fmt.Sprintf("/__apitest_baseline_%d_%d", time.Now().UnixNano(), rand.Int())
		if r, ok := probeRaw(ctx, client, base, p, headers); ok {
			samples = append(samples, baselineResp{Status: r.Status, Length: r.Length, BodyHash: r.BodyHash})
		}
	}
	if len(samples) == 0 {
		return baselineResp{Status: 404}
	}
	bl := samples[0]
	if len(samples) > 1 && (samples[1].Status != bl.Status || samples[1].BodyHash != bl.BodyHash) {
		bl.BodyHash = ""
	}
	return bl
}

func probe(ctx context.Context, client *http.Client, base *url.URL, path string, headers []string) (Finding, bool) {
	r, ok := probeRaw(ctx, client, base, path, headers)
	if !ok {
		return Finding{}, false
	}
	return Finding{
		Path:        path,
		Status:      r.Status,
		ContentType: r.ContentType,
		Length:      r.Length,
		BodyHash:    r.BodyHash,
	}, true
}

type rawResp struct {
	Status      int
	ContentType string
	Length      int64
	BodyHash    string
}

func probeRaw(ctx context.Context, client *http.Client, base *url.URL, path string, headers []string) (rawResp, bool) {
	u := joinPath(base, path)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return rawResp{}, false
	}
	req.Header.Set("Accept", "application/json, */*;q=0.5")
	applyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return rawResp{}, false
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, _ := io.Copy(h, io.LimitReader(resp.Body, 64*1024))
	return rawResp{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Length:      n,
		BodyHash:    hex.EncodeToString(h.Sum(nil))[:16],
	}, true
}

func isSoftNotFound(f Finding, bl baselineResp) bool {
	if f.Status != bl.Status {
		return false
	}
	if bl.BodyHash != "" && f.BodyHash == bl.BodyHash {
		return true
	}
	if bl.Status == 200 && absDiff(f.Length, bl.Length) < 32 {
		return true
	}
	return f.Status == 404
}

func interesting(f Finding) bool {
	switch f.Status {
	case 200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500:
		return true
	}
	return false
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func applyHeaders(req *http.Request, headers []string) {
	for _, h := range headers {
		i := strings.Index(h, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(h[:i])
		value := strings.TrimSpace(h[i+1:])
		if name != "" {
			req.Header.Set(name, value)
		}
	}
}

func joinPath(base *url.URL, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := *base
	u.Path = p
	u.RawQuery = ""
	return u.String()
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	seen := make(map[string]struct{}, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out, sc.Err()
}
