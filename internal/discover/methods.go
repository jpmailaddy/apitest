package discover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type MethodResult struct {
	Method      string `json:"method"`
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
	ContentType string `json:"content_type,omitempty"`
	Allow       string `json:"allow,omitempty"`
	Notable     string `json:"notable,omitempty"` // why we kept this (e.g. "200 vs GET 404")
	Replay      string `json:"replay,omitempty"`
}

var probedMethods = []string{"OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// probeMethodsForFindings probes additional HTTP methods on each interesting
// finding and records results that differ meaningfully from the GET baseline.
// Bounded: maxFindings findings, concurrent workers.
func probeMethodsForFindings(ctx context.Context, client *http.Client, base *url.URL, findings []Finding, headers []string) []Finding {
	const maxFindings = 50
	const workers = 20

	type job struct{ idx int }
	jobs := make(chan job, workers*2)
	var wg sync.WaitGroup

	// Operate on a copy of indices to interesting findings only.
	targets := make([]int, 0, len(findings))
	for i, f := range findings {
		if !f.Interesting {
			continue
		}
		if isStaticPath(f.Path) {
			continue
		}
		targets = append(targets, i)
		if len(targets) >= maxFindings {
			break
		}
	}
	if len(targets) == 0 {
		return findings
	}

	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results := methodsForOne(ctx, client, base, findings[j.idx], headers)
				if len(results) == 0 {
					continue
				}
				mu.Lock()
				findings[j.idx].Methods = results
				mu.Unlock()
			}
		}()
	}
	for _, idx := range targets {
		select {
		case <-ctx.Done():
		case jobs <- job{idx: idx}:
		}
	}
	close(jobs)
	wg.Wait()
	return findings
}

func methodsForOne(ctx context.Context, client *http.Client, base *url.URL, f Finding, headers []string) []MethodResult {
	var out []MethodResult
	for _, m := range probedMethods {
		r, ok := probeWithMethod(ctx, client, base, f.Path, m, headers)
		if !ok {
			continue
		}
		notable := methodIsNotable(m, r, f)
		if notable == "" {
			continue
		}
		r.Notable = notable
		r.Replay = buildCurl(base, f.Path, m, headers, usedJSONBody(m))
		out = append(out, r)
	}
	return out
}

func probeWithMethod(ctx context.Context, client *http.Client, base *url.URL, path, method string, headers []string) (MethodResult, bool) {
	u := joinPath(base, path)
	var body io.Reader
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return MethodResult{}, false
	}
	if method == "POST" || method == "PUT" || method == "PATCH" {
		req.Body = io.NopCloser(strings.NewReader("{}"))
		req.ContentLength = 2
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, */*;q=0.5")
	applyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return MethodResult{}, false
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, _ := io.Copy(h, io.LimitReader(resp.Body, 64*1024))
	_ = hex.EncodeToString(h.Sum(nil)) // hash unused for now
	return MethodResult{
		Method:      method,
		Status:      resp.StatusCode,
		Length:      n,
		ContentType: resp.Header.Get("Content-Type"),
		Allow:       resp.Header.Get("Allow"),
	}, true
}

// methodIsNotable returns a non-empty reason string if this method's result is
// worth recording, comparing against the original GET finding.
func methodIsNotable(method string, r MethodResult, getF Finding) string {
	// OPTIONS is always interesting if it returns Allow header info.
	if method == "OPTIONS" {
		if r.Allow != "" {
			return "Allow: " + r.Allow
		}
		if r.Status != 405 && r.Status != getF.Status {
			return "OPTIONS responded " + httpCode(r.Status)
		}
		return ""
	}
	// For mutating methods, keep results that look like the endpoint accepts them.
	switch r.Status {
	case 200, 201, 202, 204:
		return method + " accepted (" + httpCode(r.Status) + " vs GET " + httpCode(getF.Status) + ")"
	case 400, 422:
		// Looks like the endpoint expects this method but our body was wrong.
		return method + " expects body (" + httpCode(r.Status) + ")"
	case 401, 403:
		// Auth-gated method — exists but requires creds.
		return method + " requires auth (" + httpCode(r.Status) + ")"
	case 405:
		return "" // method explicitly not allowed — boring
	}
	// Any time the method gives a meaningfully different status than GET, keep it.
	if r.Status != getF.Status && r.Status < 500 {
		return method + " differs from GET (" + httpCode(r.Status) + " vs " + httpCode(getF.Status) + ")"
	}
	return ""
}

func httpCode(n int) string {
	if n == 0 {
		return "0"
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func isStaticPath(p string) bool {
	pl := strings.ToLower(p)
	for _, suf := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(pl, suf) {
			return true
		}
	}
	for _, ex := range []string{"/robots.txt", "/sitemap.xml", "/favicon.ico", "/crossdomain.xml"} {
		if pl == ex {
			return true
		}
	}
	return false
}
