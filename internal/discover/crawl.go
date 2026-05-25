package discover

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// pathRE matches plausible URL paths inside HTML bodies / attributes.
// Starts with "/", followed by path-safe chars. Captures things like
// /api/v2/resources/books, /graphql, /openapi.json
var pathRE = regexp.MustCompile(`/[A-Za-z][A-Za-z0-9_./~-]{1,128}`)

// hrefSrcRE pulls href="..." / src="..." values for tighter signal.
var hrefSrcRE = regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']([^"'#?\s]+)`)

// extractPaths returns deduped candidate paths from an HTML body.
// Filters: must start with "/", not "//", reasonable length, sane chars.
func extractPaths(body []byte, baseHost string) []string {
	seen := make(map[string]struct{})
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
			return
		}
		// Drop query/fragment for probing.
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		if len(p) < 2 || len(p) > 200 {
			return
		}
		seen[p] = struct{}{}
	}

	// Pass 1: explicit href/src/action attributes.
	for _, m := range hrefSrcRE.FindAllSubmatch(body, -1) {
		raw := string(m[1])
		// If it's an absolute URL on the same host, keep the path.
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			if baseHost == "" || strings.EqualFold(u.Host, baseHost) {
				add(u.Path)
			}
			continue
		}
		add(raw)
	}

	// Pass 2: bare path-shaped tokens in body text (catches Foxy-style "/api/v2/resources/books" in <p> tags).
	for _, m := range pathRE.FindAll(body, -1) {
		add(string(m))
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// crawl HTML 200 responses already found, extract candidate paths, probe them.
// Returns the new findings (interesting ones only). Limits work to keep it bounded.
func crawlHTMLFindings(ctx context.Context, client *http.Client, base *url.URL, found []Finding, tried map[string]struct{}, bl baselineResp, headers []string) []Finding {
	const maxPagesToCrawl = 5
	const maxNewProbes = 200

	// Pick HTML 200s, in original order, up to N.
	pages := make([]Finding, 0, maxPagesToCrawl)
	for _, f := range found {
		if f.Status == 200 && strings.Contains(strings.ToLower(f.ContentType), "html") {
			pages = append(pages, f)
			if len(pages) >= maxPagesToCrawl {
				break
			}
		}
	}
	if len(pages) == 0 {
		return nil
	}

	candidates := make(map[string]struct{})
	for _, p := range pages {
		body, ok := fetchBody(ctx, client, base, p.Path, headers)
		if !ok {
			continue
		}
		for _, c := range extractPaths(body, base.Host) {
			if _, dup := tried[c]; dup {
				continue
			}
			candidates[c] = struct{}{}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Bound the probing.
	list := make([]string, 0, len(candidates))
	for c := range candidates {
		list = append(list, c)
	}
	sort.Strings(list)
	if len(list) > maxNewProbes {
		list = list[:maxNewProbes]
	}

	var out []Finding
	for _, p := range list {
		f, ok := probe(ctx, client, base, p, headers)
		if !ok {
			continue
		}
		tried[p] = struct{}{}
		if isSoftNotFound(f, bl) {
			continue
		}
		f.Interesting = interesting(f)
		f.Replay = buildCurl(base, f.Path, "GET", headers, false)
		out = append(out, f)
	}
	return out
}

func fetchBody(ctx context.Context, client *http.Client, base *url.URL, path string, headers []string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", joinPath(base, path), nil)
	if err != nil {
		return nil, false
	}
	applyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, false
	}
	return b, true
}
