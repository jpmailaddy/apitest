package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jpmailaddy/apitest/internal/checks"
	"github.com/jpmailaddy/apitest/internal/classify"
	"github.com/jpmailaddy/apitest/internal/discover"
	"github.com/jpmailaddy/apitest/internal/fingerprint"
	"github.com/jpmailaddy/apitest/internal/spec"
)

type Options struct {
	Target       string
	HTTPTimeout  time.Duration
	UserAgent    string
	Classifier   classify.Classifier
	Fingerprint  fingerprint.Fingerprinter
	Discover     bool
	WordlistPath string
	Concurrency  int
	Progress     bool
	ExtraHeaders []string
	ProxyURL     string  // e.g. http://127.0.0.1:8080
	RPS          float64 // requests per second cap; 0 = unlimited
	Insecure     bool    // skip TLS verification
}

type Scanner struct {
	opts   Options
	client *http.Client
}

type Report struct {
	Target      string                `json:"target"`
	StartedAt   time.Time             `json:"started_at"`
	FinishedAt  time.Time             `json:"finished_at"`
	Classify    *classify.Result      `json:"classify"`
	Fingerprint []fingerprint.Finding `json:"fingerprint"`
	OpenAPI     *spec.OpenAPIResult   `json:"openapi,omitempty"`
	GraphQL     *spec.GraphQLResult   `json:"graphql,omitempty"`
	Discover        *discover.Result `json:"discover,omitempty"`
	Vulnerabilities []checks.Finding `json:"vulnerabilities,omitempty"`
	Notes           []string         `json:"notes,omitempty"`
	Extra           map[string]any   `json:"extra,omitempty"`
}

func New(o Options) (*Scanner, error) {
	if o.UserAgent == "" {
		o.UserAgent = "apitest/0.1 (+security-research)"
	}
	if o.HTTPTimeout == 0 {
		o.HTTPTimeout = 15 * time.Second
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure},
	}
	if o.ProxyURL != "" {
		pu, err := url.Parse(o.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid --proxy URL: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	var rt http.RoundTripper = tr
	if o.RPS > 0 {
		rt = &rateLimitedTransport{base: rt, limiter: newLimiter(o.RPS)}
	}
	rt = &uaTransport{ua: o.UserAgent, base: rt}

	return &Scanner{
		opts:   o,
		client: &http.Client{Timeout: o.HTTPTimeout, Transport: rt},
	}, nil
}

func (s *Scanner) Run(ctx context.Context) (*Report, error) {
	r := &Report{Target: s.opts.Target, StartedAt: time.Now().UTC()}

	cls, err := s.opts.Classifier.Classify(ctx, s.client, s.opts.Target)
	if err != nil {
		r.Notes = append(r.Notes, "classify error: "+err.Error())
	}
	r.Classify = cls

	fp, err := s.opts.Fingerprint.Fingerprint(ctx, s.client, s.opts.Target)
	if err != nil {
		r.Notes = append(r.Notes, "fingerprint error: "+err.Error())
	}
	r.Fingerprint = fp

	if cls != nil && cls.SpecURL != "" {
		switch cls.Type {
		case classify.TypeREST:
			if oa, err := spec.FetchAndParse(ctx, s.client, cls.SpecURL); err != nil {
				r.Notes = append(r.Notes, "openapi parse: "+err.Error())
			} else {
				r.OpenAPI = oa
			}
		case classify.TypeGraphQL:
			if gq, err := spec.IntrospectGraphQL(ctx, s.client, cls.SpecURL, s.opts.ExtraHeaders); err != nil {
				r.Notes = append(r.Notes, "graphql introspect: "+err.Error())
			} else {
				r.GraphQL = gq
			}
		}
	} else if cls != nil && cls.Type == classify.TypeGraphQL {
		// introspection succeeded at base target but SpecURL wasn't set (root /graphql)
		if gq, err := spec.IntrospectGraphQL(ctx, s.client, s.opts.Target, s.opts.ExtraHeaders); err == nil {
			r.GraphQL = gq
		}
	}

	if s.opts.Discover {
		dres, err := discover.Run(ctx, s.client, discover.Options{
			Target:       s.opts.Target,
			WordlistPath: s.opts.WordlistPath,
			Concurrency:  s.opts.Concurrency,
			Progress:     s.opts.Progress,
			ExtraHeaders: s.opts.ExtraHeaders,
		})
		if err != nil {
			r.Notes = append(r.Notes, "discover error: "+err.Error())
		}
		r.Discover = dres
	}

	// Capture the base response (headers + a chunk of body) so the checks
	// pass has something to inspect without re-fetching.
	baseHeaders, baseBody, baseStatus := captureBase(ctx, s.client, s.opts.Target, s.opts.ExtraHeaders)

	parsed, _ := url.Parse(s.opts.Target)
	in := checks.Input{
		Target:              parsed,
		Client:              s.client,
		ExtraHeaders:        s.opts.ExtraHeaders,
		BaseHeaders:         baseHeaders,
		BaseBody:            baseBody,
		BaseStatus:          baseStatus,
		GraphQLIntrospected: cls != nil && cls.Type == classify.TypeGraphQL,
		OpenAPIFound:        r.OpenAPI != nil,
	}
	if r.Discover != nil {
		for _, ep := range r.Discover.Endpoints {
			eps := checks.EndpointSummary{
				Path:        ep.Path,
				Status:      ep.Status,
				ContentType: ep.ContentType,
				Length:      ep.Length,
			}
			for _, m := range ep.Methods {
				eps.Methods = append(eps.Methods, checks.MethodSummary{Method: m.Method, Status: m.Status, Allow: m.Allow})
			}
			in.Endpoints = append(in.Endpoints, eps)
		}
	}
	r.Vulnerabilities = checks.Run(ctx, in)

	r.FinishedAt = time.Now().UTC()
	return r, nil
}

func captureBase(ctx context.Context, client *http.Client, target string, headers []string) (http.Header, []byte, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, nil, 0
	}
	for _, h := range headers {
		if i := indexOf(h, ":"); i > 0 {
			req.Header.Set(trim(h[:i]), trim(h[i+1:]))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.Header, body, resp.StatusCode
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

type uaTransport struct {
	ua   string
	base http.RoundTripper
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	return t.base.RoundTrip(req)
}

type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.limiter.wait(req.Context())
	return t.base.RoundTrip(req)
}
