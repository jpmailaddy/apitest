package checks

import (
	"context"
	"net/http"
	"strings"
)

// corsCheck looks for CORS misconfigurations:
//   - Access-Control-Allow-Origin: * combined with Allow-Credentials: true (browser rejects, still a finding)
//   - ACAO: * on responses that look like authenticated/sensitive endpoints
//   - Reflective Origin probe: sends Origin: https://evil.example and checks if it is echoed
type corsCheck struct{}

func (c *corsCheck) Name() string { return "cors" }

func (c *corsCheck) Run(ctx context.Context, in Input) []Finding {
	var out []Finding

	// Pass 1: examine the base-response headers we already have.
	if in.BaseHeaders != nil {
		out = append(out, evaluateCORSHeaders("", in.BaseHeaders)...)
	}

	// Pass 2: reflective-Origin probe against the base target. One request only.
	if in.Target != nil {
		if ev := reflectiveOriginProbe(ctx, in.Client, in.Target.String(), in.ExtraHeaders); ev != "" {
			out = append(out, Finding{
				ID:          "APITEST-CORS-REFLECTIVE-ORIGIN",
				OWASP:       "API8:2023 Security Misconfiguration",
				Severity:    SevHigh,
				Title:       "Reflective CORS Origin (allows arbitrary site to read responses)",
				Path:        in.Target.Path,
				Evidence:    ev,
				Remediation: "Maintain an allowlist of trusted origins instead of echoing the request's Origin header.",
			})
		}
	}
	return out
}

func evaluateCORSHeaders(path string, h http.Header) []Finding {
	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(h.Get("Access-Control-Allow-Credentials"))
	if acao == "" {
		return nil
	}
	var out []Finding
	switch {
	case acao == "*" && acac == "true":
		out = append(out, Finding{
			ID:          "APITEST-CORS-WILDCARD-WITH-CREDS",
			OWASP:       "API8:2023 Security Misconfiguration",
			Severity:    SevHigh,
			Title:       "CORS allows credentials with wildcard origin",
			Path:        path,
			Evidence:    "ACAO: * + ACAC: true",
			Remediation: "Browsers reject this combination, but the intent indicates broken auth design. Use an origin allowlist and only enable credentials for trusted origins.",
		})
	case acao == "*":
		out = append(out, Finding{
			ID:       "APITEST-CORS-WILDCARD",
			OWASP:    "API8:2023 Security Misconfiguration",
			Severity: SevLow,
			Title:    "CORS allows any origin (Access-Control-Allow-Origin: *)",
			Path:     path,
			Evidence: "ACAO: *",
			Remediation: "If this API is intended to be public read-only, this is acceptable. " +
				"For authenticated endpoints, restrict to a known-origin allowlist.",
		})
	}
	return out
}

// reflectiveOriginProbe sends one GET with Origin: https://evil.example and
// returns a short evidence string if the server reflects that origin verbatim.
func reflectiveOriginProbe(ctx context.Context, client *http.Client, target string, extra []string) string {
	const evilOrigin = "https://evil.example"
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Origin", evilOrigin)
	for _, h := range extra {
		if i := strings.Index(h, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == evilOrigin {
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
		if acac == "true" {
			return "Origin reflected; ACAC=true"
		}
		return "Origin reflected"
	}
	return ""
}
