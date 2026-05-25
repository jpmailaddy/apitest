package checks

import (
	"context"
	"strings"
)

// headersCheck reports missing common security headers on the base response.
// Severity is intentionally low — these are hardening recommendations, not
// active vulns — but they raise the floor of how a target presents itself.
type headersCheck struct{}

func (c *headersCheck) Name() string { return "headers" }

func (c *headersCheck) Run(ctx context.Context, in Input) []Finding {
	if in.BaseHeaders == nil {
		return nil
	}
	var out []Finding

	type rule struct {
		header   string
		title    string
		fix      string
		httpsOnly bool
	}
	rules := []rule{
		{"X-Content-Type-Options", "Missing X-Content-Type-Options header (MIME sniffing)", "Send 'X-Content-Type-Options: nosniff'.", false},
		{"X-Frame-Options", "Missing X-Frame-Options / frame-ancestors (clickjacking)", "Send 'X-Frame-Options: DENY' or a Content-Security-Policy with frame-ancestors.", false},
		{"Content-Security-Policy", "Missing Content-Security-Policy", "Define a CSP appropriate to the API surface (typically 'default-src none' for pure JSON APIs).", false},
		{"Strict-Transport-Security", "Missing Strict-Transport-Security (HSTS)", "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", true},
		{"Referrer-Policy", "Missing Referrer-Policy", "Send 'Referrer-Policy: no-referrer' for APIs that should not leak referrers.", false},
	}

	isHTTPS := in.Target != nil && in.Target.Scheme == "https"
	for _, r := range rules {
		if r.httpsOnly && !isHTTPS {
			continue
		}
		if in.BaseHeaders.Get(r.header) == "" {
			out = append(out, Finding{
				ID:          "APITEST-HEADER-MISSING-" + strings.ToUpper(strings.ReplaceAll(r.header, "-", "")),
				OWASP:       "API8:2023 Security Misconfiguration",
				Severity:    SevInfo,
				Title:       r.title,
				Evidence:    r.header + " absent",
				Remediation: r.fix,
			})
		}
	}

	// Server / X-Powered-By disclose version info — informational.
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := in.BaseHeaders.Get(h); v != "" {
			out = append(out, Finding{
				ID:          "APITEST-HEADER-VERSION-DISCLOSURE-" + strings.ToUpper(strings.ReplaceAll(h, "-", "")),
				OWASP:       "API8:2023 Security Misconfiguration",
				Severity:    SevInfo,
				Title:       h + " header discloses software/version",
				Evidence:    h + ": " + v,
				Remediation: "Suppress or normalize this header at the reverse proxy / framework level.",
			})
		}
	}
	return out
}
