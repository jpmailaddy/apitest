package checks

import (
	"context"
	"strings"
)

// sensitiveFileCheck flags discovered endpoints that, by name, are usually
// supposed to be internal or admin-only but were observed responding (not 404)
// during discovery.
type sensitiveFileCheck struct{}

func (c *sensitiveFileCheck) Name() string { return "sensitive-paths" }

var sensitivePathPatterns = []struct {
	contains string
	title    string
	severity Severity
}{
	{"/admin", "Admin endpoint reachable", SevMedium},
	{"/internal", "/internal/ endpoint reachable", SevMedium},
	{"/private", "/private/ endpoint reachable", SevMedium},
	{"/backup", "Backup file/endpoint reachable", SevHigh},
	{"/debug", "Debug endpoint reachable", SevMedium},
	{"/config", "Config endpoint reachable", SevMedium},
	{"/secret", "Secret endpoint reachable", SevHigh},
	{"/.well-known/security.txt", "security.txt exposed (informational)", SevInfo},
}

func (c *sensitiveFileCheck) Run(ctx context.Context, in Input) []Finding {
	var out []Finding
	for _, ep := range in.Endpoints {
		if ep.Status == 0 || ep.Status >= 500 {
			continue
		}
		// 401/403 here is still notable — the endpoint *exists* even if gated.
		p := strings.ToLower(ep.Path)
		for _, sig := range sensitivePathPatterns {
			if strings.Contains(p, sig.contains) {
				gated := ep.Status == 401 || ep.Status == 403
				sev := sig.severity
				title := sig.title
				if gated {
					sev = SevLow
					title += " (auth-gated, but discoverable)"
				}
				out = append(out, Finding{
					ID:          "APITEST-SENSITIVE-" + slugify(sig.contains),
					OWASP:       "API5:2023 Broken Function Level Authorization",
					Severity:    sev,
					Title:       title,
					Path:        ep.Path,
					Evidence:    "HTTP " + itoa(ep.Status),
					Remediation: "Confirm whether this endpoint should be reachable externally and that authorization is enforced.",
				})
				break
			}
		}
	}
	return out
}
