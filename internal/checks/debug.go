package checks

import (
	"context"
	"strings"
)

// debugConsoleCheck flags exposed debug/admin/diagnostic endpoints discovered
// during enumeration. These map to API8:2023 Security Misconfiguration and
// frequently provide direct RCE (Werkzeug /console) or major info disclosure
// (Spring /actuator/env, Go /debug/pprof).
type debugConsoleCheck struct{}

func (c *debugConsoleCheck) Name() string { return "debug-console" }

type debugSignature struct {
	pathSuffix string
	title      string
	severity   Severity
	note       string
}

var debugSignatures = []debugSignature{
	{"/console", "Exposed Werkzeug debug console (potential RCE if PIN can be derived)", SevCritical,
		"Werkzeug debugger PIN can be computed if you can read /etc/machine-id and the MAC address. Disable debug mode in production."},
	{"/actuator", "Exposed Spring Boot Actuator root", SevHigh,
		"Restrict actuator endpoints behind authentication or disable them in production."},
	{"/actuator/env", "Spring Actuator /env exposed (leaks environment, including credentials)", SevCritical,
		"Set management.endpoints.web.exposure.include= and require auth on actuator endpoints."},
	{"/actuator/heapdump", "Spring Actuator /heapdump exposed (full heap dump → memory disclosure)", SevCritical,
		"Disable /heapdump in production."},
	{"/actuator/mappings", "Spring Actuator /mappings exposed (full route disclosure)", SevHigh,
		"Restrict actuator endpoints behind authentication."},
	{"/debug/pprof", "Go pprof profiling exposed (info disclosure, possible DoS)", SevHigh,
		"Do not register net/http/pprof on a public router."},
	{"/.git/HEAD", "Exposed .git directory (source disclosure)", SevCritical,
		"Block /.git/ at the web server / reverse proxy."},
	{"/.env", "Exposed .env file (credential disclosure)", SevCritical,
		"Never serve .env from the web root."},
	{"/server-status", "Apache mod_status exposed", SevMedium,
		"Restrict /server-status to internal IPs only."},
	{"/server-info", "Apache mod_info exposed", SevMedium,
		"Restrict /server-info to internal IPs only."},
	{"/wp-json/wp/v2/users", "WordPress user enumeration via REST API", SevMedium,
		"Disable or restrict the users endpoint of the WP REST API."},
	{"/console.log", "Exposed console.log artifact", SevLow,
		"Audit static artifacts under the web root."},
	{"/swagger-ui", "Swagger UI publicly exposed", SevInfo,
		"Confirm whether the Swagger UI is intentionally public. If not, restrict it."},
	{"/graphiql", "GraphiQL playground publicly exposed", SevLow,
		"Disable GraphiQL in production environments."},
}

func (c *debugConsoleCheck) Run(ctx context.Context, in Input) []Finding {
	var out []Finding
	for _, ep := range in.Endpoints {
		// Only consider endpoints that responded with something other than 404/5xx.
		if ep.Status >= 400 && ep.Status != 401 && ep.Status != 403 {
			continue
		}
		p := strings.ToLower(ep.Path)
		for _, sig := range debugSignatures {
			if strings.HasSuffix(p, sig.pathSuffix) || p == sig.pathSuffix {
				out = append(out, Finding{
					ID:          "APITEST-DEBUG-" + slugify(sig.pathSuffix),
					OWASP:       "API8:2023 Security Misconfiguration",
					Severity:    sig.severity,
					Title:       sig.title,
					Path:        ep.Path,
					Evidence:    "HTTP " + itoa(ep.Status) + " on " + ep.Path,
					Remediation: sig.note,
				})
				break
			}
		}
	}
	return out
}

func slugify(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "")
	return strings.Trim(s, "-")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
