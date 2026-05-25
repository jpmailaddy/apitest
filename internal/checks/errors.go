package checks

import (
	"context"
	"strings"
)

// verboseErrorCheck looks at the base response body for clear framework error
// traces or stack frames — these leak path/version info and aid attackers.
type verboseErrorCheck struct{}

func (c *verboseErrorCheck) Name() string { return "verbose-errors" }

// Signatures: substring match (case-insensitive) on the body of the base
// response. Each entry pairs a needle with a short label.
var traceSignatures = []struct {
	needle string
	label  string
}{
	{"traceback (most recent call last)", "Python traceback"},
	{"werkzeug debugger", "Werkzeug debugger UI"},
	{"<title>werkzeug debugger</title>", "Werkzeug debugger UI"},
	{"at java.base/", "Java stack frame"},
	{"at org.springframework.", "Spring stack frame"},
	{"goroutine 1 [running]", "Go runtime panic"},
	{"<title>whitelabel error page</title>", "Spring Whitelabel error page"},
	{"<b>parse error</b>:", "PHP parse error"},
	{"<b>fatal error</b>:", "PHP fatal error"},
	{"<b>warning</b>:", "PHP warning"},
	{"errorexception", "PHP / Laravel exception"},
	{"yii\\base\\errorexception", "Yii framework exception"},
	{"actionview::template::error", "Rails template error"},
	{"undefined method", "Ruby NoMethodError"},
	{"system.web.httpexception", "ASP.NET exception"},
}

func (c *verboseErrorCheck) Run(ctx context.Context, in Input) []Finding {
	if len(in.BaseBody) == 0 {
		return nil
	}
	body := strings.ToLower(string(in.BaseBody))
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	var out []Finding
	for _, s := range traceSignatures {
		if strings.Contains(body, s.needle) {
			out = append(out, Finding{
				ID:          "APITEST-VERBOSE-ERROR",
				OWASP:       "API8:2023 Security Misconfiguration",
				Severity:    SevMedium,
				Title:       "Verbose error / stack trace in response body",
				Evidence:    s.label,
				Remediation: "Catch unhandled exceptions and return a generic error envelope in production.",
			})
			return out // one finding is enough; don't spam
		}
	}
	return out
}
