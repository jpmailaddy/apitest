package discover

import (
	"fmt"
	"net/url"
	"strings"
)

// buildCurl returns a shell-safe single-line curl command that reproduces the
// given request. Used to populate the Replay field on findings.
func buildCurl(base *url.URL, path, method string, extraHeaders []string, withJSONBody bool) string {
	u := joinPath(base, path)
	var b strings.Builder
	b.WriteString("curl -i")
	if method != "" && method != "GET" {
		b.WriteString(" -X ")
		b.WriteString(method)
	}
	for _, h := range extraHeaders {
		b.WriteString(" -H ")
		b.WriteString(shellQuote(h))
	}
	if withJSONBody {
		b.WriteString(" -H 'Content-Type: application/json' --data '{}'")
	}
	b.WriteString(" ")
	b.WriteString(shellQuote(u))
	return b.String()
}

// shellQuote wraps s in single quotes and escapes any embedded single quotes.
func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t'\"\\$`!*?[]{}();<>|&#~") && s != "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// usedJSONBody returns true if a method typically sends a JSON body in our probes.
func usedJSONBody(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

var _ = fmt.Sprintf // reserved for future debugging
