// Package checks implements passive vulnerability checks aligned with the
// OWASP API Security Top 10. Checks run against discovered endpoints and the
// base target after discovery. They are passive (no exploitation payloads),
// observation-only, and produce structured Findings.
package checks

import (
	"context"
	"net/http"
	"net/url"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Finding is one vulnerability/misconfiguration observation.
type Finding struct {
	ID         string   `json:"id"`                 // stable identifier: APITEST-CORS-WILDCARD
	OWASP      string   `json:"owasp,omitempty"`    // e.g. API8:2023
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Path       string   `json:"path,omitempty"`     // URL path the finding applies to ("" = global)
	Evidence   string   `json:"evidence,omitempty"` // short observed value
	Remediation string  `json:"remediation,omitempty"`
}

// Input is the data each check receives. Checks read; they do not mutate.
type Input struct {
	Target       *url.URL
	Client       *http.Client
	ExtraHeaders []string
	BaseHeaders  http.Header // headers from the initial response to the target
	BaseBody     []byte
	BaseStatus   int
	// Endpoints discovered. checks.Finding.Path is set per-endpoint when applicable.
	Endpoints []EndpointSummary
	GraphQLIntrospected bool // classifier confirmed introspection is open
	OpenAPIFound        bool // an OpenAPI/Swagger spec was published
}

// EndpointSummary is the subset of a discover.Finding that the checks need.
// Kept local so the checks package doesn't import discover (avoids cycles).
type EndpointSummary struct {
	Path        string
	Status      int
	ContentType string
	Length      int64
	Methods     []MethodSummary
}

type MethodSummary struct {
	Method string
	Status int
	Allow  string
}

type Check interface {
	Name() string
	Run(ctx context.Context, in Input) []Finding
}

// All returns every registered check. Order is stable.
func All() []Check {
	return []Check{
		&corsCheck{},
		&headersCheck{},
		&debugConsoleCheck{},
		&graphqlIntrospectionCheck{},
		&verboseErrorCheck{},
		&sensitiveFileCheck{},
	}
}

// Run executes every check and returns the combined findings.
func Run(ctx context.Context, in Input) []Finding {
	var out []Finding
	for _, c := range All() {
		out = append(out, c.Run(ctx, in)...)
	}
	return out
}
