package classify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type APIType string

const (
	TypeUnknown APIType = "unknown"
	TypeREST    APIType = "rest"
	TypeSOAP    APIType = "soap"
	TypeGraphQL APIType = "graphql"
	TypeGRPCWeb APIType = "grpc-web"
)

type Result struct {
	Type        APIType  `json:"type"`
	Confidence  float64  `json:"confidence"`
	SpecURL     string   `json:"spec_url,omitempty"`
	Evidence    []string `json:"evidence"`
	ContentType string   `json:"content_type,omitempty"`
}

type Classifier interface {
	Classify(ctx context.Context, client *http.Client, target string) (*Result, error)
}

func Default() Classifier { return &heuristic{} }

type heuristic struct{}

func (h *heuristic) Classify(ctx context.Context, client *http.Client, target string) (*Result, error) {
	res := &Result{Type: TypeUnknown, Evidence: []string{}}

	base, err := url.Parse(target)
	if err != nil {
		return res, err
	}

	body, headers, _ := fetch(ctx, client, target)
	res.ContentType = headers.Get("Content-Type")
	ct := strings.ToLower(res.ContentType)

	switch {
	case strings.Contains(ct, "soap") || strings.Contains(ct, "xml"):
		if strings.Contains(string(body), "Envelope") && strings.Contains(string(body), "soap") {
			res.Type = TypeSOAP
			res.Confidence = 0.9
			res.Evidence = append(res.Evidence, "SOAP Envelope in body")
		}
	case strings.Contains(ct, "application/grpc-web"):
		res.Type = TypeGRPCWeb
		res.Confidence = 0.9
		res.Evidence = append(res.Evidence, "Content-Type application/grpc-web")
	case strings.Contains(ct, "json"):
		if looksGraphQLBody(body) {
			res.Type = TypeGraphQL
			res.Confidence = 0.7
			res.Evidence = append(res.Evidence, "JSON body shaped like GraphQL response")
		} else {
			res.Type = TypeREST
			res.Confidence = 0.6
			res.Evidence = append(res.Evidence, "JSON response on base path")
		}
	case strings.Contains(ct, "html"):
		if t, ev := guessFromHTMLBody(body); t != TypeUnknown {
			res.Type = t
			res.Confidence = 0.55
			res.Evidence = append(res.Evidence, ev)
		}
	}

	for _, p := range []string{"?wsdl", "service?wsdl"} {
		if u := joinURL(base, p); probeBodyContains(ctx, client, u, "wsdl:definitions") {
			res.Type = TypeSOAP
			res.Confidence = 0.95
			res.SpecURL = u
			res.Evidence = append(res.Evidence, "WSDL at "+u)
			break
		}
	}

	if introspectGraphQL(ctx, client, target) {
		res.Type = TypeGraphQL
		res.Confidence = 0.99
		res.Evidence = append(res.Evidence, "GraphQL introspection succeeded")
	} else {
		for _, p := range []string{"/graphql", "/api/graphql", "/query"} {
			u := joinURL(base, p)
			if introspectGraphQL(ctx, client, u) {
				res.Type = TypeGraphQL
				res.Confidence = 0.99
				res.SpecURL = u
				res.Evidence = append(res.Evidence, "GraphQL introspection at "+u)
				break
			}
		}
	}

	specCandidates := []string{"openapi.json", "swagger.json", "v3/api-docs", "api-docs", "swagger/v1/swagger.json"}
	for _, p := range specCandidates {
		for _, u := range []string{joinURL(base, "/"+p), joinAtPath(base, p)} {
			if u == "" {
				continue
			}
			if probeBodyContains(ctx, client, u, "\"openapi\"") || probeBodyContains(ctx, client, u, "\"swagger\"") {
				if res.Type == TypeUnknown || res.Type == TypeREST {
					res.Type = TypeREST
					res.Confidence = 0.95
					res.SpecURL = u
					res.Evidence = append(res.Evidence, "OpenAPI spec at "+u)
				}
				break
			}
		}
		if res.SpecURL != "" {
			break
		}
	}

	return res, nil
}

func guessFromHTMLBody(b []byte) (APIType, string) {
	low := strings.ToLower(string(b))
	switch {
	case strings.Contains(low, "graphql"), strings.Contains(low, "graphiql"):
		return TypeGraphQL, "HTML body mentions GraphQL"
	case strings.Contains(low, "wsdl"), strings.Contains(low, "soap:envelope"), strings.Contains(low, "soap envelope"):
		return TypeSOAP, "HTML body mentions SOAP/WSDL"
	case strings.Contains(low, "rest api"), strings.Contains(low, "restful"),
		strings.Contains(low, "api documentation"), strings.Contains(low, "/api/"),
		strings.Contains(low, "swagger"), strings.Contains(low, "openapi"):
		return TypeREST, "HTML body mentions REST API / api routes"
	}
	return TypeUnknown, ""
}

func looksGraphQLBody(b []byte) bool {
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "{") {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	_, hasData := m["data"]
	_, hasErrors := m["errors"]
	return hasData || hasErrors
}

func introspectGraphQL(ctx context.Context, client *http.Client, target string) bool {
	const q = `{"query":"{__schema{queryType{name}}}"}`
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(q))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return strings.Contains(string(b), "__schema") && strings.Contains(string(b), "queryType")
}

func probeBodyContains(ctx context.Context, client *http.Client, u, needle string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return strings.Contains(strings.ToLower(string(b)), strings.ToLower(needle))
}

func fetch(ctx context.Context, client *http.Client, u string) ([]byte, http.Header, int) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, http.Header{}, 0
	}
	req.Header.Set("Accept", "application/json, application/xml;q=0.9, */*;q=0.5")
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.Header{}, 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return b, resp.Header, resp.StatusCode
}

// joinAtPath appends p to the base URL's path (preserving the existing prefix).
func joinAtPath(base *url.URL, p string) string {
	u := *base
	prefix := strings.TrimRight(u.Path, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u.Path = prefix + p
	u.RawQuery = ""
	return u.String()
}

func joinURL(base *url.URL, p string) string {
	if strings.HasPrefix(p, "?") {
		u := *base
		u.RawQuery = strings.TrimPrefix(p, "?")
		return u.String()
	}
	ref, err := url.Parse(p)
	if err != nil {
		return p
	}
	return base.ResolveReference(ref).String()
}
