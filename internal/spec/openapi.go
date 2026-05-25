package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

type OpenAPIResult struct {
	SpecURL    string             `json:"spec_url"`
	Version    string             `json:"version"`           // openapi or swagger version
	Title      string             `json:"title,omitempty"`
	APIVersion string             `json:"api_version,omitempty"`
	BasePath   string             `json:"base_path,omitempty"`
	Endpoints  []OpenAPIEndpoint  `json:"endpoints"`
	Servers    []string           `json:"servers,omitempty"`
}

type OpenAPIEndpoint struct {
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	Summary     string   `json:"summary,omitempty"`
	OperationID string   `json:"operation_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	HasAuth     bool     `json:"has_auth,omitempty"` // declared security requirement
	Params      []string `json:"params,omitempty"`   // parameter names
}

// FetchAndParse downloads the spec at specURL and returns a normalized result.
// Supports OpenAPI 3.x (openapi field) and Swagger 2.x (swagger field).
func FetchAndParse(ctx context.Context, client *http.Client, specURL string) (*OpenAPIResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", specURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("spec fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	return parseSpec(specURL, body)
}

func parseSpec(specURL string, body []byte) (*OpenAPIResult, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("spec is not JSON: %w", err)
	}
	res := &OpenAPIResult{SpecURL: specURL}

	if v, ok := raw["openapi"]; ok {
		_ = json.Unmarshal(v, &res.Version)
	} else if v, ok := raw["swagger"]; ok {
		_ = json.Unmarshal(v, &res.Version)
	} else {
		return nil, fmt.Errorf("not an OpenAPI/Swagger document")
	}

	// info { title, version }
	if v, ok := raw["info"]; ok {
		var info struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		}
		_ = json.Unmarshal(v, &info)
		res.Title = info.Title
		res.APIVersion = info.Version
	}

	// basePath (Swagger 2)
	if v, ok := raw["basePath"]; ok {
		_ = json.Unmarshal(v, &res.BasePath)
	}

	// servers (OpenAPI 3)
	if v, ok := raw["servers"]; ok {
		var servers []struct{ URL string `json:"url"` }
		if err := json.Unmarshal(v, &servers); err == nil {
			for _, s := range servers {
				if s.URL != "" {
					res.Servers = append(res.Servers, s.URL)
				}
			}
		}
	}

	// paths
	var paths map[string]map[string]json.RawMessage
	if v, ok := raw["paths"]; ok {
		if err := json.Unmarshal(v, &paths); err != nil {
			return res, nil // best-effort: return what we have
		}
	}

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "delete": true,
		"patch": true, "head": true, "options": true, "trace": true,
	}

	for path, ops := range paths {
		for method, opRaw := range ops {
			ml := strings.ToLower(method)
			if !httpMethods[ml] {
				continue
			}
			var op struct {
				Summary     string `json:"summary"`
				OperationID string `json:"operationId"`
				Tags        []string `json:"tags"`
				Security    []map[string][]string `json:"security"`
				Parameters  []struct {
					Name string `json:"name"`
					In   string `json:"in"`
				} `json:"parameters"`
			}
			_ = json.Unmarshal(opRaw, &op)
			ep := OpenAPIEndpoint{
				Path:        joinBase(res.BasePath, path),
				Method:      strings.ToUpper(method),
				Summary:     op.Summary,
				OperationID: op.OperationID,
				Tags:        op.Tags,
				HasAuth:     len(op.Security) > 0,
			}
			for _, p := range op.Parameters {
				if p.Name != "" {
					ep.Params = append(ep.Params, p.Name+" ("+p.In+")")
				}
			}
			res.Endpoints = append(res.Endpoints, ep)
		}
	}

	sort.Slice(res.Endpoints, func(i, j int) bool {
		if res.Endpoints[i].Path != res.Endpoints[j].Path {
			return res.Endpoints[i].Path < res.Endpoints[j].Path
		}
		return res.Endpoints[i].Method < res.Endpoints[j].Method
	})
	return res, nil
}

func joinBase(base, p string) string {
	if base == "" {
		return p
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}
