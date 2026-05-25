package spec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

type GraphQLResult struct {
	URL          string              `json:"url"`
	QueryType    string              `json:"query_type,omitempty"`
	MutationType string              `json:"mutation_type,omitempty"`
	SubType      string              `json:"subscription_type,omitempty"`
	Operations   []GraphQLOperation  `json:"operations"`
	TypeCount    int                 `json:"type_count"`
}

type GraphQLOperation struct {
	Kind        string   `json:"kind"` // query | mutation | subscription
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Args        []string `json:"args,omitempty"`
	ReturnType  string   `json:"return_type,omitempty"`
}

const introspectionQuery = `{
  "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields(includeDeprecated:true) { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind ofType { name kind } } } } } } }"
}`

func IntrospectGraphQL(ctx context.Context, client *http.Client, gqlURL string, headers []string) (*GraphQLResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", gqlURL, bytes.NewReader([]byte(introspectionQuery)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for _, h := range headers {
		if i := strings.Index(h, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("introspection returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Data struct {
			Schema struct {
				QueryType        *struct{ Name string } `json:"queryType"`
				MutationType     *struct{ Name string } `json:"mutationType"`
				SubscriptionType *struct{ Name string } `json:"subscriptionType"`
				Types            []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name        string `json:"name"`
						Description string `json:"description"`
						Args        []struct {
							Name string         `json:"name"`
							Type rawType        `json:"type"`
						} `json:"args"`
						Type rawType `json:"type"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("introspection response not JSON: %w", err)
	}
	if len(payload.Errors) > 0 || payload.Data.Schema.QueryType == nil {
		return nil, fmt.Errorf("introspection blocked or empty (errors=%d)", len(payload.Errors))
	}

	res := &GraphQLResult{URL: gqlURL, TypeCount: len(payload.Data.Schema.Types)}
	if payload.Data.Schema.QueryType != nil {
		res.QueryType = payload.Data.Schema.QueryType.Name
	}
	if payload.Data.Schema.MutationType != nil {
		res.MutationType = payload.Data.Schema.MutationType.Name
	}
	if payload.Data.Schema.SubscriptionType != nil {
		res.SubType = payload.Data.Schema.SubscriptionType.Name
	}

	classify := func(name string) string {
		switch name {
		case res.QueryType:
			return "query"
		case res.MutationType:
			return "mutation"
		case res.SubType:
			return "subscription"
		}
		return ""
	}

	for _, t := range payload.Data.Schema.Types {
		kind := classify(t.Name)
		if kind == "" {
			continue
		}
		for _, f := range t.Fields {
			op := GraphQLOperation{Kind: kind, Name: f.Name, Description: f.Description, ReturnType: f.Type.unwrap()}
			for _, a := range f.Args {
				op.Args = append(op.Args, a.Name+":"+a.Type.unwrap())
			}
			res.Operations = append(res.Operations, op)
		}
	}
	sort.Slice(res.Operations, func(i, j int) bool {
		if res.Operations[i].Kind != res.Operations[j].Kind {
			return res.Operations[i].Kind < res.Operations[j].Kind
		}
		return res.Operations[i].Name < res.Operations[j].Name
	})
	return res, nil
}

type rawType struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	OfType *rawType `json:"ofType"`
}

func (t rawType) unwrap() string {
	if t.Name != "" {
		return t.Name
	}
	if t.OfType != nil {
		inner := t.OfType.unwrap()
		switch t.Kind {
		case "NON_NULL":
			return inner + "!"
		case "LIST":
			return "[" + inner + "]"
		}
		return inner
	}
	return t.Kind
}
