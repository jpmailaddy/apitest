package checks

import "context"

// graphqlIntrospectionCheck flags introspection enabled on what looks like a
// production endpoint. Introspection is fine on dev but leaks the full schema
// in prod, which dramatically reduces attacker effort.
type graphqlIntrospectionCheck struct{}

func (c *graphqlIntrospectionCheck) Name() string { return "graphql-introspection" }

func (c *graphqlIntrospectionCheck) Run(ctx context.Context, in Input) []Finding {
	if !in.GraphQLIntrospected {
		return nil
	}
	return []Finding{{
		ID:          "APITEST-GRAPHQL-INTROSPECTION-ENABLED",
		OWASP:       "API8:2023 Security Misconfiguration",
		Severity:    SevMedium,
		Title:       "GraphQL introspection enabled (full schema disclosure)",
		Evidence:    "Introspection query succeeded",
		Remediation: "Disable introspection in production. Most GraphQL servers expose a config flag (e.g. Apollo introspection:false).",
	}}
}
