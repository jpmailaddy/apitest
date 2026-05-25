package fingerprint

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

type Finding struct {
	Product  string `json:"product"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
	Evidence string `json:"evidence,omitempty"`
}

type Fingerprinter interface {
	Fingerprint(ctx context.Context, client *http.Client, target string) ([]Finding, error)
}

func Default() Fingerprinter { return &basic{} }

type basic struct{}

var versionRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_.-]*)/([0-9]+(?:\.[0-9A-Za-z]+)*)`)

func (b *basic) Fingerprint(ctx context.Context, client *http.Client, target string) ([]Finding, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out []Finding
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via"} {
		v := resp.Header.Get(h)
		if v == "" {
			continue
		}
		for _, m := range versionRE.FindAllStringSubmatch(v, -1) {
			out = append(out, Finding{Product: strings.ToLower(m[1]), Version: m[2], Source: "header:" + h, Evidence: v})
		}
		if len(versionRE.FindAllStringSubmatch(v, -1)) == 0 {
			out = append(out, Finding{Product: strings.ToLower(v), Source: "header:" + h, Evidence: v})
		}
	}
	return out, nil
}
