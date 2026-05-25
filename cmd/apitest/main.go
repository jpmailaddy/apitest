package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jpmailaddy/apitest/internal/authz"
	"github.com/jpmailaddy/apitest/internal/classify"
	"github.com/jpmailaddy/apitest/internal/fingerprint"
	"github.com/jpmailaddy/apitest/internal/scan"

	"github.com/spf13/cobra"
)

var (
	flagYes         bool
	flagReason      string
	flagTimeout     int
	flagOutput      string
	flagDiscover    bool
	flagWordlist    string
	flagConcurrency int
	flagQuiet       bool
	flagHeaders     []string
	flagProxy       string
	flagRPS         float64
	flagInsecure    bool
)

func main() {
	root := &cobra.Command{
		Use:   "apitest",
		Short: "External API security posture scanner",
		Long:  "apitest classifies an API endpoint (REST/SOAP/GraphQL), fingerprints it, and surfaces likely CVEs.",
	}

	scanCmd := &cobra.Command{
		Use:   "scan <url>",
		Short: "Scan a target API URL",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}
	scanCmd.Flags().BoolVarP(&flagYes, "yes", "y", false, "Skip interactive authorization prompt (still logged)")
	scanCmd.Flags().StringVarP(&flagReason, "reason", "r", "", "Authorization reason (required with --yes)")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 15, "HTTP timeout per request (seconds)")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write JSON report to file")
	scanCmd.Flags().BoolVarP(&flagDiscover, "discover", "d", false, "Enumerate endpoints (uses built-in mini-list unless --wordlist set)")
	scanCmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "Wordlist file for endpoint discovery (implies --discover)")
	scanCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 100, "Concurrent workers for discovery")
	scanCmd.Flags().BoolVar(&flagQuiet, "quiet", false, "Suppress progress output on stderr")
	scanCmd.Flags().StringArrayVarP(&flagHeaders, "header", "H", nil, "Custom header sent with every request, e.g. -H 'Authorization: Bearer xyz' (repeatable)")
	scanCmd.Flags().StringVar(&flagProxy, "proxy", "", "Proxy URL for all requests, e.g. http://127.0.0.1:8080 (Burp)")
	scanCmd.Flags().Float64Var(&flagRPS, "rps", 0, "Cap total requests per second (0 = unlimited)")
	scanCmd.Flags().BoolVarP(&flagInsecure, "insecure", "k", false, "Skip TLS certificate verification")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the local dashboard (not yet implemented)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("dashboard not implemented yet")
		},
	}

	root.AddCommand(scanCmd, serveCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	att, err := authz.Confirm(authz.Request{
		Target:        target,
		PreAuthorized: flagYes,
		Reason:        flagReason,
	})
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[authz] logged attestation id=%s\n", att.ID)

	ctxBudget := time.Duration(flagTimeout*4) * time.Second
	if flagDiscover || flagWordlist != "" {
		ctxBudget = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), ctxBudget)
	defer cancel()

	discoverOn := flagDiscover || flagWordlist != ""
	s, err := scan.New(scan.Options{
		Target:       target,
		HTTPTimeout:  time.Duration(flagTimeout) * time.Second,
		Classifier:   classify.Default(),
		Fingerprint:  fingerprint.Default(),
		Discover:     discoverOn,
		WordlistPath: flagWordlist,
		Concurrency:  flagConcurrency,
		Progress:     !flagQuiet,
		ExtraHeaders: flagHeaders,
		ProxyURL:     flagProxy,
		RPS:          flagRPS,
		Insecure:     flagInsecure,
	})
	if err != nil {
		return err
	}

	report, err := s.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return err
	}

	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		out := json.NewEncoder(f)
		out.SetIndent("", "  ")
		return out.Encode(report)
	}
	return nil
}
