package main

import (
	"fmt"
	"os"	
	"context"

	"github.com/YccYeung/LightTI/internal/enricher"
	"github.com/YccYeung/LightTI/internal/store"
	"github.com/YccYeung/LightTI/internal/score"
	"github.com/YccYeung/LightTI/internal/llm"

	"github.com/spf13/cobra"
	"github.com/joho/godotenv"
)

// CLI flag variables bound to the enrich command's flags via init().
var (
	ip 		string
	domain 	string
	hash 	string
	llmUse	bool
)

// enrich sub-command: fans out enrichment, scores results, persists to DB, optionally runs LLM.
var enrich = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich an IP, domain, or file hash against threat intelligence sources",
	Long:  "Enrich an IP address, domain, or file hash against multiple threat intelligence sources including AbuseIPDB, VirusTotal, and GreyNoise etc.",
	Run: func(cmd *cobra.Command, args []string) {
		// Load .env file so os.Getenv calls below can read API keys.
		_ = godotenv.Load()

		dbURL := os.Getenv("DATABASE_URL")
		vtApiKey := os.Getenv("VT_API_KEY")
		abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")

		// Initialise the database store.
		ctx := context.Background()
		s, err := store.New(ctx, dbURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", err)
			return
		}
		
		if ip != "" {

			// Fan out concurrent API calls to VT, AbuseIPDB, IP2Location, GreyNoise.
			enrichmentList := enricher.EnrichIP(ip, vtApiKey, abuseIpApiKey)
			// Score results deterministically (0-100).
			totalScore := score.ScoreProcessing(enrichmentList)
			fmt.Println(score.FormatScore(totalScore))
			// Persist the lookup so results can be linked by ID.
			id, err := s.SaveLookup(ctx, ip, "ip")
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to save lookup: %v\n", err)
				return
			}
			
			for _, result := range enrichmentList {
				errMsg := ""
				if result.Err != nil {
					fmt.Printf("Error from %s: %v\n", result.Source, result.Err)
					errMsg = result.Err.Error()
				}

				if err := s.SaveResult(ctx, id, result.Source, result.RawResult, errMsg); err != nil {
					fmt.Fprintf(os.Stderr, "failed to save result: %v\n", err)
				}
				// Type assertion before printing output
				switch r := result.Result.(type) {
					case enricher.VTResult:
						fmt.Println(enricher.FormatVTReport(r))
					case enricher.AbuseIpResult:
						fmt.Println(enricher.FormatAbuseIpOutput(r))
					case enricher.IpToLocationResult:
						fmt.Println(enricher.FormatIpToLocationOutput(r))
					case enricher.GreyNoiseResult:
						fmt.Println(enricher.FormatGreyNoiseOutput(r))
				}
			}
			// If llm flag is used
			if llmUse {
				provider := llm.NewProvider()	
				result, err := provider.LLMAnalysis(ip, enrichmentList, totalScore.Total)
				if err != nil {
					fmt.Fprintf(os.Stderr, "LLM analysis failed: %v\n", err)
					return
				}
				fmt.Println("\n=== LLM Sigma Rule Generation ===")
				fmt.Println(result)
			}

		} else if domain != "" {
			// Call internal function to enrich domain	
		} else if hash != "" {
			// Call internal function to enrich Hash
		} else {
			fmt.Println("\nPlease provide a flag: --ip, --domain, or --hash")
			if err := cmd.Help(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to print help: %v\n", err)
			}
		}
	},
}

func init() {
	enrich.Flags().StringVar(&ip, "ip", "", "IP address to enrich")
	enrich.Flags().StringVar(&domain, "domain", "", "Domains to enrich")
	enrich.Flags().StringVar(&hash, "hash", "", "Hashes to enrich")

	enrich.Flags().BoolVar(&llmUse, "llm", false, "Enable LLM-powered Sigma rule generation")

	rootCmd.AddCommand(enrich)
}