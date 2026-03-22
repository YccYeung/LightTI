package main

import (
	"fmt"
	"os"

	"github.com/YccYeung/LightTI/internal/enricher"

	"github.com/spf13/cobra"
	"github.com/joho/godotenv"
)

var (
	ip 		string
	domain 	string
	hash 	string
)

var enrich = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich an IP, domain, or file hash against threat intelligence sources",
	Long:  "Enrich an IP address, domain, or file hash against multiple threat intelligence sources including AbuseIPDB, VirusTotal, and GreyNoise etc.",
	Run: func(cmd *cobra.Command, args []string) {
		// Load Api key values from environment variables
		godotenv.Load()
		vtApiKey := os.Getenv("VT_API_KEY")
		abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")
		// If IP flag is used
		if ip != "" {
			// Call internal function to enrich IP, Source: VirusTotal, AbuseIPDB, IP2Location, GreyNoise
			enrichmentList := enricher.EnrichIP(ip, vtApiKey, abuseIpApiKey)
			for _, result := range enrichmentList {
				if result.Err != nil {
					fmt.Printf("Error from %s: %v\n", result.Source, result.Err)
					continue
				}
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
		} else if domain != "" {
			// Call internal function to enrich domain	
		} else if hash != "" {
			// Call internal function to enrich Hash
		} else {
			fmt.Println("\nPlease provide a flag: --ip, --domain, or --hash\n")
			cmd.Help()
		}
	},
}

func init() {
	enrich.Flags().StringVar(&ip, "ip", "", "IP address to enrich")
	enrich.Flags().StringVar(&domain, "domain", "", "Domains to enrich")
	enrich.Flags().StringVar(&hash, "hash", "", "Hashes to enrich")

	rootCmd.AddCommand(enrich)
}