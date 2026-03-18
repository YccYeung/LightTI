package main

import (
	"fmt"
	"os"
	"net"

	"github.com/spf13/cobra"
)

var (
	ip 		string
	domain 	string
	hash 	string
)

var enrich = &cobra.Command{
	Use:   "enrich",
	Short: "Enrich an IP, domain, or file hash against threat intelligence sources",
	Long:  "Enrich an IP address, domain, or file hash against multiple threat intelligence sources including AbuseIPDB, VirusTotal, and Shodan etc.",
	Run: func(cmd *cobra.Command, args []string) {
		// If IP flag is used
		if ip != "" {
			if net.ParseIP(ip) == nil {
				fmt.Fprintf(os.Stderr, "invalid IP address: %s\n", ip)
				os.Exit(1)
			}
			// Call internal function to enrich IP
			// enrichIP(ip)
		} else if domain != "" {
			// Call internal function to enrich domain	
		} else if hash != "" {
			// Call internal function to enrich Hash
		} else {
			// print something
		}
	},
}

func init() {
	enrich.Flags().StringVar(&ip, "ip", "", "IP address to enrich")
	enrich.Flags().StringVar(&domain, "domain", "", "Domains to enrich")
	enrich.Flags().StringVar(&hash, "hash", "", "Hashes to enrich")

	rootCmd.AddCommand(enrich)
}
