package enricher

import (
	"fmt"
	"os"
	"net"

	"github.com/joho/godotenv"
)

// Formatting String constants used for report output formatting
const (
	fmtStr = "  %-30s %s\n"
	fmtDec = "  %-30s %d\n"
)

// Unified Struct to store report from different api calls
type EnrichmentResult struct {
	// Name of report
	Source		string
	// Content of report
	Result 		any
	Err			error
}

// EnrichIP concurrently queries VirusTotal and AbuseIPDB for the given IP
// and prints a formatted report for each source to stdout.
func EnrichIP(ip string) []EnrichmentResult {
	godotenv.Load()

	if net.ParseIP(ip) == nil {
		fmt.Printf("Invalid IP address: %s\n", ip)
		return []EnrichmentResult{}
	}
		
	vtApiKey := os.Getenv("VT_API_KEY")
	abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")

	// Buffer size matches number of goroutines so neither blocks on send
	chNum := 4
	ch := make(chan EnrichmentResult, chNum)

	go fetchVT(ip, vtApiKey, ch)
	go fetchAbuseIpDb(ip, abuseIpApiKey, ch)
	go fetchIpToLocation(ip, ch)
	go fetchGreyNoise(ip, ch)

	enrichmentList := []EnrichmentResult{}

	for i := 0; i < chNum; i++ {
		result := <- ch
		enrichmentList = append(enrichmentList, result)
	}
	
	return enrichmentList
}