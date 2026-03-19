package enricher

import (
	"fmt"
	"os"
	"net"
	"net/http"
	"encoding/json"
	"io"
	"strings"

	"github.com/joho/godotenv"
)

// VTResult holds the subset of fields returned by the VirusTotal IP address API
// that are relevant for threat intelligence analysis.
type VTResult struct {
	Data struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Attributes struct {
			Tags						[]string	`json:"tags"`
			Continent            		string 		`json:"continent"`
			Country 					string  	`json:"country"`
			ASN							int			`json:"asn"`
			AsOwner						string 		`json:"as_owner"`
			Network						string		`json:"network"`
			RegionalInternetRegistry	string 		`json:"regional_internet_registry"`
			LastHTTPSCertificateDate	int			`json:"last_https_certificate_date"`
			WhoisDate                	int 		`json:"whois_date"`
			LastModificationDate     	int 		`json:"last_modification_date"`
			Reputation 					int 		`json:"reputation"`
			TotalVotes               	struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`	
			LastAnalysisStats			struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"` 	 
		} `json:"attributes"` 	
	} `json:"data"`
}

// sanitizeVTOutput parses a raw VirusTotal JSON response into a VTResult struct.
// Returns an error if the JSON is malformed or cannot be decoded.
func parseVTOutput(report string) (VTResult, error) {
	var vtReport VTResult
	
	err := json.Unmarshal([]byte(report), &vtReport)
	if err != nil {
		return VTResult{}, fmt.Errorf("failed to parse VT report: %w", err)
	}

	return vtReport, nil
}

func formatVTReport(report VTResult) string {
	d := report.Data
	a := d.Attributes

	output := "\n=== VirusTotal Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf("  %-30s %s\n", "IP Address:", d.ID)
	output += fmt.Sprintf("  %-30s %s\n", "Network:", a.Network)
	output += fmt.Sprintf("  %-30s %s\n", "Country:", a.Country)
	output += fmt.Sprintf("  %-30s %s\n", "Continent:", a.Continent)
	output += fmt.Sprintf("  %-30s %d\n", "ASN:", a.ASN)
	output += fmt.Sprintf("  %-30s %s\n", "AS Owner:", a.AsOwner)
	output += fmt.Sprintf("  %-30s %s\n", "Regional Internet Registry:", a.RegionalInternetRegistry)
	output += fmt.Sprintf("  %-30s %d\n", "Reputation:", a.Reputation)

	if len(a.Tags) > 0 {
		output += fmt.Sprintf("  %-30s %s\n", "Tags:", strings.Join(a.Tags, ", "))
	}

	output += "\nLast Analysis Stats\n"
	output += fmt.Sprintf("  %-30s %d\n", "Malicious:", a.LastAnalysisStats.Malicious)
	output += fmt.Sprintf("  %-30s %d\n", "Suspicious:", a.LastAnalysisStats.Suspicious)
	output += fmt.Sprintf("  %-30s %d\n", "Harmless:", a.LastAnalysisStats.Harmless)
	output += fmt.Sprintf("  %-30s %d\n", "Undetected:", a.LastAnalysisStats.Undetected)
	output += fmt.Sprintf("  %-30s %d\n", "Timeout:", a.LastAnalysisStats.Timeout)

	output += "\nTotal Votes\n"
	output += fmt.Sprintf("  %-30s %d\n", "Malicious:", a.TotalVotes.Malicious)
	output += fmt.Sprintf("  %-30s %d\n", "Harmless:", a.TotalVotes.Harmless)

	return output
}

// EnrichIP looks up threat intelligence for the given IP address across
// configured sources and prints a structured summary to stdout.
func EnrichIP(ip string) {
	godotenv.Load()
	
	vtApiKey := os.Getenv("VT_API_KEY")

	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "invalid IP address: %s\n", ip)
		return
	}

	vtUrl := "https://www.virustotal.com/api/v3/ip_addresses/" + ip

	vtReq, _ := http.NewRequest("GET", vtUrl, nil)
	vtReq.Header.Add("accept", "application/json")
	vtReq.Header.Add("x-apikey", vtApiKey)
	vtRes, err := http.DefaultClient.Do(vtReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}

	defer vtRes.Body.Close()
	vtBody, _ := io.ReadAll(vtRes.Body)

	vtReport, err := parseVTOutput(string(vtBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse VT report: %v\n", err)
		return
	}

	fmt.Printf(formatVTReport(vtReport))
}