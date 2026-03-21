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

// AbuseIpResult holds the subset of fields returned by the AbuseIPDB IP address API
// that are relevant for threat intelligence analysis.
type AbuseIpResult struct {
	Data struct {
		IPAddress            string    `json:"ipAddress"`
		IsPublic             bool      `json:"isPublic"`
		IPVersion            int       `json:"ipVersion"`
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		CountryCode          string    `json:"countryCode"`
		UsageType            string    `json:"usageType"`
		Isp                  string    `json:"isp"`
		Domain               string    `json:"domain"`
		Hostnames            []any     `json:"hostnames"`
		IsTor                bool      `json:"isTor"`
		TotalReports         int       `json:"totalReports"`
		NumDistinctUsers     int       `json:"numDistinctUsers"`
	} `json:"data"`
}

// Parse VT api call response body and store it in JSON format
func parseVTOutput(report string) (VTResult, error) {
	var vtReport VTResult
	
	err := json.Unmarshal([]byte(report), &vtReport)
	if err != nil {
		return VTResult{}, fmt.Errorf("failed to parse VT report: %w", err)
	}

	return vtReport, nil
}

// Parse AbuseIPD api call response body and store it in JSON format
func parseAbuseIpOutput(report string) (AbuseIpResult, error) {
	var AbuseIpReport AbuseIpResult
	
	err := json.Unmarshal([]byte(report), &AbuseIpReport)
	if err != nil {
		return AbuseIpResult{}, fmt.Errorf("failed to parse AbuseIPDB report: %w", err)
	}

	return AbuseIpReport, nil
}

// Virus Total output format in Terminal
func formatVTReport(report VTResult) string {
	d := report.Data
	a := d.Attributes

	output := "\n=== VirusTotal Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf(fmtStr, "IP Address:", d.ID)
	output += fmt.Sprintf(fmtStr, "Network:", a.Network)
	output += fmt.Sprintf(fmtStr, "Country:", a.Country)
	output += fmt.Sprintf(fmtStr, "Continent:", a.Continent)
	output += fmt.Sprintf(fmtDec, "ASN:", a.ASN)
	output += fmt.Sprintf(fmtStr, "AS Owner:", a.AsOwner)
	output += fmt.Sprintf(fmtStr, "Regional Internet Registry:", a.RegionalInternetRegistry)
	output += fmt.Sprintf(fmtDec, "Reputation:", a.Reputation)

	if len(a.Tags) > 0 {
		output += fmt.Sprintf(fmtStr, "Tags:", strings.Join(a.Tags, ", "))
	}

	output += "\nLast Analysis Stats\n"
	output += fmt.Sprintf(fmtDec, "Malicious:", a.LastAnalysisStats.Malicious)
	output += fmt.Sprintf(fmtDec, "Suspicious:", a.LastAnalysisStats.Suspicious)
	output += fmt.Sprintf(fmtDec, "Harmless:", a.LastAnalysisStats.Harmless)
	output += fmt.Sprintf(fmtDec, "Undetected:", a.LastAnalysisStats.Undetected)
	output += fmt.Sprintf(fmtDec, "Timeout:", a.LastAnalysisStats.Timeout)

	output += "\nTotal Votes\n"
	output += fmt.Sprintf(fmtDec, "Malicious:", a.TotalVotes.Malicious)
	output += fmt.Sprintf(fmtDec, "Harmless:", a.TotalVotes.Harmless)

	return output
}

// AbuseIPDB output format in Terminal
func formatAbuseIpOutput(report AbuseIpResult) string {
	d := report.Data
	output := "\n=== AbuseIPDB Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf(fmtStr, "IP Address:", d.IPAddress)
	output += fmt.Sprintf(fmtDec, "IP Version:", d.IPVersion)

	if d.IsPublic {
		output += fmt.Sprintf(fmtStr, "IP Type:", "Public")	
	} else {
		output += fmt.Sprintf(fmtStr, "IP Type:", "Private")		
	}

	output += fmt.Sprintf(fmtStr, "Country Code:", d.CountryCode)
	output += fmt.Sprintf(fmtStr, "ISP:", d.Isp)
	output += fmt.Sprintf(fmtStr, "Domain:", d.Domain)
	output += fmt.Sprintf(fmtStr, "Usage Type:", d.UsageType)

	output += "\nRisk Assessment\n"
	output += fmt.Sprintf(fmtDec, "Abuse Confidence Score:", d.AbuseConfidenceScore)
	output += fmt.Sprintf(fmtDec, "Total Reports:", d.TotalReports)
	output += fmt.Sprintf(fmtDec, "Distinct Users Reporting:", d.NumDistinctUsers)
	output += fmt.Sprintf(fmtStr, "Is Tor:", fmt.Sprintf("%v", d.IsTor))
	output += fmt.Sprintf(fmtStr, "Is Whitelisted:", fmt.Sprintf("%v", d.IsWhitelisted))

	return output
}

// fetchVT calls the VirusTotal IP address API and sends the parsed result to ch.
// Runs as a goroutine. All error paths send to ch before returning.
func fetchVT(ip string, key string, ch chan EnrichmentResult) {
	vtUrl := "https://www.virustotal.com/api/v3/ip_addresses/" + ip

	vtReq, err := http.NewRequest("GET", vtUrl, nil)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "VirusTotal",  
			Err: err,
		}
		return
	}
	vtReq.Header.Add("accept", "application/json")
	vtReq.Header.Add("x-apikey", key)
	vtRes, err := http.DefaultClient.Do(vtReq)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "VirusTotal",  
			Err: err,
		}
		return
	}

	defer vtRes.Body.Close()
	vtBody, err := io.ReadAll(vtRes.Body)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "VirusTotal",  
			Err: err,
		}
		return
	}

	vtReport, err := parseVTOutput(string(vtBody))
	if err != nil {
		ch <- EnrichmentResult{
			Source: "VirusTotal",  
			Err: err,
		}
		return
	}
	ch <- EnrichmentResult{
		Source: "VirusTotal",
		Result: vtReport,
		Err: nil,
	}
	return
}

// fetchAbuseIpDb calls the AbuseIPDB check API and sends the parsed result to ch.
// Runs as a goroutine. All error paths send to ch before returning.
func fetchAbuseIpDb(ip string, key string, ch chan EnrichmentResult) {
	abuseIpUrl := "https://api.abuseipdb.com/api/v2/check"

	abuseIpReq, err := http.NewRequest("GET", abuseIpUrl, nil)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "AbuseIPDB",
			Err: err,
		}
		return
	}

	q := abuseIpReq.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	abuseIpReq.Header.Add("Accept", "application/json")
	abuseIpReq.Header.Add("Key", key)	
	abuseIpReq.URL.RawQuery = q.Encode()

	abuseIpRes, err := http.DefaultClient.Do(abuseIpReq)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "AbuseIPDB",
			Err: err,
		}
		return
	}

	defer abuseIpRes.Body.Close() 
	abuseIpBody, err := io.ReadAll(abuseIpRes.Body)	
	if err != nil {
		ch <- EnrichmentResult{
			Source: "AbuseIPDB",
			Err: err,
		}
		return
	}	

	abuseIpReport, err := parseAbuseIpOutput(string(abuseIpBody))
	if err != nil {
		ch <- EnrichmentResult{
			Source: "AbuseIPDB",  
			Err: err,
		}
		return
	}
	ch <- EnrichmentResult{
		Source: "AbuseIPDB",
		Result: abuseIpReport,
		Err: nil,
	}
	return
}

// EnrichIP concurrently queries VirusTotal and AbuseIPDB for the given IP
// and prints a formatted report for each source to stdout.
func EnrichIP(ip string) {
	godotenv.Load()

	if net.ParseIP(ip) == nil {
		fmt.Printf("Invalid IP address: %s\n", ip)
		return
	}
		
	vtApiKey := os.Getenv("VT_API_KEY")
	abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")

	// Buffer size matches number of goroutines so neither blocks on send
	chNum := 2
	ch := make(chan EnrichmentResult, chNum)

	go fetchVT(ip, vtApiKey, ch)
	go fetchAbuseIpDb(ip, abuseIpApiKey, ch)

	for i := 0; i < chNum; i++ {
		result := <- ch
		if result.Err != nil {
			fmt.Println("Error from", result.Source, result.Err)
			return
		}
		// Route result to the correct formatter based on its concrete type
		switch r := result.Result.(type) {
		case VTResult:
			fmt.Println(formatVTReport(r))
		case AbuseIpResult:
			fmt.Println(formatAbuseIpOutput(r))
		}
	}
}