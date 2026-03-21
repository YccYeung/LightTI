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

// TODO comment
type EnrichmentResult struct {
	Source		string
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

type AbuseIpResult struct {
	Data struct {
		IPAddress            string    `json:"ipAddress"`
		IsPublic             bool      `json:"isPublic"`
		IPVersion            int       `json:"ipVersion"`
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		CountryCode          string    `json:"countryCode"`
		CountryName          string    `json:"countryName"`
		UsageType            string    `json:"usageType"`
		Isp                  string    `json:"isp"`
		Domain               string    `json:"domain"`
		Hostnames            []any     `json:"hostnames"`
		IsTor                bool      `json:"isTor"`
		TotalReports         int       `json:"totalReports"`
		NumDistinctUsers     int       `json:"numDistinctUsers"`
		// LastReportedAt       time.Time `json:"lastReportedAt"`
		Reports              []struct {
			// ReportedAt          time.Time `json:"reportedAt"`
			Comment             string    `json:"comment"`
			Categories          []int     `json:"categories"`
			ReporterID          int       `json:"reporterId"`
			ReporterCountryCode string    `json:"reporterCountryCode"`
			ReporterCountryName string    `json:"reporterCountryName"`
		} `json:"reports"`
	} `json:"data"`
}

// TODO Comment
func parseVTOutput(report string) (VTResult, error) {
	var vtReport VTResult
	
	err := json.Unmarshal([]byte(report), &vtReport)
	if err != nil {
		return VTResult{}, fmt.Errorf("failed to parse VT report: %w", err)
	}

	return vtReport, nil
}

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
	fmtStr := "  %-30s %s\n"
	fmtDec := "  %-30s %d\n" 

	output := "\n=== VirusTotal Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf(fmtStr, "IP Address:", d.ID)
	output += fmt.Sprintf(fmtStr, "Network:", a.Network)
	output += fmt.Sprintf(fmtStr, "Country:", a.Country)
	output += fmt.Sprintf(fmtStr, "Continent:", a.Continent)
	output += fmt.Sprintf(fmtDec, "ASN:", a.ASN)
	output += fmt.Sprintf(fmtStr, "AS Owner:", a.AsOwner)
	output += fmt.Sprintf(fmtStr, "Regional Internet Registry:", a.RegionalInternetRegistry)
	output += fmt.Sprintf(fmtStr, "Reputation:", a.Reputation)

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


func formatAbuseIpOutput(report AbuseIpResult) string {
	// TODO
}


// TODO comment
func fetchVT(ip string, key string, ch chan EnrichmentResult) {
	// Send http GET request to retrieve Virus Total IP report 
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
	// TODO comment
	ch <- EnrichmentResult{
		Source: "VirusTotal", 
		Result: vtReport, 
		Err: nil,
	} 
	return
}

// TODO comment
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
	abuseIpReq.Header.Add("Key", os.Getenv("ABUSE_IP_DB_API_KEY"))	
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

	fmt.Println(parseAbuseIpOutput(string(abuseIpBody)))

	// TODO: Send result to channel
	
}

// TODO comment
func EnrichIP(ip string) {
	godotenv.Load()

	if net.ParseIP(ip) == nil {
		fmt.Println("Invalid IP address: %s", ip)
		return
	}
		
	vtApiKey := os.Getenv("VT_API_KEY")

	ch := make(chan EnrichmentResult, 2)

	go fetchVT(ip, vtApiKey, ch)
	go fetchAbuseIpDb(ip, vtApiKey, ch)

	result := <- ch
	if result.Err != nil {
		fmt.Println("Error from", result.Source, result.Err)
		return
	}

	// switch r := result.Result.(type) {
	// case condition:
		
	// }
}