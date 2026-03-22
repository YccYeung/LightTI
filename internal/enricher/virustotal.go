package enricher

import (
	"fmt"
	"net/http"
	"encoding/json"
	"io"
	"strings"
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

// Parse VT api call response body and store it in JSON format
func parseVTOutput(report string) (VTResult, error) {
	var vtReport VTResult
	
	err := json.Unmarshal([]byte(report), &vtReport)
	if err != nil {
		return VTResult{}, fmt.Errorf("failed to parse VT report: %w", err)
	}

	return vtReport, nil
}

// Virus Total output format in Terminal
func FormatVTReport(report VTResult) string {
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
		RawResult: vtBody,
		Err: nil,
	}
}