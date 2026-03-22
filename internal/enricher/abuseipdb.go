package enricher

import (
	"fmt"
	"net/http"
	"encoding/json"
	"io"
)

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

// Parse AbuseIPD api call response body and store it in JSON format
func parseAbuseIpOutput(report string) (AbuseIpResult, error) {
	var AbuseIpReport AbuseIpResult
	
	err := json.Unmarshal([]byte(report), &AbuseIpReport)
	if err != nil {
		return AbuseIpResult{}, fmt.Errorf("failed to parse AbuseIPDB report: %w", err)
	}

	return AbuseIpReport, nil
}

// AbuseIPDB output format in Terminal
func FormatAbuseIpOutput(report AbuseIpResult) string {
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
		RawResult: abuseIpBody,
		Err: nil,
	}
}