package enricher

import (
	"fmt"
	"net/http"
	"encoding/json"
	"io"
)

// IpToLocationResult holds the fields returned by the ip2location API relevant for threat analysis.
type IpToLocationResult struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	RegionName  string  `json:"region_name"`
	CityName    string  `json:"city_name"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ZipCode     string  `json:"zip_code"`
	TimeZone    string  `json:"time_zone"`
	Asn         string  `json:"asn"`
	As          string  `json:"as"`
	IsProxy     bool    `json:"is_proxy"`
}

// parseIpToLocationOutput unmarshals the ip2location API response body into an IpToLocationResult.
func parseIpToLocationOutput(report string) (IpToLocationResult, error) {
	var IpToLocationReport IpToLocationResult
	
	err := json.Unmarshal([]byte(report), &IpToLocationReport)
	if err != nil {
		return IpToLocationResult{}, fmt.Errorf("failed to parse IpToLocation report: %w", err)
	}

	return IpToLocationReport, nil
}

// FormatIpToLocationOutput renders an IpToLocationResult as a human-readable CLI report.
func FormatIpToLocationOutput(report IpToLocationResult) string {
	output := "\n=== Ip2Location Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf(fmtStr, "IP Address:", report.IP)
	output += fmt.Sprintf(fmtStr, "Country Code:", report.CountryCode)
	output += fmt.Sprintf(fmtStr, "Country:", report.CountryName)
	output += fmt.Sprintf(fmtStr, "Region:", report.RegionName)
	output += fmt.Sprintf(fmtStr, "City:", report.CityName)
	output += fmt.Sprintf(fmtStr, "Zip Code:", report.ZipCode)
	output += fmt.Sprintf(fmtStr, "Time Zone:", fmt.Sprintf("%v", report.TimeZone))
	output += fmt.Sprintf(fmtStr, "ASN", report.Asn)
	output += fmt.Sprintf(fmtStr, "AS:", report.As)
	output += fmt.Sprintf(fmtStr, "Is Proxy:", fmt.Sprintf("%v", report.IsProxy))

	return output
}

// fetchIpToLocation calls the ip2location API and sends the parsed result to ch.
// Runs as a goroutine. All error paths send to ch before returning.
func fetchIpToLocation(ip string, ch chan EnrichmentResult) {
	ipToLocationURL := "https://api.ip2location.io/"	

	ipToLocationReq, err := http.NewRequest("GET", ipToLocationURL, nil)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "IpToLocation",
			Err: err,
		}
		return
	}

	q := ipToLocationReq.URL.Query()
	q.Add("ip", ip)
	q.Add("format", "json")
	ipToLocationReq.Header.Add("Accept", "application/json")	
	ipToLocationReq.URL.RawQuery = q.Encode()

	ipToLocationRes, err := http.DefaultClient.Do(ipToLocationReq)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "IpToLocation",
			Err: err,
		}
		return
	}

	defer ipToLocationRes.Body.Close() 
	ipToLocationBody, err := io.ReadAll(ipToLocationRes.Body)	
	if err != nil {
		ch <- EnrichmentResult{
			Source: "IpToLocation",
			Err: err,
		}
		return
	}	

	ipToLocationReport, err := parseIpToLocationOutput(string(ipToLocationBody))
	if err != nil {
		ch <- EnrichmentResult{
			Source: "IpToLocation",  
			Err: err,
		}
		return
	}
	ch <- EnrichmentResult{
		Source: "IpToLocation",
		Result: ipToLocationReport,
		RawResult: ipToLocationBody, 
		Err: nil,
	}
}