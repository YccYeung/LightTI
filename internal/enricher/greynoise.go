package enricher

import (
	"fmt"
	"net/http"
	"encoding/json"
	"io"
)
	
type GreyNoiseResult struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func parseGreyNoiseOutput(report string) (GreyNoiseResult, error) {
	var GreyNoiseReport GreyNoiseResult
	
	err := json.Unmarshal([]byte(report), &GreyNoiseReport)
	if err != nil {
		return GreyNoiseResult{}, fmt.Errorf("failed to parse Grey Noise report: %w", err)
	}

	return GreyNoiseReport, nil
}

func FormatGreyNoiseOutput(report GreyNoiseResult) string {
	output := "\n=== GreyNoise Report ===\n\n"

	output += "General Information\n"
	output += fmt.Sprintf(fmtStr, "IP:", report.IP)
	output += fmt.Sprintf(fmtStr, "Noise:", fmt.Sprintf("%v", report.Noise))
	output += fmt.Sprintf(fmtStr, "Riot:", fmt.Sprintf("%v", report.Riot))
	if report.Classification == "" {
		output += fmt.Sprintf(fmtStr, "Classification:", "Not observed")
	} else {
		output += fmt.Sprintf(fmtStr, "Classification:", report.Classification)
	}
	if report.Name == "" {
		output += fmt.Sprintf(fmtStr, "Known As:", "Not observed")
	} else {
		output += fmt.Sprintf(fmtStr, "Known As:", report.Name)
	}
	if report.Name == "" {
		output += fmt.Sprintf(fmtStr, "Last Seen:", "Not observed")	
	} else {
		output += fmt.Sprintf(fmtStr, "Last Seen:", report.LastSeen)
	}
	

	return output
}

// fetchGreyNoise calls the Grey Noise API and sends the parsed result to ch.
// Runs as a goroutine. All error paths send to ch before returning.
func fetchGreyNoise(ip string, ch chan EnrichmentResult) {
	GreyNoiseURL := "https://api.greynoise.io/v3/community/" + ip	

	GreyNoiseReq, err := http.NewRequest("GET", GreyNoiseURL, nil)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "GreyNoise",
			Err: err,
		}
		return
	}

	GreyNoiseReq.Header.Add("Accept", "application/json")	

	GreyNoiseRes, err := http.DefaultClient.Do(GreyNoiseReq)
	if err != nil {
		ch <- EnrichmentResult{
			Source: "GreyNoise",
			Err: err,
		}
		return
	}

	defer GreyNoiseRes.Body.Close() 
	GreyNoiseBody, err := io.ReadAll(GreyNoiseRes.Body)	
	if err != nil {
		ch <- EnrichmentResult{
			Source: "GreyNoise",
			Err: err,
		}
		return
	}	

	GreyNoiseReport, err := parseGreyNoiseOutput(string(GreyNoiseBody))
	if err != nil {
		ch <- EnrichmentResult{
			Source: "GreyNoise",  
			Err: err,
		}
		return
	}
	ch <- EnrichmentResult{
		Source: "GreyNoise",
		Result: GreyNoiseReport,
		RawResult: GreyNoiseBody,
		Err: nil,
	}
}