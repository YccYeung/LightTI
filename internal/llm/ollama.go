package llm

import (
	"fmt"
	"net/http"
	"bytes"
	"encoding/json"
	"bufio"
	"strings"

	"github.com/YccYeung/LightTI/internal/enricher"
)

func buildPrompt(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error) {
	var summary string
	
	for _, r := range reports {
		switch r.Source {
		case "VirusTotal":
			data, err := json.Marshal(r.Result.(enricher.VTResult))
			if err != nil {
   	 			continue
			}
			summary += fmt.Sprintf("VirusTotal: %s\n", string(data))
		case "AbuseIPDB":
			data, err := json.Marshal(r.Result.(enricher.AbuseIpResult))
			if err != nil {
   	 			continue
			}
			summary += fmt.Sprintf("AbuseIPDB: %s\n", string(data))
		case "GreyNoise":
			data, err := json.Marshal(r.Result.(enricher.GreyNoiseResult))
			if err != nil {
   	 			continue
			}
			summary += fmt.Sprintf("GreyNoise: %s\n", string(data))
		case "IpToLocation":
			data, err := json.Marshal(r.Result.(enricher.IpToLocationResult))
			if err != nil {
   	 			continue
			}
			summary += fmt.Sprintf("IP2Location: %s\n", string(data))
		}
	}

    var prompt string
    if totalScore >= 40 {
        prompt = fmt.Sprintf(
            "A senior SOC analyst is reviewing threat intelligence for IP %s. "+
            "Based on the following data: %s. "+
            "Generate a Sigma detection rule in YAML for this IP. "+
            "Output only the YAML Sigma rule. No preamble, no explanation.",
            ip, summary,
        )
    } else {
        prompt = fmt.Sprintf(
            "A senior SOC analyst is reviewing threat intelligence for IP %s. "+
            "Based on the following data: %s. "+
            "Output only this single sentence: 'No Sigma rule required — IP appears benign.'",
            ip, summary,
        )
    }

    return prompt, nil
}

func LLMAnalysis(ip string, reports []enricher.EnrichmentResult, totalScore int, model string, llmURL string) (string, error) {
	prompt, _ := buildPrompt(ip, reports, totalScore) 

	payload := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": true,
	}

	payloadBytes, _ := json.Marshal(payload)

	resp, err := http.Post(
		llmURL,
		"application/json",
		bytes.NewBuffer(payloadBytes),
	)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	defer resp.Body.Close()

	fmt.Println("\n=== LLM Sigma Rule Generation ===\n")

	// Read the streaming response line by line
	scanner := bufio.NewScanner(resp.Body)
	var output strings.Builder
	for scanner.Scan() {
		var result map[string]interface{}
		json.Unmarshal(scanner.Bytes(), &result)

		// Print each chunk of text as it arrives
		if text, ok := result["response"].(string); ok {
			fmt.Print(text)
			output.WriteString(text)
		}
	}

	return output.String(), nil
}