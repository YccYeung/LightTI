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

type OllamaClient struct {
	model		string
	modelURL	string
	apiKey		string
}

func NewOllamaClient(llmModel string, url string, key string) *OllamaClient {
	return &OllamaClient{
		model: llmModel, 
		modelURL: url, 
		apiKey: key,
	}
}

func (ollama *OllamaClient) LLMAnalysis(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error) {
	prompt, err := BuildPrompt(ip, reports, totalScore)
	if err != nil {
		fmt.Println("Error in buildPrompt:", err)
		return "", err	
	} 

	payload := map[string]interface{}{
		"model":  ollama.model,
		"prompt": prompt,
		"stream": true,
	}

	payloadBytes, _ := json.Marshal(payload)

	resp, err := http.Post(
		ollama.modelURL,
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
			output.WriteString(text)
		}
	}

	return output.String(), nil
}