package llm

import (
	"fmt"
	"net/http"
	"bytes"
	"encoding/json"
	"bufio"
	"strings"
	"os"

	"github.com/YccYeung/LightTI/internal/enricher"
	"github.com/YccYeung/LightTI/internal/command"
)

// OllamaClient implements LLMProvider using a locally running Ollama instance.
type OllamaClient struct {
	model		string
	modelURL	string
	apiKey		string
}

// NewOllamaClient constructs an OllamaClient with the given model and endpoint URL.
func NewOllamaClient(llmModel string, url string, key string) *OllamaClient {
	return &OllamaClient{
		model: llmModel, 
		modelURL: url, 
		apiKey: key,
	}
}

func (ollama *OllamaClient) callOllama(prompt string) (string, error) {
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

	scanner := bufio.NewScanner(resp.Body)
	var output strings.Builder
	for scanner.Scan() {
		var result map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil{
			fmt.Fprintf(os.Stderr, "failed to unmarshal json %v\n", err)
			continue
		}

		if text, ok := result["response"].(string); ok {
			output.WriteString(text)
		}
	}

	return output.String(), nil	
}

// LLMAnalysis builds a prompt, streams the Ollama response line by line, and returns the assembled output.
// Ollama's generate API emits one JSON object per line with a "response" field rather than a single payload.
func (ollama *OllamaClient) LLMAnalysis(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error) {
	prompt, err := BuildPrompt(ip, reports, totalScore)
	if err != nil {
		fmt.Println("Error in buildPrompt:", err)
		return "", err	
	} 
	return ollama.callOllama(prompt)
}

func (ollama *OllamaClient) CommandLLMAnalysis(result command.CommandResult) (string, error) {
	prompt, err := BuildCommandAnalysisPrompt(result)
	if err != nil {
		fmt.Println("Error in buildPrompt:", err)
		return "", err		
	}
	return ollama.callOllama(prompt)
}	