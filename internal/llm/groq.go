package llm

import (
	"fmt"
	"net/http"
	"bytes"
	"encoding/json"
	"io"

	"github.com/YccYeung/LightTI/internal/enricher"
)

type GroqResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int    `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		Logprobs     any    `json:"logprobs"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		QueueTime        float64 `json:"queue_time"`
		PromptTokens     int     `json:"prompt_tokens"`
		PromptTime       float64 `json:"prompt_time"`
		CompletionTokens int     `json:"completion_tokens"`
		CompletionTime   float64 `json:"completion_time"`
		TotalTokens      int     `json:"total_tokens"`
		TotalTime        float64 `json:"total_time"`
	} `json:"usage"`
	SystemFingerprint string `json:"system_fingerprint"`
	XGroq             struct {
		ID string `json:"id"`
	} `json:"x_groq"`
}

type GroqClient struct {
	model		string
	modelURL	string
	apiKey		string
}

func NewGroqClient(llmModel string, url string, key string) *GroqClient {
	return &GroqClient{
		model: llmModel,
		modelURL: url, 
		apiKey: key,
	}
}

func (groq *GroqClient) LLMAnalysis(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error) {
	prompt, err := BuildPrompt(ip, reports, totalScore)
	if err != nil {
		fmt.Println("Error in buildPrompt:", err)
		return "", err	
	} 

	payload := map[string]interface{}{
		"model": groq.model,
		"messages": []map[string]interface{} { 
			{
				"role": "system", 
				"content": "You are a senior SOC analyst specialising in threat intelligence.",
			},
			{
				"role": "user",
				"content": prompt,
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(
		"POST",
		groq.modelURL,
		bytes.NewBuffer(payloadBytes),
	)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer " + groq.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	fmt.Println("\n=== LLM Sigma Rule Generation ===\n")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	var groqResp GroqResponse
	if err := json.Unmarshal(body, &groqResp); err != nil {
		return "", err
	}

	if len(groqResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	output := groqResp.Choices[0].Message.Content

	return output, nil
}