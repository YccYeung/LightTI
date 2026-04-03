package llm

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/YccYeung/LightTI/internal/enricher"
)

// NewProvider reads LLM_PROVIDER from the environment and returns the matching client.
// Defaults to Ollama if the variable is unset.
func NewProvider() LLMProvider {
	switch os.Getenv("LLM_PROVIDER") {
		case "groq":
			return NewGroqClient(os.Getenv("GROQ_MODEL"), os.Getenv("GROQ_URL"), os.Getenv("GROQ_API_KEY"))
		default:
			return NewOllamaClient(os.Getenv("OLLAMA_MODEL"), os.Getenv("OLLAMA_URL"), "")
    }
}

// LLMProvider abstracts the LLM backend so Groq and Ollama are interchangeable.
type LLMProvider interface {
	LLMAnalysis(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error)
}

// BuildPrompt serialises enrichment results into a prompt string.
// Score >= 40 requests a Sigma YAML rule; below that the model is told no rule is needed.
func BuildPrompt(ip string, reports []enricher.EnrichmentResult, totalScore int) (string, error) {
	var summary string

	for _, r := range reports {
		data, err := json.Marshal(r.Result)
		if err != nil {
			continue
		}
		summary += fmt.Sprintf("%s: %s\n", r.Source, string(data))
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