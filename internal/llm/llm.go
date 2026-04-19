package llm

import (
	"encoding/json"
	"fmt"
	"os"
    "strings"

	"github.com/YccYeung/LightTI/internal/enricher"
    "github.com/YccYeung/LightTI/internal/command"
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
    CommandLLMAnalysis(result command.CommandResult) (string, error)
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

func BuildCommandAnalysisPrompt(result command.CommandResult) (string, error) {
    var summary string
    
    summary += fmt.Sprintf("%s: %s\n", "original command", result.RawCommand)
    summary += fmt.Sprintf("%s: %s\n", "Operating Systems", result.ParsedCommand.OS)
    summary += fmt.Sprintf("%s: %s\n", "Executable", result.ParsedCommand.Executable)
    summary += fmt.Sprintf("%s: %s\n", "Full Path", result.ParsedCommand.FullPath) 
    for _, args := range result.ParsedCommand.Args {
        summary += fmt.Sprintf("%s: %s\n", "Arguments", args)  
    }
    
    if result.LOLBasResult != nil {
        summary += fmt.Sprintf("LOLBas findings: %s\n", result.LOLBasResult.Description)
        summary += fmt.Sprintf("MITRE techniques: %s\n", strings.Join(result.LOLBasResult.MITRE, ", "))
        summary += fmt.Sprintf("Known usecases: %s\n", strings.Join(result.LOLBasResult.Usecases, ", "))
    }
    
    if result.GTFOBinsResult != nil {
        summary += fmt.Sprintf("GTFOBins functions: %s\n", strings.Join(result.GTFOBinsResult.Functions, ", "))
    }

    prompt := fmt.Sprintf(
        "You are a senior software engineer with expertise in security and malware analysis investigating a suspicious command execution alert.\n\n"+
        "Analyse the following command and respond in EXACTLY this format with no additional text:\n\n"+
        "1. Risk Level: [Low/Medium/High/Critial] - [one sentence justification]\n"+
        "2. Source: [what application or system this command originates from]\n"+
        "3. Intent: [list EACH argument on a new line with format 'argument → explanation', then add an Overall line summarising the objective]\n"+
        "4. Recommended Actions: [specific analyst actions to take]\n\n"+
        "Command details:\n%s",
        summary,
    )

    return prompt, nil
}