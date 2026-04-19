package score

import (
	"fmt"
	"math"
)

// FormatScore renders a TotalScore into a human-readable CLI summary,
// showing the overall risk level and a per-source point breakdown.
func FormatScore(ts TotalScore) string {
	output := "\n=== Unified Threat Summary ===\n"
	output += "\n=== Threat Score ===\n\n"

	// Overall threat level
	if ts.Total < 40 {
		output += fmt.Sprintf("  Total Score:    %d/100 — Low Risk\n", ts.Total)
	} else if ts.Total < 80 {
		output += fmt.Sprintf("  Total Score:    %d/100 — Medium Risk\n", ts.Total)
	} else {
		output += fmt.Sprintf("  Total Score:    %d/100 — High Risk\n", ts.Total)
	}

	// VirusTotal
	output += fmt.Sprintf("\n  VirusTotal:     %d/40\n", ts.VirusTotal.Score)
	if ts.VirusTotal.Details["Reputation"].Points > 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.VirusTotal.Details["Reputation"].Points, ts.VirusTotal.Details["Reputation"].Comment)
	}
	if ts.VirusTotal.Details["Malicious"].Points > 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.VirusTotal.Details["Malicious"].Points, ts.VirusTotal.Details["Malicious"].Comment)
	}
	if ts.VirusTotal.Details["Suspicious"].Points > 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.VirusTotal.Details["Suspicious"].Points, ts.VirusTotal.Details["Suspicious"].Comment)
	}

	// AbuseIPDB
	output += fmt.Sprintf("\n  AbuseIPDB:      %d/40\n", ts.AbuseIPDB.Score)
	output += fmt.Sprintf("    + %dpts  %s\n", ts.AbuseIPDB.Details["Abuse Confident"].Points, ts.AbuseIPDB.Details["Abuse Confident"].Comment)

	// GreyNoise
	output += fmt.Sprintf("\n  GreyNoise:      %d/20\n", ts.GreyNoise.Score)
	if ts.GreyNoise.Details["Noise"].Points > 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.GreyNoise.Details["Noise"].Points, ts.GreyNoise.Details["Noise"].Comment)
	} else if ts.GreyNoise.Details["Noise"].Points < 0 {
		output += fmt.Sprintf("    - %dpts  %s\n", ts.GreyNoise.Details["Noise"].Points, ts.GreyNoise.Details["Noise"].Comment)
	} 
	if ts.GreyNoise.Details["Riot"].Points >= 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.GreyNoise.Details["Riot"].Points, ts.GreyNoise.Details["Riot"].Comment)
	} else {
		output += fmt.Sprintf("    - %dpts  %s\n", int(math.Abs(float64(ts.GreyNoise.Details["Riot"].Points))), ts.GreyNoise.Details["Riot"].Comment)	
	}
	if ts.GreyNoise.Details["Classification"].Points != 0 {
		output += fmt.Sprintf("    + %dpts  %s\n", ts.GreyNoise.Details["Classification"].Points, ts.GreyNoise.Details["Classification"].Comment)
	}

	return output
}