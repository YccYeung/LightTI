package score

import (
	"fmt"
	"github.com/YccYeung/LightTI/internal/enricher"
)

type TotalScore struct {
	AbuseIPDB	ScoreBreakdown
	VirusTotal	ScoreBreakdown
	GreyNoise	ScoreBreakdown
	Total      	int 
}

type ScoreBreakdown struct {
	Details		map[string]ScoreDetail
	Score       int
}

type ScoreDetail struct {
	Points		int
	Comment		string
}

func scoreVT(result enricher.EnrichmentResult) ScoreBreakdown {
	var s ScoreBreakdown
	s.Details = make(map[string]ScoreDetail)

	r, ok := result.Result.(enricher.VTResult)
	if !ok {
		return s
	}
	
	a := r.Data.Attributes
	l := a.LastAnalysisStats

	var detailRuputation ScoreDetail
	var detailMalicious	ScoreDetail
	var detailSuspicious ScoreDetail

	if a.Reputation < 0 {
		detailRuputation.Points = 5
		detailRuputation.Comment = fmt.Sprintf("Negative reputation score (%d) in VirusTotal Community", a.Reputation)
		s.Details["Reputation"]	= detailRuputation
		s.Score += 5
	}

	detailMalicious.Points = l.Malicious * 5
	detailMalicious.Comment = fmt.Sprintf("%d Malicious detections from VirusTotal", l.Malicious)
	s.Details["Malicious"] = detailMalicious
	s.Score += detailMalicious.Points

	detailSuspicious.Points = l.Suspicious * 3
	detailSuspicious.Comment = fmt.Sprintf("%d Suspicious detections from VirusTotal", l.Suspicious)
	s.Details["Suspicious"] = detailSuspicious
	s.Score += detailSuspicious.Points

	if s.Score > 40 {
		s.Score = 40
	}

	return s
}

func scoreAbuseIPDB(result enricher.EnrichmentResult) ScoreBreakdown {
	var s ScoreBreakdown
	s.Details = make(map[string]ScoreDetail)
	
	r, ok := result.Result.(enricher.AbuseIpResult)
	if !ok {
		return s
	}

	var d ScoreDetail

	d.Points = int(float64(r.Data.AbuseConfidenceScore) * 0.3)
	d.Comment = "Adjusted scale of AbuseIPDB Confident Score, from 0 - 30"

	s.Score = d.Points
	s.Details["Abuse Confident"] = d
	
	return s
}

func scoreGreyNoise(result enricher.EnrichmentResult) ScoreBreakdown {
	var s ScoreBreakdown
	s.Details = make(map[string]ScoreDetail)

	var detailNoise ScoreDetail
	var detailRiot ScoreDetail
	var detailClassification ScoreDetail

	r, ok := result.Result.(enricher.GreyNoiseResult)
	if !ok {
		return s
	}

	if r.Noise {
		detailNoise.Points = 5
		detailNoise.Comment = "IP is observed in widespread, untargeted internet background traffic (botnets, crawlers, research scanners)"
		s.Details["Noise"] = detailNoise
		s.Score += 5
	} 

	if r.Riot {
		detailRiot.Points = -5
		detailRiot.Comment = "IP belongs to a known-benign service (e.g. Google, Cloudflare), likely a false positive"
		s.Details["Riot"] = detailRiot
		s.Score -= 5
	} else if !r.Riot && r.LastSeen != "Not Observed" {
		detailRiot.Points = 5
		detailRiot.Comment = "IP DOES NOT belongs to a known-benign service (e.g. Google, Cloudflare)"
		s.Details["Riot"] = detailRiot
		s.Score += 5
	} else {
		detailRiot.Points = 0
		detailRiot.Comment = "GreyNoise has no information on this IP"
		s.Details["Riot"] = detailRiot	
	}

	if r.Classification == "Benign" {
		detailClassification.Points = -10
		detailClassification.Comment = "IP classified as Benign by GreyNoise"
		s.Details["Classification"] = detailClassification
		s.Score -= 10
	} else if r.Classification == "Suspicious" {
		detailClassification.Points = 5
		detailClassification.Comment = "IP classified as Suspicious by GreyNoise"
		s.Details["Classification"] = detailClassification
		s.Score += 5
	} else if r.Classification == "Unknown" {
		detailClassification.Points = 10
		detailClassification.Comment = "IP classified as Unknown by GreyNoise"
		s.Details["Classification"] = detailClassification
		s.Score += 10
	} else if r.Classification == "Malicious" {
		detailClassification.Points = 15
		detailClassification.Comment = "IP classified as Malicious by GreyNoise"
		s.Details["Classification"] = detailClassification
		s.Score += 15
	} else {
		detailClassification.Points = 0
		detailClassification.Comment = "GreyNoise has no classification on this IP"
		s.Details["Classification"] = detailClassification
	}

	if s.Score < 0 {
		s.Score = 0
	} else if s.Score > 30 {
		s.Score = 30
	}

	return s 
}

func ScoreProcessing(result []enricher.EnrichmentResult) TotalScore {
	var total TotalScore
	for _, r := range result {
		switch r.Source {
		case "VirusTotal":
			total.VirusTotal = scoreVT(r)
		case "AbuseIPDB":
			total.AbuseIPDB = scoreAbuseIPDB(r)
		case "GreyNoise":
			total.GreyNoise = scoreGreyNoise(r)	
		}
	}

	total.Total = total.AbuseIPDB.Score + total.VirusTotal.Score + total.GreyNoise.Score

    return total
}