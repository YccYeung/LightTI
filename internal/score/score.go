package score

import (
	"fmt"
	// "github.com/YccYeung/LightTI/internal/enricher"
)

func placeholder() {
	fmt.Println("TBD")
}


// type TotalScore struct {
// 	AbuseIPDB	ScoreBreakdown
// 	VirusTotal	ScoreBreakdown
// 	GreyNoise	ScoreBreakdown
// }

// type ScoreBreakdown struct {
// 	Details		map[string]ScoreDetail
// 	Score       int
// }

// type ScoreDetail struct {
// 	Points		int
// 	Comment		string
// }

// func scoreVT(result enricher.EnrichmentResult) ScoreBreakdown {
// 	var summary ScoreBreakdown
// 	r := result.Result.(enricher.VirusTotal)
// 	thr

// 	// TODO

// }

// func scoreAbuseIPDB(result enricher.EnrichmentResult) ScoreBreakdown {
// 	var d ScoreDetail
// 	var s ScoreBreakdown

// 	r, ok := result.Result.(enricher.AbuseIpResult)
// 	if !ok {
// 		return s
// 	}

// 	d.Points = int(float64(r.Data.AbuseConfidenceScore) * 0.4)
// 	d.Comment = "Adjusted scale of AbuseIPDB Confident Score, from 0 - 40"

// 	s.Details = make(map[string]ScoreDetail)
// 	s.Score = d.Points
// 	s.Details["AbuseIPDB Confident Score"] = d
	
// 	return s
// }

// func scoreGreyNoise(result enricher.EnrichmentResult) ScoreBreakdown {
// 	var s ScoreBreakdown
// 	r, ok := result.Result.(enricher.GreyNoiseResult)
// 	if !ok {
// 		return s
// 	}

// 	if r.Noise {
// 		var detailNoise ScoreDetail
// 		detailNoise.Points += 5
// 		detailNoise.Comment = "Noise means xyz"
// 		s.Details["Noise"] = detailNoise
// 		s.Score += 5
// 	} 

// 	if r.Riot && r.LastSeen == "" {
// 		total += 10
// 	} else {
// 		total -= 5
// 	} 

// 	if r.Classification == "Benign" {
// 		total -= 10
// 	} else if r.Classification == "Not observed" {
// 		total += 0
// 	} else if r.Classification == "Suspicious" {
// 		total += 5
// 	} else if r.Classification == "Unknown" {
// 		total += 10
// 	} else {
// 		total += 15
// 	}

// 	if total < 0 {
// 		total = 0
// 	} else if total > 30 {
// 		total = 30
// 	}

// 	return s 
// }

// func ScoreProcessing(result []enricher.EnrichmentResult) TotalScore {
// 	var total TotalScore
// 	// need a for loop
// 	switch result.Source {
// 	case "VirusTotal":
// 		total.VirusTotal = scoreVT(result)
// 	case "AbuseIPDB":
// 		total.AbuseIPDB = scoreAbuseIPDB(result)
// 	case "GreyNoise":
// 		total.GreyNoise = scoreGreyNoise(result)	
// 	}

//     return total
// }