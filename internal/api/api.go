package api

import (
	"fmt"
	"os"

	"github.com/YccYeung/LightTI/internal/enricher"
	"github.com/YccYeung/LightTI/internal/store"
	"github.com/YccYeung/LightTI/internal/score"
	"github.com/YccYeung/LightTI/internal/llm"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

type EnrichmentRequest struct {
	Ioc		string 	`json:"ioc"`
	IocType	string	`json:"ioc_type"`
}

type Handler struct {
    store 		store.Store
	vtApiKey    string
    abuseKey    string
	model		string
	llmURL		string
}

// NewHandler injects all dependencies into the Handler so routes share a single store and API key set.
func NewHandler(store store.Store, vtApiKey string, abuseKey string, model string, llmURL string) *Handler {
	return &Handler{
		store: store,
		vtApiKey: vtApiKey,
        abuseKey: abuseKey,
		model:	model,
		llmURL:	llmURL,
	}
}

// PostEnrich handles POST /enrich: fans out enrichment, scores, persists, and optionally runs LLM analysis.
// Pass ?llm=true as a query param to trigger Sigma rule generation.
func (h *Handler) PostEnrich(c *gin.Context) {
	var req	EnrichmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
        return
	}

	enrichmentList := enricher.EnrichIP(req.Ioc, h.vtApiKey, h.abuseKey)
	totalScore := score.ScoreProcessing(enrichmentList)

	ctx := c.Request.Context()
	lookupID, err := h.store.SaveLookup(ctx, req.Ioc, req.IocType)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to save lookup"})
		return
	}

	for _, result := range enrichmentList {
		errMsg := ""
		if result.Err != nil {
			fmt.Printf("Error from %s: %v\n", result.Source, result.Err)
			errMsg = result.Err.Error()
		}
		
		if err := h.store.SaveResult(ctx, lookupID, result.Source, result.RawResult, errMsg); err != nil {
			fmt.Fprintf(os.Stderr, "failed to save result: %v\n", err)
		}
	}

	llmParam := c.Query("llm")
	var llmAnalysis string
	if llmParam == "true" {
		provider := llm.NewProvider()
		llmAnalysis, err = provider.LLMAnalysis(req.Ioc, enrichmentList, totalScore.Total)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LLM analysis failed: %v\n", err)
		}
	}
	
	c.JSON(200, gin.H{
		"lookup_id":    lookupID,
		"score":        totalScore,
		"results":      enrichmentList,
		"llm_analysis": llmAnalysis,
	})
}

func (h *Handler) GetHistory(c *gin.Context) {
	// TODO
}

// SetupRouter registers all routes and applies CORS middleware, allowing the React frontend and local dev to call the API.
func SetupRouter(h *Handler) *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
        AllowOrigins: []string{
			"http://localhost:3000",
			"https://light-ti.vercel.app",
		},
        AllowMethods: []string{"GET", "POST"},
        AllowHeaders: []string{"Content-Type"},
    }))

    r.POST("/enrich", h.PostEnrich)
    r.GET("/history", h.GetHistory)
    return r
}