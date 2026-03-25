package api

import (
	"fmt"
	"os"
	// "net/http"

	"github.com/YccYeung/LightTI/internal/enricher"
	"github.com/YccYeung/LightTI/internal/store"
	"github.com/YccYeung/LightTI/internal/score"

	"github.com/gin-gonic/gin"
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

func NewHandler(store store.Store, vtApiKey string, abuseKey string, model string, llmURL string) *Handler {
	return &Handler{
		store: store,
		vtApiKey: vtApiKey,
        abuseKey: abuseKey,
		model:	model,
		llmURL:	llmURL,
	}
}

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

	c.JSON(200, gin.H{
		"lookup_id": lookupID,
		"score":     totalScore,
		"results":   enrichmentList,
	})
}

func (h *Handler) GetHistory(c *gin.Context) {
	
}

func SetupRouter(h *Handler) *gin.Engine {
	r := gin.Default()
    r.POST("/enrich", h.PostEnrich)
    r.GET("/history", h.GetHistory)
    return r
}