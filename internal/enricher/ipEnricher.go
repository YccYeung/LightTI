package enricher

import (
	"fmt"
	"os"
	"net"
	"net/http"
	// "log"
	"io"

	"github.com/joho/godotenv"
)

type scanResult struct {
	serviceName		string
	ip				string
	// add some other fields later
}

func sanitizeVTOutput(report string) {
	// Sanitize VT Scan Result and put nessary informaiton into scanResult struct
}

func EnrichIP(ip string) {
	godotenv.Load()
	
	vtApiKey := os.Getenv("VT_API_KEY")

	if net.ParseIP(ip) == nil {
		fmt.Fprintf(os.Stderr, "invalid IP address: %s\n", ip)
		return
	}

	vtUrl := "https://www.virustotal.com/api/v3/ip_addresses/" + ip

	vtReq, _ := http.NewRequest("GET", vtUrl, nil)
	vtReq.Header.Add("accept", "application/json")
	vtReq.Header.Add("x-apikey", vtApiKey)
	vtRes, err := http.DefaultClient.Do(vtReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return
	}

	defer vtRes.Body.Close()
	vtBody, _ := io.ReadAll(vtRes.Body)

	fmt.Println(string(vtBody))
}