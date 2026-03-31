# LightTI

**Live Demo: [https://light-ti.vercel.app](https://light-ti.vercel.app)**

LightTI is a threat intelligence enrichment platform that automates IOC (Indicator of Compromise) investigation for SOC analysts. Instead of querying multiple sources manually and piecing results together, LightTI aggregates enrichment data from four threat intelligence sources into a single interface.

What sets LightTI apart from similar tools:

- **Unified risk scoring**: a weighted scoring system (0-100) across VirusTotal, AbuseIPDB, and GreyNoise provides immediate threat context, collapsing the search-then-analyse workflow into one step.
- **LLM-powered Sigma rule generation**: for high-risk IOCs, LightTI can generate a Sigma detection rule ready to paste directly into a SIEM, giving analysts a head start on custom detection.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Go, Gin, pgx |
| Frontend | React, TypeScript |
| Database | PostgreSQL (Supabase) |
| LLM | Groq (production), Ollama (local dev) |
| Deployment | GCP Cloud Run, Vercel |
| Containerisation | Docker (multi-stage build) |

---

## Architecture

![LightTI Architecture](architecture.svg)

The enrichment engine queries threat intel sources concurrently using goroutines and a fan-out/fan-in channel pattern, minimising latency.

---

## Features

- IP enrichment across VirusTotal, AbuseIPDB, GreyNoise, and IpToLocation
- Weighted threat scoring with per-source score breakdowns and reasoning
- LLM-powered Sigma rule generation for high-risk IPs (score >= 40)
- REST API with persistent storage of all lookups
- React dashboard with cyber/terminal aesthetic and progressive LLM loading
- CLI with `enrich` and `server` subcommands

---

## Local Development

### Prerequisites

- Go 1.25+
- Node.js 18+
- Docker (for local PostgreSQL)
- Ollama (optional, for local LLM)

### Backend setup

1. Clone the repository:
```bash
git clone https://github.com/YccYeung/LightTI.git
cd LightTI
```

2. Copy and fill in environment variables:
```bash
cp .env.example .env
```

Required variables:
```
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/lightti?sslmode=disable
VT_API_KEY=your_virustotal_key
ABUSE_IP_DB_API_KEY=your_abuseipdb_key
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3
OLLAMA_URL=http://localhost:11434/api/generate
GROQ_API_KEY=your_groq_key
GROQ_MODEL=llama-3.1-8b-instant
GROQ_URL=https://api.groq.com/openai/v1/chat/completions
```

3. Start a local PostgreSQL instance:
```bash
docker run -d --name lightti-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=lightti -p 5432:5432 postgres:16
```

4. Run database migrations:
```bash
migrate -path migrations -database "postgresql://postgres:postgres@localhost:5432/lightti?sslmode=disable" up
```

5. Start the API server:
```bash
go run ./cmd/lightti server
```

### Frontend setup

```bash
cd frontend
cp .env.local.example .env.local
# Set REACT_APP_API_URL=http://localhost:8080
npm install
npm start
```

### CLI usage

```bash
# Enrich an IP
go run ./cmd/lightti enrich --ip 1.1.1.1

# Enrich with LLM Sigma rule generation
go run ./cmd/lightti enrich --ip 1.1.1.1 --llm
```

---

## Deployment

The production stack uses GCP Cloud Run for the backend and Vercel for the frontend.

### Backend (GCP Cloud Run)

```bash
# Build for linux/amd64 (required for M-series Macs)
docker build --platform linux/amd64 -t lightti .
docker tag lightti europe-west2-docker.pkg.dev/YOUR_PROJECT/lightti/lightti:latest
docker push europe-west2-docker.pkg.dev/YOUR_PROJECT/lightti/lightti:latest

gcloud run deploy lightti \
  --image europe-west2-docker.pkg.dev/YOUR_PROJECT/lightti/lightti:latest \
  --platform managed \
  --region europe-west2 \
  --allow-unauthenticated \
  --port 8080
```

Set environment variables on Cloud Run:
```bash
gcloud run services update lightti \
  --region europe-west2 \
  --set-env-vars "DATABASE_URL=...,GROQ_API_KEY=...,LLM_PROVIDER=groq,..."
```

### Frontend (Vercel)

Connect your GitHub repository to Vercel, set the root directory to `frontend`, and add the environment variable:
```
REACT_APP_API_URL=https://your-cloud-run-url.run.app
```

Vercel auto-deploys on every push to `main`.

---

## Roadmap

- [ ] Domain enrichment (WHOIS, DNS, VirusTotal domain scan)
- [ ] File hash enrichment (MD5, SHA1, SHA256 via VirusTotal)
- [ ] Lookup history endpoint and dashboard view
- [ ] Redis caching for repeated IOC lookups
- [ ] Batch processing for multiple IOCs
- [ ] Export enrichment report as PDF

---

## API Reference

### POST /enrich

Enrich an IP address against all threat intelligence sources.

**Request:**
```json
{
  "ioc": "1.1.1.1",
  "ioc_type": "ip"
}
```

**Query params:**
- `?llm=true` — enable Sigma rule generation

**Response:**
```json
{
  "lookup_id": "uuid",
  "score": {
    "Total": 85,
    "VirusTotal": { "Score": 40, "Details": {} },
    "AbuseIPDB": { "Score": 40, "Details": {} },
    "GreyNoise": { "Score": 5, "Details": {} }
  },
  "results": [],
  "llm_analysis": "Sigma rule YAML..."
}
```

---

## Scoring System

| Source | Max Score | Factors |
|---|---|---|
| VirusTotal | 40 | Malicious detections, suspicious detections, reputation |
| AbuseIPDB | 40 | Abuse confidence score |
| GreyNoise | 20 | Classification, RIOT membership |
| **Total** | **100** | |

Threat levels: Low < 40, Medium 40-79, High >= 80