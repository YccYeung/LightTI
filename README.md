# LightTI

**Live Demo: [https://light-ti.vercel.app](https://light-ti.vercel.app)**

LightTI is a threat intelligence enrichment platform that automates IOC (Indicator of Compromise) investigation for SOC analysts. Instead of querying multiple sources manually and piecing results together, LightTI aggregates enrichment data from four threat intelligence sources into a single interface.

What sets LightTI apart from similar tools:

- **Unified risk scoring** — a weighted scoring system (0-100) across VirusTotal, AbuseIPDB, and GreyNoise provides immediate threat context, collapsing the search-then-analyse workflow into one step.
- **LLM-powered Sigma rule generation** — for high-risk IOCs, LightTI can generate a Sigma detection rule ready to paste directly into a SIEM, giving analysts a head start on custom detection.

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

<svg width="100%" viewBox="0 0 680 420" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>

  <!-- User -->
  <rect x="40" y="170" width="90" height="44" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#2C2C2A" x="85" y="192" text-anchor="middle" dominant-baseline="central">User</text>

  <!-- Arrow user -> vercel -->
  <line x1="130" y1="192" x2="168" y2="192" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>

  <!-- Vercel / Frontend -->
  <rect x="168" y="158" width="120" height="68" rx="8" fill="#EEEDFE" stroke="#534AB7" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#3C3489" x="228" y="183" text-anchor="middle" dominant-baseline="central">Vercel</text>
  <text font-family="sans-serif" font-size="12" fill="#534AB7" x="228" y="203" text-anchor="middle" dominant-baseline="central">React + TypeScript</text>

  <!-- Arrow vercel -> cloud run -->
  <line x1="288" y1="192" x2="326" y2="192" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>

  <!-- Cloud Run / Backend -->
  <rect x="326" y="158" width="130" height="68" rx="8" fill="#E1F5EE" stroke="#0F6E56" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#085041" x="391" y="183" text-anchor="middle" dominant-baseline="central">Cloud Run</text>
  <text font-family="sans-serif" font-size="12" fill="#0F6E56" x="391" y="203" text-anchor="middle" dominant-baseline="central">Go + Gin API</text>

  <!-- Arrow cloud run -> supabase -->
  <line x1="391" y1="226" x2="391" y2="264" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>

  <!-- Supabase -->
  <rect x="326" y="264" width="130" height="68" rx="8" fill="#E6F1FB" stroke="#185FA5" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#0C447C" x="391" y="289" text-anchor="middle" dominant-baseline="central">Supabase</text>
  <text font-family="sans-serif" font-size="12" fill="#185FA5" x="391" y="309" text-anchor="middle" dominant-baseline="central">PostgreSQL</text>

  <!-- Arrow cloud run -> groq -->
  <line x1="456" y1="192" x2="494" y2="192" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>

  <!-- Groq -->
  <rect x="494" y="158" width="110" height="68" rx="8" fill="#FAEEDA" stroke="#854F0B" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#633806" x="549" y="183" text-anchor="middle" dominant-baseline="central">Groq</text>
  <text font-family="sans-serif" font-size="12" fill="#854F0B" x="549" y="203" text-anchor="middle" dominant-baseline="central">LLM inference</text>

  <!-- Single threat intel box -->
  <rect x="290" y="18" width="200" height="44" rx="8" fill="#FAECE7" stroke="#993C1D" stroke-width="0.5"/>
  <text font-family="sans-serif" font-size="14" font-weight="500" fill="#712B13" x="390" y="33" text-anchor="middle" dominant-baseline="central">Threat intel sources</text>
  <text font-family="sans-serif" font-size="12" fill="#993C1D" x="390" y="51" text-anchor="middle" dominant-baseline="central">VirusTotal, AbuseIPDB, GreyNoise...</text>

  <!-- Arrow threat intel -> cloud run -->
  <line x1="390" y1="62" x2="390" y2="158" stroke="#B4B2A9" stroke-width="0.5" stroke-dasharray="4 3" marker-end="url(#arrow)"/>

  <!-- Legend -->
  <line x1="40" y1="395" x2="70" y2="395" stroke="#5F5E5A" stroke-width="1.5" marker-end="url(#arrow)"/>
  <text font-family="sans-serif" font-size="12" fill="#5F5E5A" x="76" y="399" dominant-baseline="central">HTTP request</text>
  <line x1="200" y1="395" x2="230" y2="395" stroke="#B4B2A9" stroke-width="0.5" stroke-dasharray="4 3" marker-end="url(#arrow)"/>
  <text font-family="sans-serif" font-size="12" fill="#5F5E5A" x="236" y="399" dominant-baseline="central">Concurrent API calls</text>
</svg>

The enrichment engine queries all four threat intel sources concurrently using goroutines and a fan-out/fan-in channel pattern, minimising latency.

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

Threat levels: Low < 30, Medium 30-60, High >= 60