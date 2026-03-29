import { useState } from "react"

interface ScoreDetail {
  Points: number
  Comment: string
}

interface ScoreBreakdown {
  Score: number
  Details: Record<string, ScoreDetail>
}

interface APIResponse {
  lookup_id: string
  score: {
    Total: number
    AbuseIPDB: ScoreBreakdown
    VirusTotal: ScoreBreakdown
    GreyNoise: ScoreBreakdown
  }
  results: any[]
}

function getThreat(score: number) {
  if (score < 30) return { label: "LOW RISK", color: "#00ff88", glow: "rgba(0,255,136,0.12)" }
  if (score < 60) return { label: "MEDIUM RISK", color: "#ffaa00", glow: "rgba(255,170,0,0.12)" }
  return { label: "HIGH RISK", color: "#ff3355", glow: "rgba(255,51,85,0.12)" }
}

function getSource(results: any[], name: string) {
  return results.find(r => r.Source === name)?.Result || null
}

function isValidIP(ip: string): boolean {
  const pattern = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!pattern.test(ip)) return false
  return ip.split(".").every(n => {
    const num = parseInt(n, 10)
    return num >= 0 && num <= 255
  })
}

function Row({ label, value, flag }: { label: string; value: any; flag?: string }) {
  return (
    <div style={{ display:"flex", justifyContent:"space-between", fontSize:"11px", padding:"4px 0", borderBottom:"1px solid rgba(255,255,255,0.03)" }}>
      <span style={{ color:"#3a5570", letterSpacing:"1px", flexShrink:0, marginRight:"12px" }}>{label}</span>
      <span style={{
        color: flag === "bad" ? "#ff3355" : flag === "good" ? "#00ff88" : flag === "warn" ? "#ffaa00" : "#b8cfe0",
        textAlign:"right", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"
      }}>{value ?? "—"}</span>
    </div>
  )
}

export default function App() {
  const [ip, setIp] = useState("")
  const [searchedIp, setSearchedIp] = useState("")
  const [results, setResults] = useState<APIResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [llmLoading, setLlmLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [llmEnabled, setLlmEnabled] = useState(false)
  const [llmOutput, setLlmOutput] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!ip.trim()) return

    // IP validation
    if (!isValidIP(ip.trim())) {
      setError("Invalid IP address. Please enter a valid IPv4 address (e.g. 1.1.1.1)")
      return
    }

    const target = ip.trim()
    setSearchedIp(target)
    setLoading(true)
    setError(null)
    setResults(null)
    setLlmOutput(null)

    try {
      // Phase 1 — enrichment only without LLM Analysis
      const res = await fetch(`${process.env.REACT_APP_API_URL}/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc: target, ioc_type: "ip" }),
      })
      if (!res.ok) throw new Error()
      const data = await res.json()
      setResults(data)
      setLoading(false)

      // Phase 2 — enrichment with LLM analysis when option is selected
      if (llmEnabled) {
        setLlmLoading(true)
        const llmRes = await fetch(`${process.env.REACT_APP_API_URL}/enrich?llm=true`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ioc: target, ioc_type: "ip" }),
        })
        if (llmRes.ok) {
          const llmData = await llmRes.json()
          if (llmData.llm_analysis) setLlmOutput(llmData.llm_analysis)
        }
        setLlmLoading(false)
      }

    } catch {
      setError("Failed to reach server. Is lightti serve running?")
      setLoading(false)
      setLlmLoading(false)
    }
  }

  const threat = results ? getThreat(results.score.Total) : null

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        body{background:#060a0e;color:#b8cfe0;font-family:'Share Tech Mono',monospace;min-height:100vh}
        body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);pointer-events:none;z-index:9999}
        .gbg{position:fixed;inset:0;background-image:linear-gradient(rgba(0,200,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,200,255,.025) 1px,transparent 1px);background-size:48px 48px;pointer-events:none}
        .app{position:relative;z-index:1;max-width:1000px;margin:0 auto;padding:48px 24px 80px}
        @keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}
        @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
      `}</style>

      <div className="gbg" />
      <div className="app">

        {/* Header */}
        <div style={{ textAlign:"center", marginBottom:"48px" }}>
          <div style={{ display:"inline-flex", alignItems:"center", gap:"16px", marginBottom:"10px" }}>
            <div style={{ width:"34px", height:"34px", border:"2px solid #00c8ff", transform:"rotate(45deg)", position:"relative", flexShrink:0 }}>
              <div style={{ position:"absolute", inset:"5px", background:"rgba(0,200,255,0.2)" }} />
            </div>
            <span style={{ fontFamily:"Orbitron,monospace", fontSize:"30px", fontWeight:900, color:"#00c8ff", letterSpacing:"8px" }}>LIGHTTI</span>
          </div>
          <p style={{ fontSize:"10px", color:"#3a5570", letterSpacing:"5px" }}>THREAT INTELLIGENCE AGGREGATION PLATFORM</p>
        </div>

        {/* Search */}
        <div style={{ maxWidth:"680px", margin:"0 auto 14px" }}>
          <div style={{ display:"flex", border:`1px solid ${error ? "rgba(255,51,85,0.5)" : "#162030"}`, background:"#0b1118", transition:"border-color .2s" }}>
            <span style={{ fontSize:"12px", color:"#00c8ff", padding:"0 16px", display:"flex", alignItems:"center", borderRight:"1px solid #162030", letterSpacing:"1px", userSelect:"none" }}>IP</span>
            <input
              value={ip}
              onChange={e => { setIp(e.target.value); setError(null) }}
              onKeyDown={e => e.key === "Enter" && handleSearch()}
              placeholder="Enter IP address..."
              style={{ flex:1, background:"transparent", border:"none", outline:"none", padding:"16px 20px", fontFamily:"'Share Tech Mono',monospace", fontSize:"15px", color:"#b8cfe0", letterSpacing:"2px" }}
            />
            <button
              onClick={handleSearch}
              disabled={loading}
              style={{ background:"#00c8ff", color:"#060a0e", border:"none", padding:"0 36px", fontFamily:"Orbitron,monospace", fontSize:"11px", fontWeight:700, letterSpacing:"3px", cursor:loading?"not-allowed":"pointer", opacity:loading?.4:1, transition:"opacity .15s", whiteSpace:"nowrap" }}
            >
              {loading ? "SCANNING" : "ENRICH"}
            </button>
          </div>

          {/* Inline error */}
          {error && (
            <div style={{ padding:"10px 16px", background:"rgba(255,51,85,0.05)", border:"1px solid rgba(255,51,85,0.2)", borderTop:"none", fontSize:"11px", color:"#ff3355", letterSpacing:"1px" }}>
              ⚠ {error}
            </div>
          )}
        </div>

        {/* LLM toggle */}
        <div style={{ display:"flex", justifyContent:"center", alignItems:"center", gap:"12px", marginBottom:"40px", fontSize:"10px", color:"#3a5570", letterSpacing:"2px" }}>
          <span>LLM ANALYSIS</span>
          <div
            onClick={() => setLlmEnabled(v => !v)}
            style={{ width:"36px", height:"18px", background: llmEnabled ? "rgba(0,200,255,0.15)" : "#162030", border:`1px solid ${llmEnabled ? "#00c8ff" : "#3a5570"}`, position:"relative", cursor:"pointer", transition:"all .2s" }}
          >
            <div style={{ position:"absolute", top:"2px", left: llmEnabled ? "20px" : "2px", width:"12px", height:"12px", background: llmEnabled ? "#00c8ff" : "#3a5570", transition:"left .2s, background .2s" }} />
          </div>
          <span style={{ color: llmEnabled ? "#00c8ff" : "#3a5570" }}>{llmEnabled ? "ENABLED" : "DISABLED"}</span>
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ textAlign:"center", padding:"72px", fontSize:"11px", color:"#3a5570", letterSpacing:"3px" }}>
            QUERYING THREAT INTEL SOURCES
            {[0,1,2].map(i => <span key={i} style={{ animation:`pulse 1.4s ease ${i*.2}s infinite` }}> .</span>)}
          </div>
        )}

        {/* Results */}
        {results && threat && (() => {
          const vt = getSource(results.results, "VirusTotal")
          const abuse = getSource(results.results, "AbuseIPDB")
          const gn = getSource(results.results, "GreyNoise")
          const loc = getSource(results.results, "IpToLocation")

          return (
            <div style={{ animation:"rise .4s ease both" }}>

              {/* Score hero */}
              <div style={{ maxWidth:"680px", margin:"0 auto 32px", border:"1px solid #162030", background:"#0b1118", padding:"36px 40px", position:"relative", textAlign:"center" }}>
                <div style={{ position:"absolute", top:0, left:0, right:0, height:"2px", background:threat.color }} />
                <div style={{ fontFamily:"Orbitron,monospace", fontSize:"16px", color:"#00c8ff", letterSpacing:"4px", marginBottom:"6px" }}>{searchedIp}</div>
                <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"4px", marginBottom:"28px" }}>IOC ENRICHMENT COMPLETE</div>
                <div style={{ display:"flex", alignItems:"baseline", justifyContent:"center", gap:"6px", marginBottom:"20px" }}>
                  <span style={{ fontFamily:"Orbitron,monospace", fontSize:"80px", fontWeight:900, lineHeight:1, color:threat.color }}>{results.score.Total}</span>
                  <span style={{ fontFamily:"Orbitron,monospace", fontSize:"22px", color:"#3a5570" }}>/100</span>
                </div>
                <div style={{ height:"3px", background:"#162030", maxWidth:"400px", margin:"0 auto 20px" }}>
                  <div style={{ height:"100%", width:`${results.score.Total}%`, background:threat.color, transition:"width .8s cubic-bezier(.4,0,.2,1)" }} />
                </div>
                <div style={{ display:"inline-block", fontFamily:"Orbitron,monospace", fontSize:"10px", fontWeight:700, letterSpacing:"4px", padding:"7px 20px", border:`1px solid ${threat.color}`, color:threat.color, background:threat.glow }}>
                  {threat.label}
                </div>
              </div>

              {/* 2x2 Cards */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"16px", maxWidth:"880px", margin:"0 auto 24px" }}>

                {/* VirusTotal */}
                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>VIRUSTOTAL</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{results.score.VirusTotal.Score}/40</span>
                  </div>
                  {vt && <>
                    <Row label="NETWORK" value={vt.data?.attributes?.network} />
                    <Row label="COUNTRY" value={vt.data?.attributes?.country} />
                    <Row label="AS OWNER" value={vt.data?.attributes?.as_owner} />
                    <Row label="MALICIOUS" value={vt.data?.attributes?.last_analysis_stats?.malicious} flag={(vt.data?.attributes?.last_analysis_stats?.malicious||0)>0?"bad":"good"} />
                    <Row label="SUSPICIOUS" value={vt.data?.attributes?.last_analysis_stats?.suspicious} flag={(vt.data?.attributes?.last_analysis_stats?.suspicious||0)>0?"warn":undefined} />
                    <Row label="HARMLESS" value={vt.data?.attributes?.last_analysis_stats?.harmless} />
                    <Row label="REPUTATION" value={vt.data?.attributes?.reputation} flag={(vt.data?.attributes?.reputation||0)<0?"bad":undefined} />
                  </>}
                  <div style={{ marginTop:"12px", paddingTop:"12px", borderTop:"1px solid #162030" }}>
                    <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"2px", marginBottom:"8px" }}>SCORE FACTORS</div>
                    {Object.entries(results.score.VirusTotal.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>+{d.Points}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* AbuseIPDB */}
                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>ABUSEIPDB</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{results.score.AbuseIPDB.Score}/40</span>
                  </div>
                  {abuse && <>
                    <Row label="ISP" value={abuse.data?.isp} />
                    <Row label="DOMAIN" value={abuse.data?.domain} />
                    <Row label="USAGE TYPE" value={abuse.data?.usageType} />
                    <Row label="ABUSE SCORE" value={`${abuse.data?.abuseConfidenceScore}%`} flag={(abuse.data?.abuseConfidenceScore||0)>50?"bad":(abuse.data?.abuseConfidenceScore||0)>20?"warn":"good"} />
                    <Row label="REPORTS" value={abuse.data?.totalReports} flag={(abuse.data?.totalReports||0)>0?"warn":undefined} />
                    <Row label="WHITELISTED" value={abuse.data?.isWhitelisted?"YES":"NO"} flag={abuse.data?.isWhitelisted?"good":undefined} />
                    <Row label="TOR EXIT" value={abuse.data?.isTor?"YES":"NO"} flag={abuse.data?.isTor?"bad":undefined} />
                  </>}
                  <div style={{ marginTop:"12px", paddingTop:"12px", borderTop:"1px solid #162030" }}>
                    <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"2px", marginBottom:"8px" }}>SCORE FACTORS</div>
                    {Object.entries(results.score.AbuseIPDB.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>+{d.Points}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* GreyNoise */}
                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>GREYNOISE</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{results.score.GreyNoise.Score}/20</span>
                  </div>
                  {gn && <>
                    <Row label="NOISE" value={gn.noise?"TRUE":"FALSE"} flag={gn.noise?"warn":undefined} />
                    <Row label="RIOT" value={gn.riot?"TRUE":"FALSE"} flag={gn.riot?"good":undefined} />
                    <Row label="CLASSIFICATION" value={(gn.classification||"NOT OBSERVED").toUpperCase()} flag={gn.classification==="malicious"?"bad":gn.classification==="benign"?"good":undefined} />
                    <Row label="KNOWN AS" value={gn.name||"NOT OBSERVED"} />
                    <Row label="LAST SEEN" value={gn.last_seen||"NOT OBSERVED"} />
                  </>}
                  <div style={{ marginTop:"12px", paddingTop:"12px", borderTop:"1px solid #162030" }}>
                    <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"2px", marginBottom:"8px" }}>SCORE FACTORS</div>
                    {Object.entries(results.score.GreyNoise.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>+{d.Points}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* IP2Location */}
                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>IP2LOCATION</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>GEO</span>
                  </div>
                  {loc && <>
                    <Row label="COUNTRY" value={loc.country_name} />
                    <Row label="REGION" value={loc.region_name} />
                    <Row label="CITY" value={loc.city_name} />
                    <Row label="ZIP" value={loc.zip_code} />
                    <Row label="ASN" value={loc.asn} />
                    <Row label="AS" value={loc.as} />
                    <Row label="TIMEZONE" value={loc.time_zone} />
                    <Row label="PROXY" value={loc.is_proxy?"YES":"NO"} flag={loc.is_proxy?"bad":undefined} />
                  </>}
                </div>

              </div>

              {/* LLM section */}
              {llmEnabled && (
                <div style={{ maxWidth:"880px", margin:"0 auto 24px", border:"1px solid rgba(0,200,255,0.2)", background:"rgba(0,200,255,0.03)", padding:"24px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:"16px" }}>
                    <div style={{ fontSize:"9px", color:"#00c8ff", letterSpacing:"3px" }}>⬡ LLM ANALYSIS — SIGMA DETECTION RULE</div>
                    {llmLoading && (
                      <div style={{ fontSize:"10px", color:"#3a5570", letterSpacing:"2px" }}>
                        GENERATING
                        {[0,1,2].map(i => <span key={i} style={{ animation:`pulse 1.4s ease ${i*.2}s infinite` }}> .</span>)}
                      </div>
                    )}
                  </div>
                  {llmOutput
                    ? <pre style={{ fontSize:"12px", color:"#b8cfe0", lineHeight:1.8, whiteSpace:"pre-wrap", letterSpacing:"0.5px" }}>{llmOutput}</pre>
                    : llmLoading
                      ? <div style={{ height:"2px", background:"#162030", overflow:"hidden" }}>
                          <div style={{ height:"100%", width:"40%", background:"rgba(0,200,255,0.3)", animation:"slide 1.5s ease infinite" }} />
                        </div>
                      : null
                  }
                </div>
              )}

              {/* Footer */}
              <div style={{ maxWidth:"880px", margin:"0 auto", paddingTop:"20px", borderTop:"1px solid #162030", display:"flex", justifyContent:"space-between", fontSize:"9px", color:"#3a5570", letterSpacing:"2px" }}>
                <span>LOOKUP_ID: {results.lookup_id}</span>
                <span>SOURCES: 4 · CONCURRENT · GO</span>
              </div>

            </div>
          )
        })()}
      </div>
    </>
  )
}