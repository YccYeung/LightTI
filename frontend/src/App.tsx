import { useState } from "react"

interface ScoreDetail {
  Points: number
  Comment: string
}

interface ScoreBreakdown {
  Score: number
  Details: Record<string, ScoreDetail>
}

interface EnrichAPIResponse {
  lookup_id: string
  score: {
    Total: number
    AbuseIPDB: ScoreBreakdown
    VirusTotal: ScoreBreakdown
    GreyNoise: ScoreBreakdown
  }
  results: any[]
}

interface AnalyzeAPIResponse {
  lookup_id: string
  results: string
}

type Mode = "ip" | "command"

function getThreat(score: number) {
  if (score < 40) return { label: "LOW RISK", color: "#00ff88", glow: "rgba(0,255,136,0.12)" }
  if (score < 80) return { label: "MEDIUM RISK", color: "#ffaa00", glow: "rgba(255,170,0,0.12)" }
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

const MODE_CONFIG = {
  ip: {
    accent: "#00c8ff",
    gridColor: "rgba(0,200,255,.025)",
    placeholder: "Enter IP address...",
    buttonLabel: "ENRICH",
    buttonScanning: "SCANNING",
  },
  command: {
    accent: "#ff6b35",
    gridColor: "rgba(255,107,53,.02)",
    placeholder: "Paste suspicious command...",
    buttonLabel: "ANALYZE",
    buttonScanning: "ANALYZING",
  }
}

export default function App() {
  const [mode, setMode] = useState<Mode>("ip")
  const [input, setInput] = useState("")
  const [searchedInput, setSearchedInput] = useState("")
  const [enrichResults, setEnrichResults] = useState<EnrichAPIResponse | null>(null)
  const [analyzeResults, setAnalyzeResults] = useState<AnalyzeAPIResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [llmLoading, setLlmLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [llmEnabled, setLlmEnabled] = useState(false)
  const [llmOutput, setLlmOutput] = useState<string | null>(null)
  const [dropdownOpen, setDropdownOpen] = useState(false)

  const cfg = MODE_CONFIG[mode]

  const handleModeSwitch = (newMode: Mode) => {
    setMode(newMode)
    setInput("")
    setError(null)
    setEnrichResults(null)
    setAnalyzeResults(null)
    setLlmOutput(null)
    setSearchedInput("")
  }

  const handleSearch = async () => {
    if (!input.trim()) return

    if (mode === "ip" && !isValidIP(input.trim())) {
      setError("Invalid IP address. Please enter a valid IPv4 address (e.g. 1.1.1.1)")
      return
    }

    const target = input.trim()
    setSearchedInput(target)
    setLoading(true)
    setError(null)
    setEnrichResults(null)
    setAnalyzeResults(null)
    setLlmOutput(null)

    const apiBase = process.env.REACT_APP_API_URL

    try {
      if (mode === "ip") {
        const res = await fetch(`${apiBase}/enrich`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ioc: target, ioc_type: "ip" }),
        })
        if (!res.ok) throw new Error()
        const data = await res.json()
        setEnrichResults(data)
        setLoading(false)

        if (llmEnabled) {
          setLlmLoading(true)
          const llmRes = await fetch(`${apiBase}/enrich?llm=true`, {
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
      } else {
        const res = await fetch(`${apiBase}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ioc: target, ioc_type: "command" }),
        })
        if (!res.ok) throw new Error()
        const data = await res.json()
        setAnalyzeResults(data)
        setLoading(false)
      }
    } catch {
      setError("Failed to reach server. Is lightti serve running?")
      setLoading(false)
      setLlmLoading(false)
    }
  }

  const threat = enrichResults ? getThreat(enrichResults.score.Total) : null

  const extractSection = (raw: string, num: string, key: string) => {
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const regex = new RegExp(`${num}\\.\\s+${escaped}:\\s+([\\s\\S]+?)(?=\\n\\d\\.|$)`)
    const match = raw.match(regex)
    return match ? match[1].trim() : null
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        body{background:#060a0e;color:#b8cfe0;font-family:'Share Tech Mono',monospace;min-height:100vh}
        body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.04) 2px,rgba(0,0,0,0.04) 4px);pointer-events:none;z-index:9999}
        .gbg{position:fixed;inset:0;pointer-events:none}
        .app{position:relative;z-index:1;max-width:1000px;margin:0 auto;padding:48px 24px 80px}
        @keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}
      `}</style>

      <div className="gbg" style={{
        backgroundImage:`linear-gradient(${cfg.gridColor} 1px,transparent 1px),linear-gradient(90deg,${cfg.gridColor} 1px,transparent 1px)`,
        backgroundSize:"48px 48px",
        transition:"background-image 0.5s"
      }} />

      <div className="app">

        {/* Header — always static */}
        <div style={{ textAlign:"center", marginBottom:"48px" }}>
          <div style={{ display:"inline-flex", alignItems:"center", gap:"16px", marginBottom:"10px" }}>
            <div style={{ width:"34px", height:"34px", border:`2px solid ${cfg.accent}`, transform:"rotate(45deg)", position:"relative", flexShrink:0, transition:"border-color 0.4s" }}>
              <div style={{ position:"absolute", inset:"5px", background:`${cfg.accent}22`, transition:"background 0.4s" }} />
            </div>
            <span style={{ fontFamily:"Orbitron,monospace", fontSize:"30px", fontWeight:900, color:cfg.accent, letterSpacing:"8px", transition:"color 0.4s" }}>LIGHTTI</span>
          </div>
          <p style={{ fontSize:"10px", color:"#3a5570", letterSpacing:"5px" }}>THREAT INTELLIGENCE AGGREGATION PLATFORM</p>
        </div>

        {/* Search bar with dropdown */}
        <div style={{ maxWidth:"680px", margin:"0 auto 14px" }}>
          <div style={{ display:"flex", border:`1px solid ${error ? "rgba(255,51,85,0.5)" : "#162030"}`, background:"#0b1118", transition:"border-color .2s" }}>
            <div style={{ position:"relative", borderRight:"1px solid #162030", flexShrink:0 }}>
              <div
                onClick={() => setDropdownOpen(v => !v)}
                style={{ display:"flex", alignItems:"center", gap:"8px", padding:"0 16px", height:"52px", cursor:"pointer", color:cfg.accent, fontSize:"11px", letterSpacing:"2px", fontFamily:"'Share Tech Mono',monospace", userSelect:"none", transition:"color 0.4s", minWidth:"90px" }}
              >
                <span>{mode === "ip" ? "IP" : "CMD"}</span>
                <span style={{ fontSize:"14px", display:"inline-block", transform: dropdownOpen ? "rotate(180deg)" : "rotate(0deg)", transition:"transform .2s" }}>▾</span>
              </div>
              {dropdownOpen && (
                <div style={{ position:"absolute", top:"100%", left:"-1px", zIndex:100, background:"#0b1118", border:"1px solid #162030", borderTop:"none", minWidth:"130px" }}>
                  {(["ip", "command"] as Mode[]).map(m => (
                    <div
                      key={m}
                      onClick={() => { handleModeSwitch(m); setDropdownOpen(false) }}
                      style={{
                        padding:"10px 16px",
                        fontSize:"10px",
                        letterSpacing:"2px",
                        fontFamily:"'Share Tech Mono',monospace",
                        cursor:"pointer",
                        color: mode === m ? MODE_CONFIG[m].accent : "#3a5570",
                        background: mode === m ? `${MODE_CONFIG[m].accent}0d` : "transparent",
                        borderLeft: mode === m ? `2px solid ${MODE_CONFIG[m].accent}` : "2px solid transparent",
                        transition:"all .15s",
                      }}
                    >
                      {m === "ip" ? "IP ENRICH" : "CMD ANALYZE"}
                    </div>
                  ))}
                </div>
              )}
            </div>
            <input
              value={input}
              onChange={e => { setInput(e.target.value); setError(null) }}
              onKeyDown={e => e.key === "Enter" && handleSearch()}
              placeholder={cfg.placeholder}
              style={{ flex:1, background:"transparent", border:"none", outline:"none", padding:"16px 20px", fontFamily:"'Share Tech Mono',monospace", fontSize:"15px", color:"#b8cfe0", letterSpacing:"2px" }}
            />
            <button
              onClick={handleSearch}
              disabled={loading}
              style={{ background:cfg.accent, color:"#060a0e", border:"none", padding:"0 36px", fontFamily:"Orbitron,monospace", fontSize:"11px", fontWeight:700, letterSpacing:"3px", cursor:loading?"not-allowed":"pointer", opacity:loading?0.4:1, transition:"background 0.4s, opacity .15s", whiteSpace:"nowrap" }}
            >
              {loading ? cfg.buttonScanning : cfg.buttonLabel}
            </button>
          </div>
          {error && (
            <div style={{ padding:"10px 16px", background:"rgba(255,51,85,0.05)", border:"1px solid rgba(255,51,85,0.2)", borderTop:"none", fontSize:"11px", color:"#ff3355", letterSpacing:"1px" }}>
              ⚠ {error}
            </div>
          )}
        </div>

        {/* LLM toggle — IP only */}
        {mode === "ip" && (
          <div style={{ display:"flex", justifyContent:"center", alignItems:"center", gap:"12px", marginBottom:"40px", fontSize:"10px", color:"#3a5570", letterSpacing:"2px" }}>
            <span>LLM ANALYSIS</span>
            <div onClick={() => setLlmEnabled(v => !v)} style={{ width:"36px", height:"18px", background: llmEnabled ? "rgba(0,200,255,0.15)" : "#162030", border:`1px solid ${llmEnabled ? "#00c8ff" : "#3a5570"}`, position:"relative", cursor:"pointer", transition:"all .2s" }}>
              <div style={{ position:"absolute", top:"2px", left: llmEnabled ? "20px" : "2px", width:"12px", height:"12px", background: llmEnabled ? "#00c8ff" : "#3a5570", transition:"left .2s, background .2s" }} />
            </div>
            <span style={{ color: llmEnabled ? "#00c8ff" : "#3a5570" }}>{llmEnabled ? "ENABLED" : "DISABLED"}</span>
          </div>
        )}
        {mode === "command" && <div style={{ marginBottom:"40px" }} />}

        {/* Loading */}
        {loading && (
          <div style={{ textAlign:"center", padding:"72px", fontSize:"11px", color:"#3a5570", letterSpacing:"3px" }}>
            {mode === "ip" ? "QUERYING THREAT INTEL SOURCES" : "ANALYSING COMMAND"}
            {[0,1,2].map(i => <span key={i} style={{ animation:`pulse 1.4s ease ${i*.2}s infinite` }}> .</span>)}
          </div>
        )}

        {/* ===== IP ENRICH RESULTS ===== */}
        {mode === "ip" && enrichResults && threat && (() => {
          const vt = getSource(enrichResults.results, "VirusTotal")
          const abuse = getSource(enrichResults.results, "AbuseIPDB")
          const gn = getSource(enrichResults.results, "GreyNoise")
          const loc = getSource(enrichResults.results, "IpToLocation")
          return (
            <div style={{ animation:"rise .4s ease both" }}>
              <div style={{ maxWidth:"680px", margin:"0 auto 32px", border:"1px solid #162030", background:"#0b1118", padding:"36px 40px", position:"relative", textAlign:"center" }}>
                <div style={{ position:"absolute", top:0, left:0, right:0, height:"2px", background:threat.color }} />
                <div style={{ fontFamily:"Orbitron,monospace", fontSize:"16px", color:"#00c8ff", letterSpacing:"4px", marginBottom:"6px" }}>{searchedInput}</div>
                <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"4px", marginBottom:"28px" }}>IOC ENRICHMENT COMPLETE</div>
                <div style={{ display:"flex", alignItems:"baseline", justifyContent:"center", gap:"6px", marginBottom:"20px" }}>
                  <span style={{ fontFamily:"Orbitron,monospace", fontSize:"80px", fontWeight:900, lineHeight:1, color:threat.color }}>{enrichResults.score.Total}</span>
                  <span style={{ fontFamily:"Orbitron,monospace", fontSize:"22px", color:"#3a5570" }}>/100</span>
                </div>
                <div style={{ height:"3px", background:"#162030", maxWidth:"400px", margin:"0 auto 20px" }}>
                  <div style={{ height:"100%", width:`${enrichResults.score.Total}%`, background:threat.color, transition:"width .8s cubic-bezier(.4,0,.2,1)" }} />
                </div>
                <div style={{ display:"inline-block", fontFamily:"Orbitron,monospace", fontSize:"10px", fontWeight:700, letterSpacing:"4px", padding:"7px 20px", border:`1px solid ${threat.color}`, color:threat.color, background:threat.glow }}>
                  {threat.label}
                </div>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"16px", maxWidth:"880px", margin:"0 auto 24px" }}>
                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>VIRUSTOTAL</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{enrichResults.score.VirusTotal.Score}/40</span>
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
                    {Object.entries(enrichResults.score.VirusTotal.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>{d.Points >= 0 ? `+${d.Points}` : `${d.Points}`}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>ABUSEIPDB</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{enrichResults.score.AbuseIPDB.Score}/40</span>
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
                    {Object.entries(enrichResults.score.AbuseIPDB.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>{d.Points >= 0 ? `+${d.Points}` : `${d.Points}`}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ border:"1px solid #162030", background:"#0b1118", padding:"24px" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px", paddingBottom:"12px", borderBottom:"1px solid #162030" }}>
                    <span style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"3px" }}>GREYNOISE</span>
                    <span style={{ fontSize:"11px", color:"#00c8ff", background:"rgba(0,200,255,0.08)", padding:"3px 10px" }}>{enrichResults.score.GreyNoise.Score}/20</span>
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
                    {Object.entries(enrichResults.score.GreyNoise.Details||{}).map(([k,d]) => (
                      <div key={k} style={{ display:"flex", gap:"8px", fontSize:"10px", padding:"2px 0", color:"#3a5570" }}>
                        <span style={{ color:"#00c8ff", whiteSpace:"nowrap" }}>{d.Points >= 0 ? `+${d.Points}` : `${d.Points}`}pts</span>
                        <span>{d.Comment}</span>
                      </div>
                    ))}
                  </div>
                </div>

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

              {llmEnabled && (
                <div style={{ maxWidth:"880px", margin:"0 auto 24px", border:"1px solid rgba(0,200,255,0.2)", background:"rgba(0,200,255,0.03)", padding:"24px" }}>
                  <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:"16px" }}>
                    <div style={{ fontSize:"9px", color:"#00c8ff", letterSpacing:"3px" }}>⬡ LLM ANALYSIS — SIGMA DETECTION RULE</div>
                    {llmLoading && (
                      <div style={{ fontSize:"10px", color:"#3a5570", letterSpacing:"2px" }}>
                        GENERATING{[0,1,2].map(i => <span key={i} style={{ animation:`pulse 1.4s ease ${i*.2}s infinite` }}> .</span>)}
                      </div>
                    )}
                  </div>
                  {llmOutput
                    ? <pre style={{ fontSize:"12px", color:"#b8cfe0", lineHeight:1.8, whiteSpace:"pre-wrap", letterSpacing:"0.5px" }}>{llmOutput}</pre>
                    : llmLoading ? <div style={{ height:"2px", background:"#162030" }} /> : null
                  }
                </div>
              )}

              <div style={{ maxWidth:"880px", margin:"0 auto", paddingTop:"20px", borderTop:"1px solid #162030", display:"flex", justifyContent:"space-between", fontSize:"9px", color:"#3a5570", letterSpacing:"2px" }}>
                <span>LOOKUP_ID: {enrichResults.lookup_id}</span>
                <span>SOURCES: 4 · CONCURRENT · GO</span>
              </div>
            </div>
          )
        })()}

        {/* ===== COMMAND ANALYZE RESULTS ===== */}
        {mode === "command" && analyzeResults && (
          <div style={{ animation:"rise .4s ease both", maxWidth:"880px", margin:"0 auto" }}>
            <div style={{ border:"1px solid #2a1508", background:"#0d0906", padding:"28px 32px", marginBottom:"20px", position:"relative" }}>
              <div style={{ position:"absolute", top:0, left:0, right:0, height:"2px", background:"#ff6b35" }} />
              <div style={{ fontSize:"9px", color:"#3a5570", letterSpacing:"4px", marginBottom:"8px" }}>COMMAND ANALYZED</div>
              <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"14px", color:"#ff6b35", letterSpacing:"1px", wordBreak:"break-all" }}>{searchedInput}</div>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"16px", marginBottom:"16px" }}>
              {[
                { num:"1", key:"Risk Level", icon:"⚠" },
                { num:"2", key:"Source", icon:"◈" },
              ].map(({ num, key, icon }) => {
                const content = extractSection(analyzeResults.results, num, key)
                const isHigh = content?.toLowerCase().includes("high") || content?.toLowerCase().includes("critical")
                const isMed = content?.toLowerCase().includes("medium")
                return (
                  <div key={num} style={{ border:"1px solid #2a1508", background:"#0d0906", padding:"20px" }}>
                    <div style={{ fontSize:"9px", color:"#ff6b35", letterSpacing:"3px", marginBottom:"12px", paddingBottom:"10px", borderBottom:"1px solid #1a0c04" }}>{icon} {key.toUpperCase()}</div>
                    <div style={{ fontSize:"12px", color: isHigh ? "#ff3355" : isMed ? "#ffaa00" : "#b8cfe0", lineHeight:1.6 }}>
                      {content || "—"}
                    </div>
                  </div>
                )
              })}
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"1fr", gap:"16px", marginBottom:"20px" }}>
              {[
                { num:"3", key:"Intent", icon:"◉" },
                { num:"4", key:"Recommended Actions", icon:"▶" },
              ].map(({ num, key, icon }) => {
                const content = extractSection(analyzeResults.results, num, key)
                return (
                  <div key={num} style={{ border:"1px solid #2a1508", background:"#0d0906", padding:"20px" }}>
                    <div style={{ fontSize:"9px", color:"#ff6b35", letterSpacing:"3px", marginBottom:"12px", paddingBottom:"10px", borderBottom:"1px solid #1a0c04" }}>{icon} {key.toUpperCase()}</div>
                    <div style={{ fontSize:"12px", color:"#b8cfe0", lineHeight:1.8, whiteSpace:"pre-wrap" }}>
                      {content || "—"}
                    </div>
                  </div>
                )
              })}
            </div>

            <div style={{ paddingTop:"20px", borderTop:"1px solid #2a1508", display:"flex", justifyContent:"space-between", fontSize:"9px", color:"#3a5570", letterSpacing:"2px" }}>
              <span>LOOKUP_ID: {analyzeResults.lookup_id}</span>
              <span>ENGINE: LOLBAS · GTFOBINS · LLM</span>
            </div>
          </div>
        )}
      </div>
    </>
  )
}