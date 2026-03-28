import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = "http://10.10.30.102:8000";

function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

function formatTimestamp(ts) {
  if (!ts) return "Unknown";
  return new Date(ts).toLocaleString();
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function severityRank(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}

function getSeverityClass(severity) {
  return `severity-${(severity || "unknown").toLowerCase()}`;
}

function getThreatScoreClass(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return "score-unknown";
  if (n >= 80) return "score-high";
  if (n >= 40) return "score-medium";
  return "score-low";
}

function countryFlag(country) {
  const map = { Austria: "🇦🇹", Australia: "🇦🇺", France: "🇫🇷", Russia: "🇷🇺", Unknown: "🌐" };
  return map[country] || "🌐";
}

function StatCard({ label, value, subtext, tone = "default" }) {
  return (
    <div className={cx("stat-card", `tone-${tone}`)}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {subtext ? <div className="stat-subtext">{subtext}</div> : null}
    </div>
  );
}

function Badge({ children, className = "" }) {
  return <span className={cx("badge", className)}>{children}</span>;
}

function MiniBar({ label, value, max, className = "", prefix = "" }) {
  const pct = max > 0 ? Math.max(4, Math.round((value / max) * 100)) : 0;
  return (
    <div className="mini-bar-row">
      <div className="mini-bar-top">
        <span>{prefix}{label}</span>
        <strong>{value}</strong>
      </div>
      <div className="mini-bar-track">
        <div className={cx("mini-bar-fill", className)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function TimelineBars({ data }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <div className="timeline-chart">
      {data.map((item) => {
        const h = Math.max(10, Math.round((item.count / max) * 100));
        return (
          <div key={item.label} className="timeline-col">
            <div className="timeline-bar-wrap"><div className="timeline-bar" style={{ height: `${h}%` }} /></div>
            <div className="timeline-count">{item.count}</div>
            <div className="timeline-label">{item.label}</div>
          </div>
        );
      })}
    </div>
  );
}

function AttackMapPanel({ topCountries, maxCountry }) {
  return (
    <div className="map-panel">
      <div className="map-glow" />
      <div className="map-grid" />
      <div className="map-title">Global Attack Origin Snapshot</div>
      <div className="map-subtitle">Top countries by visible event volume</div>
      <div className="country-overlay">
        {topCountries.length === 0 ? (
          <div className="empty-state compact">No location data yet.</div>
        ) : topCountries.map(([country, count]) => (
          <div key={country} className="country-pill"><span>{countryFlag(country)}</span><span>{country}</span><strong>{count}</strong></div>
        ))}
      </div>
      <div className="map-bars">
        {topCountries.map(([country, count]) => (
          <MiniBar key={country} label={country} value={count} max={maxCountry} className="bar-blue" prefix={`${countryFlag(country)} `} />
        ))}
      </div>
    </div>
  );
}

function AttackItem({ attack }) {
  const severity = (attack.severity || "unknown").toLowerCase();
  const displayIp = (attack.source_ip || "Unknown IP").replace("/32", "");
  const asnOrg = [attack.asn, attack.org].filter(Boolean).join(" | ") || "Unknown";

  return (
    <article className={cx("event-card", `severity-${severity}`)}>
      <div className="event-header">
        <div className="event-ip-block">
          <div className="event-ip">{displayIp}</div>
          <div className="event-time">{formatTimestamp(attack.timestamp)}</div>
        </div>
        <div className="event-badges">
          <Badge className="protocol-badge">{attack.protocol || "unknown"}</Badge>
          <Badge className="attacktype-badge">{attack.attack_type || "unknown"}</Badge>
          <Badge className={cx("severity-badge", getSeverityClass(severity))}>{severity}</Badge>
        </div>
      </div>
      <div className="event-grid">
        <div className="event-metric"><span>Port</span><strong>{attack.dest_port ?? "—"}</strong></div>
        <div className="event-metric"><span>Country</span><strong>{attack.country || "Unknown"}</strong></div>
        <div className="event-metric"><span>ASN / Org</span><strong>{asnOrg}</strong></div>
        <div className="event-metric"><span>Threat Score</span><strong className={cx("threat-score", getThreatScoreClass(attack.threat_score))}>{attack.threat_score ?? "—"}</strong></div>
        <div className="event-metric"><span>Confidence</span><strong>{attack.confidence || "N/A"}</strong></div>
        <div className="event-metric"><span>Status</span><strong>{attack.processed ? "Enriched" : "Pending"}</strong></div>
      </div>
      <div className="event-summary">{attack.summary || "No analyst summary available."}</div>
    </article>
  );
}

export default function App() {
  const [attacks, setAttacks] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;
    async function loadData() {
      try {
        const [attacksRes, summaryRes] = await Promise.all([
          fetch(`${API_BASE}/api/attacks`),
          fetch(`${API_BASE}/api/summary`),
        ]);
        if (!attacksRes.ok || !summaryRes.ok) throw new Error("Failed to load dashboard data");
        const [attacksJson, summaryJson] = await Promise.all([attacksRes.json(), summaryRes.json()]);
        if (!mounted) return;
        setAttacks(Array.isArray(attacksJson) ? attacksJson : []);
        setSummary(summaryJson || {});
        setLastUpdated(new Date());
        setError("");
      } catch (err) {
        if (!mounted) return;
        setError(err.message || "Unknown error");
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const derived = useMemo(() => {
    const totalVisible = attacks.length;
    const pendingVisible = attacks.filter((a) => !a.processed).length;
    const sshCount = attacks.filter((a) => (a.protocol || "").toLowerCase() === "ssh").length;
    const topAttackMap = attacks.reduce((acc, curr) => { const key = curr.attack_type || "unknown"; acc[key] = (acc[key] || 0) + 1; return acc; }, {});
    const topCountryMap = attacks.reduce((acc, curr) => { const key = curr.country || "Unknown"; acc[key] = (acc[key] || 0) + 1; return acc; }, {});
    const topIpMap = attacks.reduce((acc, curr) => { const key = (curr.source_ip || "Unknown").replace("/32", ""); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
    const usernameMap = attacks.reduce((acc, curr) => { const text = curr.summary || ""; const maybeRoot = text.toLowerCase().includes("root") ? "root" : null; if (maybeRoot) acc[maybeRoot] = (acc[maybeRoot] || 0) + 1; return acc; }, {});
    const topAttack = Object.entries(topAttackMap).sort((a, b) => b[1] - a[1])[0];
    const highestSeverity = [...attacks].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0]?.severity || "unknown";
    const topCountries = Object.entries(topCountryMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topIps = Object.entries(topIpMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const topUsernames = Object.entries(usernameMap).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const maxCountry = topCountries[0]?.[1] || 0;
    const maxIp = topIps[0]?.[1] || 0;
    const maxUser = topUsernames[0]?.[1] || 0;
    const criticalHighCount = attacks.filter((a) => { const s = (a.severity || "").toLowerCase(); return s === "critical" || s === "high"; }).length;
    const now = Date.now();
    const lagSeconds = attacks.length ? Math.max(0, Math.round((now - new Date(attacks[0].timestamp).getTime()) / 1000)) : 0;
    const timelineBuckets = Array.from({ length: 8 }, (_, idx) => {
      const minsAgoEnd = (7 - idx) * 5;
      const minsAgoStart = minsAgoEnd + 5;
      const count = attacks.filter((a) => {
        const diffMin = (now - new Date(a.timestamp).getTime()) / 60000;
        return diffMin >= minsAgoEnd && diffMin < minsAgoStart;
      }).length;
      return { label: `${(7 - idx) * 5}m`, count };
    });
    return { totalVisible, pendingVisible, sshCount, topAttack: topAttack ? topAttack[0] : "unknown", highestSeverity, topCountries, topIps, topUsernames, maxCountry, maxIp, maxUser, criticalHighCount, lagSeconds, timelineBuckets };
  }, [attacks]);

  return (
    <div className="shell">
      <div className="bg-grid" />
      <div className="bg-glow bg-glow-one" />
      <div className="bg-glow bg-glow-two" />
      <header className="hero">
        <div className="hero-left">
          <div className="brandline">NULLANDV01D SYSTEMS</div>
          <h1>NVD² Sentinel</h1>
          <p className="hero-subtitle">Live attack telemetry, enrichment, and AI-assisted threat triage.</p>
          <div className="hero-pills">
            <Badge className="hero-pill">Collector: 10.10.30.102</Badge>
            <Badge className="hero-pill">Sensor Fleet: Active</Badge>
            <Badge className="hero-pill live-pill">Threat Intel Enabled</Badge>
          </div>
        </div>
        <div className="hero-right">
          <div className="status-panel">
            <div className="status-top"><span className="live-dot" /><span>Operational</span></div>
            <div className="status-meta">{lastUpdated ? `Last sync ${lastUpdated.toLocaleTimeString()}` : "Waiting for first sync"}</div>
          </div>
        </div>
      </header>
      {error ? <div className="error-banner">Dashboard error: {error}</div> : null}
      <section className="stats-row six-up">
        <StatCard label="Total Attacks" value={summary ? safeNumber(summary.total_attacks) : derived.totalVisible} subtext="All captured events" tone="blue" />
        <StatCard label="Unique IPs" value={summary ? safeNumber(summary.unique_ips) : 0} subtext="Distinct sources observed" tone="purple" />
        <StatCard label="Processed" value={summary ? safeNumber(summary.processed_attacks) : 0} subtext="LLM-enriched events" tone="green" />
        <StatCard label="Critical / High" value={summary ? `${safeNumber(summary.critical_count)} / ${safeNumber(summary.high_count)}` : "0 / 0"} subtext="Priority queue volume" tone="red" />
        <StatCard label="Max Threat Score" value={summary ? safeNumber(summary.max_threat_score) : 0} subtext="Highest visible severity" tone="red" />
        <StatCard label="Processing Lag" value={`${derived.lagSeconds}s`} subtext="Newest visible event age" tone="purple" />
      </section>
      <section className="upper-grid">
        <div className="panel"><div className="panel-header"><div><div className="panel-kicker">ACTIVITY</div><h2>Attack Timeline</h2></div></div><TimelineBars data={derived.timelineBuckets} /></div>
        <div className="panel"><div className="panel-header"><div><div className="panel-kicker">GEO VIEW</div><h2>Attack Map</h2></div></div><AttackMapPanel topCountries={derived.topCountries} maxCountry={derived.maxCountry} /></div>
      </section>
      <section className="main-grid">
        <div className="panel panel-large">
          <div className="panel-header"><div><div className="panel-kicker">EVENT STREAM</div><h2>Recent Enriched Events</h2></div><div className="panel-header-meta">{loading ? "Loading…" : `${attacks.length} visible`}</div></div>
          <div className="event-feed">
            {loading ? <div className="empty-state">Loading live telemetry…</div> : attacks.length === 0 ? <div className="empty-state">No enriched attack data yet.</div> : attacks.map((attack) => <AttackItem key={attack.id} attack={attack} />)}
          </div>
        </div>
        <aside className="sidebar">
          <div className="panel"><div className="panel-header"><div><div className="panel-kicker">ANALYSIS</div><h2>Severity Snapshot</h2></div></div><div className="stack-list"><div className="stack-item"><span>Critical</span><strong>{summary ? safeNumber(summary.critical_count) : 0}</strong></div><div className="stack-item"><span>High</span><strong>{summary ? safeNumber(summary.high_count) : 0}</strong></div><div className="stack-item"><span>Medium</span><strong>{summary ? safeNumber(summary.medium_count) : 0}</strong></div><div className="stack-item"><span>Low</span><strong>{summary ? safeNumber(summary.low_count) : 0}</strong></div></div></div>
          <div className="panel"><div className="panel-header"><div><div className="panel-kicker">THREAT SIGNALS</div><h2>Operational Snapshot</h2></div></div><div className="signal-grid"><div className="signal-card"><span>Top Attack</span><strong>{derived.topAttack}</strong></div><div className="signal-card"><span>SSH Events</span><strong>{derived.sshCount}</strong></div><div className="signal-card"><span>Highest Severity</span><strong>{derived.highestSeverity}</strong></div><div className="signal-card"><span>Pending Visible</span><strong>{derived.pendingVisible}</strong></div></div></div>
          <div className="panel"><div className="panel-header"><div><div className="panel-kicker">TOP SOURCES</div><h2>Countries</h2></div></div><div className="mini-bar-list">{derived.topCountries.length === 0 ? <div className="empty-state compact">No data yet.</div> : derived.topCountries.map(([country, count]) => <MiniBar key={country} label={country} value={count} max={derived.maxCountry} className="bar-blue" prefix={`${countryFlag(country)} `} />)}</div></div>
          <div className="panel"><div className="panel-header"><div><div className="panel-kicker">TOP SOURCES</div><h2>Source IPs</h2></div></div><div className="mini-bar-list">{derived.topIps.length === 0 ? <div className="empty-state compact">No data yet.</div> : derived.topIps.map(([ip, count]) => <MiniBar key={ip} label={ip} value={count} max={derived.maxIp} className="bar-purple" />)}</div></div>
          <div className="panel"><div className="panel-header"><div><div className="panel-kicker">CREDENTIAL INTEL</div><h2>Observed Usernames</h2></div></div><div className="mini-bar-list">{derived.topUsernames.length === 0 ? <div className="empty-state compact">No username data yet.</div> : derived.topUsernames.map(([name, count]) => <MiniBar key={name} label={name} value={count} max={derived.maxUser} className="bar-red" />)}</div></div>
        </aside>
      </section>
    </div>
  );
}
