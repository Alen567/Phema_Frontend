
import { useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  Clock3,
  Copy,
  Fingerprint,
  Globe,
  Hash,
  Info,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

type IndicatorType = "IP Address" | "Domain" | "URL" | "File Hash";
type Risk = "Malicious" | "Suspicious" | "Clean" | "Unknown";

type Indicator = {
  id: string;
  value: string;
  type: IndicatorType;
  risk: Risk;
  score: number | null;
  source: string;
  lastSeen: string;
  description: string;
  tags: string[];
};

const sampleIndicators: Indicator[] = [
  {
    id: "IOC-1001",
    value: "198.51.100.42",
    type: "IP Address",
    risk: "Malicious",
    score: 94,
    source: "Demo intelligence feed",
    lastSeen: "4 minutes ago",
    description: "Sample IP indicator associated with simulated suspicious activity.",
    tags: ["Command and control", "Network"],
  },
  {
    id: "IOC-1002",
    value: "login-secure.example.com",
    type: "Domain",
    risk: "Suspicious",
    score: 68,
    source: "Demo domain analysis",
    lastSeen: "18 minutes ago",
    description: "Sample domain flagged for analyst review in the demonstration dataset.",
    tags: ["Domain", "Needs review"],
  },
  {
    id: "IOC-1003",
    value: "203.0.113.17",
    type: "IP Address",
    risk: "Clean",
    score: 8,
    source: "Demo reputation lookup",
    lastSeen: "32 minutes ago",
    description: "Sample low-risk indicator. This is not a real reputation verdict.",
    tags: ["Network", "Low risk"],
  },
  {
    id: "IOC-1004",
    value: "a4f9c0d28e7b15f3",
    type: "File Hash",
    risk: "Unknown",
    score: null,
    source: "Demo hash lookup",
    lastSeen: "1 hour ago",
    description: "Sample hash record without a confirmed reputation result.",
    tags: ["File", "Unclassified"],
  },
  {
    id: "IOC-1005",
    value: "https://example.org/account-check",
    type: "URL",
    risk: "Malicious",
    score: 87,
    source: "Demo URL analysis",
    lastSeen: "2 hours ago",
    description: "Simulated suspicious URL submitted for demonstration purposes.",
    tags: ["Phishing simulation", "URL"],
  },
];

const riskClass: Record<Risk, string> = {
  Malicious: "ti-risk-malicious",
  Suspicious: "ti-risk-suspicious",
  Clean: "ti-risk-clean",
  Unknown: "ti-risk-unknown",
};

function detectType(value: string): IndicatorType {
  const input = value.trim();

  if (/^https?:\/\//i.test(input)) return "URL";
  if (/^[a-f0-9]{32,128}$/i.test(input)) return "File Hash";
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(input)) {
    return "IP Address";
  }
  return "Domain";
}

function isValidIndicator(value: string, type: IndicatorType): boolean {
  const input = value.trim();

  if (!input) return false;

  if (type === "URL") {
    try {
      const url = new URL(input);
      return ["http:", "https:"].includes(url.protocol);
    } catch {
      return false;
    }
  }

  if (type === "IP Address") {
    const parts = input.split(".");
    return (
      parts.length === 4 &&
      parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
    );
  }

  if (type === "File Hash") {
    return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(input);
  }

  return (
    input.length <= 253 &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$/i.test(input) &&
    input.includes(".")
  );
}

export default function ThreatIntelligence() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [selected, setSelected] = useState<Indicator | null>(null);
  const [lookup, setLookup] = useState<Indicator | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();

    return sampleIndicators.filter((item) => {
      const matchesSearch =
        !q ||
        `${item.value} ${item.type} ${item.risk} ${item.id} ${item.source}`
          .toLowerCase()
          .includes(q);

      return matchesSearch && (filter === "All" || item.risk === filter);
    });
  }, [search, filter]);

  function performLookup() {
    const value = search.trim();
    const type = detectType(value);

    if (!isValidIndicator(value, type)) {
      setError("Enter a valid IP address, domain, URL, or supported file hash.");
      setLookup(null);
      return;
    }

    setError("");
    const existing = sampleIndicators.find(
      (item) => item.value.toLowerCase() === value.toLowerCase(),
    );

    if (existing) {
      setLookup(existing);
    } else {
      setLookup({
        id: "LOCAL-DEMO",
        value,
        type,
        risk: "Unknown",
        score: null,
        source: "No matching sample record",
        lastSeen: "Just now",
        description:
          "This indicator is not present in the local demonstration dataset. No live reputation lookup was performed.",
        tags: ["No sample match"],
      });
    }
  }

  async function copyIndicator(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setError("Clipboard access is unavailable. Select and copy the indicator manually.");
    }
  }

  return (
    <div className="ti-page">
      <section className="ti-intro">
        <div>
          <div className="ti-eyebrow"><Fingerprint size={14} /> INDICATOR INVESTIGATION</div>
          <h2>Threat Intelligence</h2>
          <p>Look up indicators, review available context, and triage potential threats.</p>
        </div>
        <div className="ti-demo-label"><span /> LOCAL DEMO DATA</div>
      </section>

      <div className="ti-disclaimer">
        <Info size={17} />
        <p>
          <strong>Demonstration mode.</strong> All records and reputation scores on this page are simulated.
          No external threat intelligence services are queried.
        </p>
      </div>

      <section className="ti-search-panel">
        <div className="ti-section-title">
          <div>
            <h3>Indicator lookup</h3>
            <p>Search the local sample dataset or inspect an indicator format.</p>
          </div>
          <Search size={19} />
        </div>

        <form
          className="ti-search-form"
          onSubmit={(event) => {
            event.preventDefault();
            performLookup();
          }}
        >
          <div className="ti-search-input">
            <Search size={18} />
            <input
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setError("");
                setLookup(null);
              }}
              placeholder="Enter IP, domain, URL, or file hash..."
              aria-label="Indicator to look up"
            />
            {search && (
              <button type="button" className="ti-clear" onClick={() => {
                setSearch("");
                setLookup(null);
                setError("");
              }} aria-label="Clear indicator">
                <X size={16} />
              </button>
            )}
          </div>
          <button type="submit" className="ti-primary-button"><Search size={16} /> Analyse indicator</button>
        </form>

        {error && <p className="ti-error" role="alert">{error}</p>}

        <div className="ti-examples">
          <span>Try a sample:</span>
          {sampleIndicators.slice(0, 3).map((item) => (
            <button key={item.id} onClick={() => {
              setSearch(item.value);
              setError("");
              setLookup(null);
            }}>{item.value}</button>
          ))}
        </div>
      </section>

      {lookup && (
        <section className="ti-lookup-result" aria-live="polite">
          <div className="ti-result-heading">
            <div className="ti-result-symbol"><ShieldAlert size={20} /></div>
            <div className="ti-result-main">
              <span>LOCAL LOOKUP RESULT</span>
              <h3>{lookup.value}</h3>
              <p>{lookup.type} · {lookup.id}</p>
            </div>
            <span className={`ti-risk ${riskClass[lookup.risk]}`}>{lookup.risk}</span>
            <button className="ti-icon-button" onClick={() => copyIndicator(lookup.value)} aria-label="Copy indicator">
              {copied ? <CheckCircle2 size={17} /> : <Copy size={17} />}
            </button>
          </div>
          <div className="ti-result-stats">
            <div><span>Sample risk score</span><strong>{lookup.score === null ? "Unavailable" : `${lookup.score}/100`}</strong></div>
            <div><span>Source</span><strong>{lookup.source}</strong></div>
            <div><span>Last recorded</span><strong>{lookup.lastSeen}</strong></div>
          </div>
          <p className="ti-result-description">{lookup.description}</p>
        </section>
      )}

      <section className="ti-summary-grid">
        <article className="ti-summary-card"><div className="ti-summary-icon cyan"><Fingerprint size={19} /></div><span>Sample indicators</span><strong>05</strong><small>Local demonstration records</small></article>
        <article className="ti-summary-card"><div className="ti-summary-icon red"><ShieldAlert size={19} /></div><span>Malicious labels</span><strong>02</strong><small>Simulated classifications</small></article>
        <article className="ti-summary-card"><div className="ti-summary-icon amber"><Activity size={19} /></div><span>Needs review</span><strong>01</strong><small>Suspicious sample record</small></article>
        <article className="ti-summary-card"><div className="ti-summary-icon green"><ShieldCheck size={19} /></div><span>Clean labels</span><strong>01</strong><small>Not a real safety verdict</small></article>
      </section>

      <section className="ti-records-panel">
        <div className="ti-records-header">
          <div><h3>Indicator records</h3><p>Browse and inspect local demonstration entries.</p></div>
          <label className="ti-filter-label">
            <span>Risk</span>
            <select value={filter} onChange={(event) => setFilter(event.target.value)}>
              <option value="All">All risks</option>
              <option value="Malicious">Malicious</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Clean">Clean</option>
              <option value="Unknown">Unknown</option>
            </select>
          </label>
        </div>

        <div className="ti-table-wrap">
          <table className="ti-table">
            <thead><tr><th>INDICATOR</th><th>TYPE</th><th>RISK</th><th>SCORE</th><th>SOURCE</th><th></th></tr></thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.id}>
                  <td><div className="ti-indicator-cell"><span className="ti-type-icon">{item.type === "IP Address" ? <Globe size={15} /> : item.type === "File Hash" ? <Hash size={15} /> : <Fingerprint size={15} />}</span><div><strong>{item.value}</strong><small>{item.id}</small></div></div></td>
                  <td>{item.type}</td>
                  <td><span className={`ti-risk ${riskClass[item.risk]}`}>{item.risk}</span></td>
                  <td>{item.score === null ? "—" : `${item.score}/100`}</td>
                  <td>{item.source}</td>
                  <td><button className="ti-details-button" onClick={() => setSelected(item)}>Details <ArrowUpRight size={14} /></button></td>
                </tr>
              ))}
              {filtered.length === 0 && <tr><td colSpan={6} className="ti-empty">No sample indicators match your filters.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="ti-table-footer"><span>{filtered.length} of {sampleIndicators.length} sample records</span><span><Clock3 size={13} /> Local static dataset</span></div>
      </section>

      {selected && (
        <div className="ti-modal-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) setSelected(null);
        }}>
          <section className="ti-modal" role="dialog" aria-modal="true" aria-labelledby="ti-modal-title">
            <div className="ti-modal-header">
              <div><span>INDICATOR DETAILS</span><h3 id="ti-modal-title">{selected.type}</h3></div>
              <button className="ti-icon-button" onClick={() => setSelected(null)} aria-label="Close details"><X size={18} /></button>
            </div>
            <div className="ti-modal-value">{selected.value}</div>
            <div className="ti-modal-row"><span>Record ID</span><strong>{selected.id}</strong></div>
            <div className="ti-modal-row"><span>Risk label</span><strong><span className={`ti-risk ${riskClass[selected.risk]}`}>{selected.risk}</span></strong></div>
            <div className="ti-modal-row"><span>Risk score</span><strong>{selected.score === null ? "Unavailable" : `${selected.score}/100`}</strong></div>
            <div className="ti-modal-row"><span>Source</span><strong>{selected.source}</strong></div>
            <p className="ti-modal-description">{selected.description}</p>
            <div className="ti-tags">{selected.tags.map((tag) => <span key={tag}>{tag}</span>)}</div>
            <div className="ti-modal-warning"><Info size={16} /> Sample data only. This result is not a live security verdict.</div>
            <button className="ti-primary-button ti-modal-close" onClick={() => setSelected(null)}>Close details</button>
          </section>
        </div>
      )}
    </div>
  );
}
