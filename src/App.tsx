import { useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowRight, Bell, Bug, CheckCircle2,
  ChevronDown, ChevronRight, CircleHelp, Clock3, FileSearch,
  GitMerge, LayoutDashboard, Link2, Menu, Network, ScanSearch,
  Search, Settings, Shield, ShieldAlert, ShieldCheck, Siren,
  Sparkles, X, type LucideIcon,
} from "lucide-react";
import "./App.css";

type Severity = "High" | "Medium" | "Low" | "Info";

type EventRecord = {
  id: string;
  title: string;
  source: string;
  severity: Severity;
  time: string;
  detail: string;
  indicator?: string;
};

type ModuleName =
  | "Phishing Detection"
  | "Honeypot"
  | "Emotion Tone Analyzer"
  | "Malicious Content Checker"
  | "Anomaly Detection";

type NavItem = { label: string; icon: LucideIcon };

const modules: {
  name: ModuleName;
  icon: LucideIcon;
  description: string;
  action: string;
}[] = [
  {
    name: "Phishing Detection",
    icon: ShieldAlert,
    description: "Inspect a URL for suspicious structure and phishing indicators.",
    action: "Analyze URL",
  },
  {
    name: "Honeypot",
    icon: Bug,
    description: "Review recorded interactions with decoy services and honeypot events.",
    action: "Record demo event",
  },
  {
    name: "Emotion Tone Analyzer",
    icon: Activity,
    description: "Analyze text for emotional tone such as urgency, fear, or anger.",
    action: "Analyze tone",
  },
  {
    name: "Malicious Content Checker",
    icon: ScanSearch,
    description: "Inspect text or content for suspicious links and threat patterns.",
    action: "Check content",
  },
  {
    name: "Anomaly Detection",
    icon: Network,
    description: "Review activity for unusual patterns against configured demo rules.",
    action: "Run demo check",
  },
];

const navigation: NavItem[] = [
  { label: "Dashboard", icon: LayoutDashboard },
  ...modules.map(({ name, icon }) => ({ label: name, icon })),
];

const initialEvents: EventRecord[] = [
  {
    id: "EVT-1005",
    title: "Unusual activity pattern detected",
    source: "Anomaly Detection",
    severity: "Medium",
    time: "2 min ago",
    detail: "A sample activity record deviated from the illustrative baseline.",
    indicator: "session-pattern-05",
  },
  {
    id: "EVT-1004",
    title: "Suspicious content pattern detected",
    source: "Malicious Content Checker",
    severity: "High",
    time: "8 min ago",
    detail: "Demo content matched a configured suspicious-language rule.",
    indicator: "campaign-demo-01",
  },
  {
    id: "EVT-1003",
    title: "Urgent language detected",
    source: "Emotion Tone Analyzer",
    severity: "Medium",
    time: "14 min ago",
    detail: "The sample text contains urgency-related wording; this is not proof of malicious intent.",
    indicator: "campaign-demo-01",
  },
  {
    id: "EVT-1002",
    title: "Decoy service interaction recorded",
    source: "Honeypot",
    severity: "High",
    time: "21 min ago",
    detail: "A simulated connection was recorded by a demo honeypot sensor.",
    indicator: "203.0.113.24",
  },
  {
    id: "EVT-1001",
    title: "Suspicious URL submitted",
    source: "Phishing Detection",
    severity: "High",
    time: "32 min ago",
    detail: "A demo URL scan flagged suspicious URL features for analyst review.",
    indicator: "https://secure-login.example.test",
  },
];

const initialCorrelations = [
  {
    id: "COR-001",
    title: "Possible coordinated social-engineering activity",
    confidence: "Review required",
    modules: ["Emotion Tone Analyzer", "Malicious Content Checker"],
    evidence:
      "The sample text triggered both urgency-tone and suspicious-content rules.",
    indicator: "campaign-demo-01",
  },
  {
    id: "COR-002",
    title: "Unusual event associated with suspicious URL activity",
    confidence: "Needs more evidence",
    modules: ["Phishing Detection", "Anomaly Detection"],
    evidence:
      "The demo records share a sample campaign marker. This is illustrative correlation, not a confirmed causal link.",
    indicator: "campaign-demo-02",
  },
];

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [events, setEvents] = useState<EventRecord[]>(initialEvents);
  const [urlInput, setUrlInput] = useState("");
  const [textInput, setTextInput] = useState("");
  const [result, setResult] = useState<{
    title: string;
    description: string;
    severity: Severity;
  } | null>(null);
  const [toast, setToast] = useState("");

  const visibleEvents = useMemo(
    () =>
      events.filter((event) => {
        const matchesQuery = `${event.id} ${event.title} ${event.source} ${
          event.indicator ?? ""
        }`
          .toLowerCase()
          .includes(query.toLowerCase());

        const matchesSeverity =
          severity === "All" || event.severity === severity;

        return matchesQuery && matchesSeverity;
      }),
    [events, query, severity],
  );

  const goTo = (page: string) => {
    setActivePage(page);
    setSidebarOpen(false);
    setResult(null);
    setToast("");
  };

  const addEvent = (event: Omit<EventRecord, "id" | "time">) => {
    const newEvent: EventRecord = {
      ...event,
      id: `EVT-${String(Date.now()).slice(-6)}`,
      time: "Just now",
    };

    setEvents((current) => [newEvent, ...current]);
    setToast("Demo activity added to Dashboard logs.");
    return newEvent;
  };

  const runModuleAction = () => {
    if (activePage === "Phishing Detection") {
      const raw = urlInput.trim();

      if (!raw) {
        setResult({
          title: "Enter a URL",
          description: "Provide a URL to run the local demonstration check.",
          severity: "Info",
        });
        return;
      }

      let parsed: URL | null = null;

      try {
        parsed = new URL(raw.includes("://") ? raw : `https://${raw}`);
      } catch {
        // Invalid URL.
      }

      if (!parsed) {
        setResult({
          title: "URL format not recognized",
          description:
            "Check the address format and try again. No network request was made.",
          severity: "Medium",
        });
        return;
      }

      const suspicious =
        /login|verify|secure|account|update|password|signin/i.test(
          `${parsed.hostname}${parsed.pathname}`,
        ) || parsed.hostname.includes("example.test");

      const verdict: Severity = suspicious ? "High" : "Info";
      const title = suspicious
        ? "Suspicious URL features detected"
        : "No demo rule matched";

      const description = suspicious
        ? `The URL contains words commonly used in credential lures (${parsed.hostname}). This is a heuristic demo result, not a verified phishing verdict.`
        : "No configured demo keyword rule matched this URL. This does not prove that the URL is safe.";

      addEvent({
        title,
        source: "Phishing Detection",
        severity: verdict,
        detail: description,
        indicator: parsed.href,
      });

      setResult({ title, description, severity: verdict });
      return;
    }

    if (activePage === "Emotion Tone Analyzer") {
      const text = textInput.trim();

      if (!text) {
        setResult({
          title: "Enter text to analyze",
          description: "Paste a message or sample text first.",
          severity: "Info",
        });
        return;
      }

      const urgent =
        /urgent|immediately|now|act fast|limited time|fear|account blocked|suspended/i.test(
          text,
        );

      const angry = /angry|hate|furious|terrible|disgusting/i.test(text);
      const tone = urgent
        ? "Urgency / pressure"
        : angry
          ? "Anger-related wording"
          : "Neutral or mixed wording";

      const desc = `Demo tone result: ${tone}. Tone classification alone cannot establish malicious intent.`;

      addEvent({
        title: `Text analyzed: ${tone}`,
        source: "Emotion Tone Analyzer",
        severity: urgent ? "Medium" : "Info",
        detail: desc,
        indicator: "text-analysis-demo",
      });

      setResult({
        title: tone,
        description: desc,
        severity: urgent ? "Medium" : "Info",
      });
      return;
    }

    if (activePage === "Malicious Content Checker") {
      const text = textInput.trim();

      if (!text) {
        setResult({
          title: "Enter content to check",
          description:
            "Paste text or content for the local demonstration check.",
          severity: "Info",
        });
        return;
      }

      const suspicious =
        /(password|verify your account|click here|wire transfer|download attachment|account suspended|https?:\/\/)/i.test(
          text,
        );

      const desc = suspicious
        ? "The sample content matched one or more configured demo patterns. Review the content and its context before deciding whether it is malicious."
        : "No configured demo pattern matched. This does not guarantee the content is safe.";

      addEvent({
        title: suspicious
          ? "Suspicious content pattern detected"
          : "Content checked",
        source: "Malicious Content Checker",
        severity: suspicious ? "High" : "Info",
        detail: desc,
        indicator: "content-check-demo",
      });

      setResult({
        title: suspicious
          ? "Suspicious patterns found"
          : "No demo rule matched",
        description: desc,
        severity: suspicious ? "High" : "Info",
      });
      return;
    }

    if (activePage === "Honeypot") {
      const desc =
        "A simulated honeypot interaction was added to the event log. No actual network listener or decoy service is running in this frontend.";

      addEvent({
        title: "Manual demo honeypot event recorded",
        source: "Honeypot",
        severity: "Medium",
        detail: desc,
        indicator: "manual-demo-interaction",
      });

      setResult({
        title: "Demo event recorded",
        description: desc,
        severity: "Medium",
      });
      return;
    }

    if (activePage === "Anomaly Detection") {
      const desc =
        "A demo rule check was recorded. Real anomaly detection requires telemetry, a baseline, and implemented detection logic.";

      addEvent({
        title: "Anomaly demo check completed",
        source: "Anomaly Detection",
        severity: "Info",
        detail: desc,
        indicator: "anomaly-demo-check",
      });

      setResult({
        title: "Demo check complete",
        description: desc,
        severity: "Info",
      });
    }
  };

  const currentModule = modules.find((module) => module.name === activePage);

  const metricCards = [
    {
      label: "Activity Events",
      value: events.length.toString().padStart(2, "0"),
      note: "Across all five modules",
      icon: Activity,
      tone: "cyan",
    },
    {
      label: "High-Risk Events",
      value: events
        .filter((event) => event.severity === "High")
        .length.toString()
        .padStart(2, "0"),
      note: "Flagged for review",
      icon: AlertTriangle,
      tone: "red",
    },
    {
      label: "Correlated Findings",
      value: "02",
      note: "Illustrative relationships",
      icon: GitMerge,
      tone: "purple",
    },
    {
      label: "Security Modules",
      value: "05",
      note: "Core modules represented",
      icon: ShieldCheck,
      tone: "green",
    },
  ];

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark">
            <Shield size={23} />
          </div>
          <div>
            <div className="brand-name">PHEMA</div>
            <div className="brand-caption">SECURITY INTELLIGENCE</div>
          </div>
          <button
            className="icon-button mobile-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
          >
            <X size={18} />
          </button>
        </div>

        <div className="workspace-label">WORKSPACE</div>

        <nav className="navigation" aria-label="Main navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activePage === label ? "nav-active" : ""}`}
              onClick={() => goTo(label)}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="workspace-label">SYSTEM</div>
          <button
            className={`nav-item ${activePage === "Settings" ? "nav-active" : ""}`}
            onClick={() => goTo("Settings")}
          >
            <Settings size={18} />
            <span>Settings</span>
          </button>

          <div className="system-status">
            <span className="status-dot" />
            <div>
              <strong>Demo environment</strong>
              <small>Local sample data</small>
            </div>
          </div>

          <div className="profile">
            <div className="avatar">PA</div>
            <div className="profile-info">
              <strong>Platform Analyst</strong>
              <small>Security analyst</small>
            </div>
            <ChevronDown size={16} className="muted-icon" />
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button
            className="icon-button menu-toggle"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open navigation"
          >
            <Menu size={20} />
          </button>

          <div className="breadcrumb">
            PHEMA <ChevronRight size={14} /> <span>{activePage}</span>
          </div>

          <div className="topbar-actions">
            <div className="environment-pill">
              <span className="status-dot" /> DEMO MODE
            </div>
            <button
              className="icon-button"
              aria-label="Help"
              onClick={() =>
                setToast(
                  "PHEMA frontend prototype: module results are demo-only.",
                )
              }
            >
              <CircleHelp size={19} />
            </button>
            <button
              className="icon-button notification-button"
              aria-label="Notifications"
              onClick={() => goTo("Dashboard")}
            >
              <Bell size={19} />
              <span />
            </button>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">PHEMA SECURITY PLATFORM</div>
              <h1>{activePage}</h1>
              <p>
                {activePage === "Dashboard"
                  ? "A unified view of activity, alerts, and cross-module findings."
                  : currentModule?.description ??
                    "Configure the PHEMA frontend demonstration."}
              </p>
            </div>

            <div className="heading-actions">
              {activePage === "Dashboard" && (
                <button
                  className="button-secondary"
                  onClick={() => {
                    setQuery("");
                    setSeverity("All");
                  }}
                >
                  <Clock3 size={16} /> Reset filters
                </button>
              )}

              {currentModule && (
                <button className="button-primary" onClick={runModuleAction}>
                  <Sparkles size={16} /> {currentModule.action}
                </button>
              )}
            </div>
          </div>

          <div className="demo-notice">
            <ShieldCheck size={18} />
            <div>
              <strong>Demonstration environment</strong>
              <span>
                Events and detection outcomes are local demo data. No external
                scans or network sensors are running.
              </span>
            </div>
            <span className="notice-tag">DEMO DATA</span>
          </div>

          {toast && (
            <div className="toast-message" role="status">
              <CheckCircle2 size={16} />
              {toast}
              <button
                onClick={() => setToast("")}
                aria-label="Dismiss message"
              >
                <X size={14} />
              </button>
            </div>
          )}

          {activePage === "Dashboard" && (
            <>
              <section className="metric-grid" aria-label="Security metrics">
                {metricCards.map(
                  ({ label, value, note, icon: Icon, tone }) => (
                    <article className="metric-card" key={label}>
                      <div className="metric-top">
                        <span>{label}</span>
                        <div className={`metric-icon ${tone}`}>
                          <Icon size={19} />
                        </div>
                      </div>
                      <div className="metric-value">{value}</div>
                      <div className="metric-caption">{note}</div>
                      <div className={`metric-accent ${tone}`} />
                    </article>
                  ),
                )}
              </section>

              <section className="content-grid">
                <article className="panel events-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Activity logs</h2>
                      <p>Recent events from all five security modules</p>
                    </div>
                    <span className="live-label">
                      <span /> LOCAL LOG
                    </span>
                  </div>

                  <div className="table-toolbar">
                    <label className="search-box">
                      <Search size={16} />
                      <input
                        value={query}
                        onChange={(event) => setQuery(event.target.value)}
                        placeholder="Search logs or indicators..."
                        aria-label="Search activity logs"
                      />
                      {query && (
                        <button
                          className="inline-clear"
                          onClick={() => setQuery("")}
                          aria-label="Clear search"
                        >
                          <X size={14} />
                        </button>
                      )}
                    </label>

                    <select
                      aria-label="Filter by severity"
                      value={severity}
                      onChange={(event) => setSeverity(event.target.value)}
                    >
                      <option>All</option>
                      <option>High</option>
                      <option>Medium</option>
                      <option>Low</option>
                      <option>Info</option>
                    </select>
                  </div>

                  <div className="events-table-wrap">
                    <table className="events-table">
                      <thead>
                        <tr>
                          <th>EVENT</th>
                          <th>MODULE</th>
                          <th>SEVERITY</th>
                          <th>TIME</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleEvents.map((event) => (
                          <tr key={event.id}>
                            <td>
                              <strong>{event.title}</strong>
                              <small>{event.id}</small>
                            </td>
                            <td>{event.source}</td>
                            <td>
                              <span
                                className={`severity severity-${event.severity.toLowerCase()}`}
                              >
                                <span />
                                {event.severity}
                              </span>
                            </td>
                            <td className="event-time">{event.time}</td>
                          </tr>
                        ))}

                        {visibleEvents.length === 0 && (
                          <tr>
                            <td colSpan={4} className="empty-state">
                              No events match your filters.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  <div className="panel-footer">
                    <span>
                      Showing {visibleEvents.length} of {events.length} local
                      events
                    </span>
                    <span>Demo records only</span>
                  </div>
                </article>

                <article className="panel module-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Module activity</h2>
                      <p>Event count by source</p>
                    </div>
                    <Activity size={18} className="muted-icon" />
                  </div>

                  <div className="module-activity-list">
                    {modules.map(({ name, icon: Icon }) => {
                      const count = events.filter(
                        (event) => event.source === name,
                      ).length;

                      return (
                        <button
                          key={name}
                          className="module-activity-row"
                          onClick={() => goTo(name)}
                        >
                          <span className="module-mini-icon">
                            <Icon size={16} />
                          </span>
                          <span className="module-activity-name">{name}</span>
                          <span className="module-count">{count}</span>
                          <ChevronRight size={15} />
                        </button>
                      );
                    })}
                  </div>

                  <p className="chart-disclaimer">
                    Counts update when demo actions add activity records.
                  </p>
                </article>
              </section>

              <section className="bottom-grid">
                <article className="panel correlation-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Cross-module correlation</h2>
                      <p>Potential relationships across module findings</p>
                    </div>
                    <div className="correlation-heading-icon">
                      <GitMerge size={18} />
                    </div>
                  </div>

                  {initialCorrelations.map((correlation) => (
                    <div className="correlation-item" key={correlation.id}>
                      <div className="correlation-item-top">
                        <div>
                          <span className="correlation-id">
                            {correlation.id}
                          </span>
                          <h3>{correlation.title}</h3>
                        </div>
                        <span className="review-pill">
                          {correlation.confidence}
                        </span>
                      </div>

                      <p>{correlation.evidence}</p>

                      <div className="correlation-tags">
                        {correlation.modules.map((module) => (
                          <span key={module}>{module}</span>
                        ))}
                      </div>

                      <div className="correlation-foot">
                        <span>
                          <Link2 size={13} /> {correlation.indicator}
                        </span>
                        <button
                          className="text-button"
                          onClick={() =>
                            setToast(
                              `Correlation ${correlation.id}: ${correlation.evidence}`,
                            )
                          }
                        >
                          View evidence <ArrowRight size={14} />
                        </button>
                      </div>
                    </div>
                  ))}

                  <p className="chart-disclaimer">
                    Correlation examples are illustrative. Real relationships
                    require implemented rules and supporting event evidence.
                  </p>
                </article>

                <article className="panel quick-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Open a module</h2>
                      <p>Run a local demo workflow</p>
                    </div>
                  </div>

                  <div className="quick-actions">
                    {modules.map(({ name, icon: Icon, description }) => (
                      <button key={name} onClick={() => goTo(name)}>
                        <div className="quick-icon cyan">
                          <Icon size={18} />
                        </div>
                        <span>
                          <strong>{name}</strong>
                          <small>{description}</small>
                        </span>
                        <ChevronRight size={16} />
                      </button>
                    ))}
                  </div>
                </article>
              </section>
            </>
          )}

          {currentModule && (
            <section className="module-workspace">
              <article className="panel module-intro-card">
                <div className="module-intro-icon">
                  <currentModule.icon size={24} />
                </div>
                <div>
                  <h2>{currentModule.name}</h2>
                  <p>{currentModule.description}</p>
                </div>
                <span className="demo-chip">FRONTEND DEMO</span>
              </article>

              {(activePage === "Phishing Detection" ||
                activePage === "Honeypot" ||
                activePage === "Anomaly Detection") && (
                <article className="panel tool-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>
                        {activePage === "Phishing Detection"
                          ? "URL inspection"
                          : activePage === "Honeypot"
                            ? "Honeypot event monitor"
                            : "Anomaly rule check"}
                      </h2>
                      <p>
                        {activePage === "Phishing Detection"
                          ? "Check URL structure using simple local demo heuristics."
                          : activePage === "Honeypot"
                            ? "Record a simulated interaction to see how event logs update."
                            : "Record a demonstration check; real analysis needs telemetry and a baseline."}
                      </p>
                    </div>
                    <ScanSearch size={20} className="accent-icon" />
                  </div>

                  {activePage === "Phishing Detection" && (
                    <label className="field-label">
                      URL to inspect
                      <input
                        value={urlInput}
                        onChange={(event) => setUrlInput(event.target.value)}
                        placeholder="https://example.com/login"
                        onKeyDown={(event) => {
                          if (event.key === "Enter") runModuleAction();
                        }}
                      />
                    </label>
                  )}

                  <div className="tool-actions">
                    <button
                      className="button-primary"
                      onClick={runModuleAction}
                    >
                      <Sparkles size={16} />
                      {currentModule.action}
                    </button>

                    {activePage === "Phishing Detection" && (
                      <button
                        className="button-secondary"
                        onClick={() =>
                          setUrlInput(
                            "https://secure-login.example.test/account/verify",
                          )
                        }
                      >
                        Use demo URL
                      </button>
                    )}
                  </div>

                  {result && <ResultCard result={result} />}
                </article>
              )}

              {(activePage === "Emotion Tone Analyzer" ||
                activePage === "Malicious Content Checker") && (
                <article className="panel tool-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>
                        {activePage === "Emotion Tone Analyzer"
                          ? "Text tone analysis"
                          : "Content inspection"}
                      </h2>
                      <p>
                        {activePage === "Emotion Tone Analyzer"
                          ? "Paste a message to see a basic keyword-based tone demo."
                          : "Paste sample text to check against local demonstration patterns."}
                      </p>
                    </div>
                    <FileSearch size={20} className="accent-icon" />
                  </div>

                  <label className="field-label">
                    {activePage === "Emotion Tone Analyzer"
                      ? "Text to analyze"
                      : "Content to inspect"}
                    <textarea
                      value={textInput}
                      onChange={(event) => setTextInput(event.target.value)}
                      rows={6}
                      placeholder={
                        activePage === "Emotion Tone Analyzer"
                          ? "Example: Act immediately or your account will be suspended..."
                          : "Paste a message, suspicious link, or other text..."
                      }
                    />
                  </label>

                  <div className="tool-actions">
                    <button
                      className="button-primary"
                      onClick={runModuleAction}
                    >
                      <Sparkles size={16} />
                      {currentModule.action}
                    </button>

                    <button
                      className="button-secondary"
                      onClick={() =>
                        setTextInput(
                          "Act immediately to verify your account or it may be suspended. Click here: https://example.test/login",
                        )
                      }
                    >
                      Use sample text
                    </button>
                  </div>

                  {result && <ResultCard result={result} />}
                </article>
              )}

              <article className="panel module-logs-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Recent module logs</h2>
                    <p>New demo actions appear here and on the Dashboard.</p>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => goTo("Dashboard")}
                  >
                    Dashboard logs <ChevronRight size={14} />
                  </button>
                </div>

                <div className="module-log-list">
                  {events
                    .filter((event) => event.source === activePage)
                    .slice(0, 5)
                    .map((event) => (
                      <div className="module-log-row" key={event.id}>
                        <div className="event-log-icon">
                          <Activity size={16} />
                        </div>
                        <div className="module-log-content">
                          <strong>{event.title}</strong>
                          <span>{event.detail}</span>
                          <small>
                            {event.id} · {event.time}
                          </small>
                        </div>
                        <span
                          className={`severity severity-${event.severity.toLowerCase()}`}
                        >
                          <span />
                          {event.severity}
                        </span>
                      </div>
                    ))}

                  {events.filter((event) => event.source === activePage)
                    .length === 0 && (
                    <p className="empty-module-log">
                      No records yet. Use the demo action to add a local
                      activity event.
                    </p>
                  )}
                </div>
              </article>
            </section>
          )}

          {activePage === "Settings" && (
            <section className="panel settings-panel">
              <div className="module-intro-icon">
                <Settings size={24} />
              </div>
              <h2>Prototype settings</h2>
              <p>
                This version stores activity in browser memory only. Refreshing
                the page resets demo records. A backend and database can be
                connected later for persistent logs.
              </p>
              <div className="settings-row">
                <span>Data mode</span>
                <strong>Local demo data</strong>
              </div>
              <div className="settings-row">
                <span>External network requests</span>
                <strong>Not used by demo checks</strong>
              </div>
              <div className="settings-row">
                <span>Core security modules</span>
                <strong>5</strong>
              </div>
              <button
                className="button-secondary"
                onClick={() => {
                  setEvents(initialEvents);
                  setToast("Demo events reset to their initial sample state.");
                }}
              >
                Reset demo activity
              </button>
            </section>
          )}

          <footer className="app-footer">
            <span>
              <Shield size={14} /> PHEMA Security Intelligence Platform
            </span>
            <span>Frontend prototype · Demo data only</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function ResultCard({
  result,
}: {
  result: { title: string; description: string; severity: Severity };
}) {
  return (
    <div className="result-card">
      <div className="result-card-icon">
        <Siren size={19} />
      </div>
      <div className="result-card-body">
        <div className="result-card-heading">
          <h3>{result.title}</h3>
          <span className={`severity severity-${result.severity.toLowerCase()}`}>
            <span />
            {result.severity}
          </span>
        </div>
        <p>{result.description}</p>
        <small>Local heuristic result · Not a verified security verdict</small>
      </div>
    </div>
  );
}

export default App;