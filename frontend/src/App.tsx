import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Boxes,
  ChevronRight,
  CircleHelp,
  Cpu,
  FileSearch,
  FlaskConical,
  FolderKanban,
  GitCompareArrows,
  HardDrive,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Plus,
  Settings2,
  ShieldCheck,
  Sparkles,
  Upload,
} from "lucide-react";
import type { FormEvent } from "react";
import { api, setCSRF, upload } from "./api";
import type { Page, Project, Scan, Settings } from "./api";
import {
  Badge,
  date,
  Empty,
  ErrorBox,
  Json,
  Loading,
  Modal,
  size,
  useLoad,
} from "./ui";
import {
  Assistant,
  CompareView,
  Components,
  Files,
  Findings,
  Reports,
} from "./views";

const tabs = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "findings", label: "Findings", icon: FileSearch },
  { id: "components", label: "Components", icon: Boxes },
  { id: "files", label: "Files", icon: FolderKanban },
  { id: "compare", label: "Compare", icon: GitCompareArrows },
  { id: "assistant", label: "Assistant", icon: Sparkles },
  { id: "reports", label: "Reports", icon: ArrowDownToLine },
];
const completed = ["complete", "partial", "failed", "unsupported", "cancelled"];
export function href(
  project: string,
  scan = "",
  tab = "overview",
  finding = "",
) {
  return `#/${project}${scan ? `/${scan}/${tab}` : ""}${finding ? `?finding=${finding}` : ""}`;
}
function route() {
  const [path, query] = location.hash.slice(2).split("?");
  const [project = "", scan = "", tab = "overview"] = (path ?? "").split("/");
  return {
    project,
    scan,
    tab,
    finding: new URLSearchParams(query).get("finding") ?? "",
  };
}

function SignIn({ onLogin }: { onLogin: () => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api<{ csrf: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ token }),
      });
      setCSRF(result.csrf);
      setToken("");
      onLogin();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login">
      <div className="login-card">
        <div className="brand-mark">
          <Cpu size={27} />
        </div>
        <p className="eyebrow">LOCAL RESEARCH WORKBENCH</p>
        <h1>
          FirmwareLens<span>.</span>
        </h1>
        <p className="intro">
          Look inside the firmware.
          <br />
          Follow the evidence.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="token">Local access token</label>
          <input
            id="token"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            required
            autoComplete="current-password"
            placeholder="Enter your first-run credential"
          />
          <ErrorBox>{error}</ErrorBox>
          <button className="primary wide" disabled={busy}>
            {busy ? "Signing in…" : "Open workbench"}
            <ArrowRight size={16} />
          </button>
        </form>
        <details>
          <summary>Where to find your token</summary>
          <p>Run this on your local machine:</p>
          <code>docker compose exec api firmwarelens access-token</code>
          <p>
            Your browser receives an HttpOnly session. The access token is never
            stored in browser storage.
          </p>
        </details>
        <div className="local-note">
          <LockKeyhole size={14} /> Local by default · Cloud AI requires opt-in
        </div>
      </div>
      <div className="login-grid" aria-hidden="true" />
    </main>
  );
}

function UploadModal({
  project,
  onClose,
  onCreated,
}: {
  project: string;
  onClose: () => void;
  onCreated: (scan: Scan) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [components, setComponents] = useState(true);
  const [vulnerabilities, setVulnerabilities] = useState(true);
  const [maxFiles, setMaxFiles] = useState(20000);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const artifact = await upload(project, file, setProgress);
      const scan = await api<Scan>(`/projects/${project}/scans`, {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          artifact_id: artifact.id,
          label: label || Array.from(file.name).slice(0, 100).join(""),
          options: {
            components,
            vulnerabilities: components && vulnerabilities,
            limits: { max_files: maxFiles },
          },
        }),
      });
      onCreated(scan);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title="Analyze firmware"
      onClose={() => {
        if (!busy) onClose();
      }}
    >
      <form onSubmit={submit}>
        <p className="muted">
          Upload firmware you are authorized to inspect. Analysis is static and
          runs in an isolated Linux container.
        </p>
        <label className="drop-zone" htmlFor="firmware">
          <Upload size={30} />
          <strong>{file ? file.name : "Choose a firmware image"}</strong>
          <span>
            {file
              ? size(file.size)
              : "SquashFS, tar, gzip tar, embedded SquashFS or ZIP"}
          </span>
          <input
            id="firmware"
            type="file"
            required
            disabled={busy}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </label>
        <label htmlFor="release-label">Release label</label>
        <input
          id="release-label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          maxLength={100}
          placeholder="e.g. Gateway · release 2.1"
        />
        <details className="advanced">
          <summary>Analysis configuration</summary>
          <label className="check">
            <input
              type="checkbox"
              checked={components}
              onChange={(e) => setComponents(e.target.checked)}
            />
            Component inventory & CycloneDX SBOM
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={vulnerabilities}
              disabled={!components}
              onChange={(e) => setVulnerabilities(e.target.checked)}
            />
            Match against prepared local Grype database
          </label>
          <label htmlFor="max-files">Maximum filesystem entries</label>
          <input
            id="max-files"
            type="number"
            min={1}
            max={100000}
            value={maxFiles}
            onChange={(e) => setMaxFiles(Number(e.target.value))}
          />
          <p className="small muted">
            Missing intelligence is reported as incomplete coverage. Signature
            validation happens in the sandbox.
          </p>
        </details>
        <ErrorBox>{error}</ErrorBox>
        {busy && (
          <div role="status">
            <progress max={100} value={progress} />
            <p className="small">
              {progress < 100
                ? `Uploading ${progress}%`
                : "Validating upload and queuing analysis…"}
            </p>
          </div>
        )}
        <button className="primary wide" disabled={busy || !file}>
          <FlaskConical size={16} />
          {busy ? "Preparing scan…" : "Start analysis"}
        </button>
      </form>
    </Modal>
  );
}

function Overview({
  scan,
  base,
  refresh,
}: {
  scan: Scan;
  base: string;
  refresh: () => void;
}) {
  const [error, setError] = useState("");
  const events = useLoad<
    { id: number; stage: string; message: string; at: string }[]
  >(base + "/events", 0, completed.includes(scan.status) ? 0 : 1500);
  async function cancel() {
    try {
      await api(base + "/cancel", { method: "POST" });
      refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  const stats = [
    { label: "Findings", value: scan.summary.findings, icon: FileSearch },
    { label: "Components", value: scan.summary.components, icon: Boxes },
    { label: "Filesystem entries", value: scan.summary.files, icon: HardDrive },
    {
      label: "Completed analyzers",
      value: `${scan.stages.filter((s) => s.state === "success").length} / ${scan.stages.length || "—"}`,
      icon: Activity,
    },
  ];
  return (
    <>
      <div className="stats">
        {stats.map((s) => (
          <div className="stat" key={s.label}>
            <div>
              <span>{s.label}</span>
              <s.icon size={18} />
            </div>
            <strong>{s.value}</strong>
          </div>
        ))}
      </div>
      {!completed.includes(scan.status) && (
        <div className="notice">
          <Activity className="spin-slow" size={20} />
          <div>
            <strong>
              {scan.cancel_requested
                ? "Cancellation requested"
                : "Analysis in progress"}
            </strong>
            <p>Progress is persisted. You can leave this page and return.</p>
          </div>
          <button
            onClick={() => void cancel()}
            disabled={scan.cancel_requested}
          >
            Cancel analysis
          </button>
        </div>
      )}
      <ErrorBox>{error || scan.error}</ErrorBox>
      {scan.status === "partial" && (
        <div className="notice warning">
          <CircleHelp size={20} />
          <div>
            <strong>
              Partial coverage — review before drawing conclusions
            </strong>
            <p>
              Some stages did not complete. An unavailable vulnerability
              database is not a clean security assessment.
            </p>
          </div>
        </div>
      )}
      <div className="two-col">
        <section className="panel">
          <div className="panel-title">
            <h2>Analysis coverage</h2>
            <span className="small muted">Transparent by design</span>
          </div>
          {scan.stages.length ? (
            scan.stages.map((stage) => (
              <div className="stage" key={stage.id}>
                <div>
                  <strong>{stage.id}</strong>
                  <Badge value={stage.state} />
                </div>
                <p>{stage.message}</p>
                {stage.diagnostics?.length ? (
                  <details>
                    <summary>Stage diagnostics</summary>
                    <ul>
                      {stage.diagnostics.map((d, i) => (
                        <li key={i}>{d}</li>
                      ))}
                    </ul>
                  </details>
                ) : null}
              </div>
            ))
          ) : (
            <p className="muted">
              Stage results will appear as analysis completes.
            </p>
          )}
        </section>
        <section className="panel">
          <div className="panel-title">
            <h2>Finding severity</h2>
            <span className="small muted">Observed results</span>
          </div>
          {Object.entries(scan.summary.severity).map(([severity, count]) => (
            <div className="severity-row" key={severity}>
              <span>{severity}</span>
              <div className="bar">
                <span
                  className={`fill fill-${severity}`}
                  style={{
                    width: `${scan.summary.findings ? (count / scan.summary.findings) * 100 : 0}%`,
                  }}
                />
              </div>
              <strong>{count}</strong>
            </div>
          ))}
          <p className="small muted">
            Severity describes impact. Confidence describes evidence strength.
            Neither establishes exploitability.
          </p>
          <div className="artifact-info">
            <span className="eyebrow">INPUT ARTIFACT</span>
            <code>{scan.artifact_id}</code>
            <p>
              {scan.format ?? "Awaiting signature inspection"} · attempt{" "}
              {scan.attempts}
            </p>
          </div>
        </section>
      </div>
      <section className="panel">
        <h2>Activity timeline</h2>
        <ErrorBox>{events.error}</ErrorBox>
        <ol className="timeline">
          {events.data?.map((event) => (
            <li key={event.id}>
              <span className="timeline-dot" />
              <div>
                <strong>{event.message}</strong>
                <small>
                  {date(event.at)} · {event.stage}
                </small>
              </div>
            </li>
          ))}
        </ol>
      </section>
      <section className="panel">
        <details>
          <summary>Reproducibility manifest & tool versions</summary>
          <Json value={scan.manifest} />
        </details>
        <details>
          <summary>Payloads and offsets</summary>
          <Json value={scan.payloads} />
        </details>
        <details>
          <summary>Scope and limitations</summary>
          <ul>
            {scan.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </details>
      </section>
    </>
  );
}

function Diagnostics({
  data,
  project,
  onDelete,
}: {
  data: Settings | null;
  project: string;
  onDelete: () => void;
}) {
  const [error, setError] = useState("");
  async function remove() {
    if (
      !confirm(
        "Delete this project and its scan history? This cannot be undone.",
      )
    )
      return;
    try {
      await api(`/projects/${project}`, { method: "DELETE" });
      onDelete();
    } catch (err) {
      setError((err as Error).message);
    }
  }
  if (!data) return <Loading />;
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">LOCAL DEPLOYMENT</p>
          <h1>Settings & diagnostics</h1>
          <p>Runtime health, isolation, and provider configuration.</p>
        </div>
      </div>
      <div className="two-col">
        <section className="panel">
          <h2>System status</h2>
          <dl className="facts">
            <dt>Database</dt>
            <dd>{data.database}</dd>
            <dt>Supervisor</dt>
            <dd>
              <Badge value={data.supervisor.alive ? "complete" : "failed"} />
            </dd>
            <dt>Engine</dt>
            <dd>{data.supervisor.sandbox.engine ?? "Unavailable"}</dd>
            <dt>Upload limit</dt>
            <dd>{size(data.limits.upload_bytes)}</dd>
            <dt>Job timeout</dt>
            <dd>{data.limits.job_timeout_seconds}s</dd>
          </dl>
          {Object.entries(data.supervisor.sandbox.checks ?? {}).map(
            ([key, value]) => (
              <div className="check-row" key={key}>
                <span>{key.replaceAll("_", " ")}</span>
                <Badge value={value ? "success" : "failure"} />
              </div>
            ),
          )}
          <details>
            <summary>Tool and sandbox details</summary>
            <Json value={data.supervisor.sandbox} />
          </details>
        </section>
        <section className="panel">
          <h2>Research assistant</h2>
          <Badge value={data.ai.provider} />
          <p>{data.ai.disclosure}</p>
          <dl className="facts">
            <dt>Model</dt>
            <dd>{data.ai.model || "Not configured"}</dd>
            <dt>Cloud opt-in</dt>
            <dd>{data.ai.cloud_enabled ? "Enabled" : "Disabled"}</dd>
            <dt>Daily request limit</dt>
            <dd>{data.ai.daily_requests}</dd>
            <dt>Context limit</dt>
            <dd>{data.ai.context_chars.toLocaleString()} characters</dd>
          </dl>
          <p className="small muted">
            Edit your local .env, then recreate the API service. Provider keys
            stay on the server.
          </p>
          <pre className="code">
            {
              "# Local model already installed in Ollama\nFL_AI_PROVIDER=ollama\nFL_AI_MODEL=your-installed-model\n\n# Or explicitly enable cloud evidence processing\nFL_AI_PROVIDER=openai\nFL_AI_MODEL=your-available-model\nFL_CLOUD_AI_ENABLED=true\nFL_OPENAI_API_KEY=your-server-side-key"
            }
          </pre>
        </section>
      </div>
      <section className="panel">
        <h2>Retention controls</h2>
        <p>
          Delete a project after cancelling active jobs. Immutable artifacts are
          retained until the local garbage-collection command removes
          unreferenced data.
        </p>
        <code>docker compose exec api firmwarelens retention gc --days 30</code>
        <p className="small muted">
          The command previews candidates. Add --apply to remove them. Back up
          before deleting research data.
        </p>
        <ErrorBox>{error}</ErrorBox>
        <button
          className="danger"
          disabled={!project}
          onClick={() => void remove()}
        >
          Delete selected project
        </button>
      </section>
    </>
  );
}

export default function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [current, setCurrent] = useState(route);
  const [refresh, setRefresh] = useState(0);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  useEffect(() => {
    void api<{ csrf: string }>("/auth/session")
      .then((result) => {
        setCSRF(result.csrf);
        setAuthenticated(true);
      })
      .catch(() => setAuthenticated(false));
    const change = () => setCurrent(route());
    addEventListener("hashchange", change);
    return () => removeEventListener("hashchange", change);
  }, []);
  const projects = useLoad<Project[]>(
    authenticated ? "/projects" : null,
    refresh,
  );
  const project =
    current.project === "settings"
      ? (projects.data?.[0]?.id ?? "")
      : current.project || projects.data?.[0]?.id || "";
  const projectData = projects.data?.find((p) => p.id === project);
  const scans = useLoad<Page<Scan>>(
    authenticated && project ? `/projects/${project}/scans` : null,
    refresh,
    4000,
  );
  const base = `/projects/${project}/scans/${current.scan}`;
  const scan = useLoad<Scan>(
    authenticated && current.scan ? base : null,
    refresh,
    2500,
  );
  const settings = useLoad<Settings>(
    authenticated ? "/settings" : null,
    refresh,
    10000,
  );
  const bump = () => setRefresh((v) => v + 1);
  async function create(event: FormEvent) {
    event.preventDefault();
    setCreating(true);
    try {
      const p = await api<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({ name, description }),
      });
      setCreateOpen(false);
      setName("");
      setDescription("");
      location.hash = href(p.id);
      bump();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }
  async function logout() {
    try {
      await api("/auth/logout", { method: "POST" });
      setAuthenticated(false);
      setCSRF("");
    } catch (err) {
      setError((err as Error).message);
    }
  }
  if (authenticated === null) return <Loading />;
  if (!authenticated)
    return (
      <SignIn
        onLogin={() => {
          setAuthenticated(true);
          bump();
        }}
      />
    );
  const readyResult = Boolean(scan.data?.stages.length);
  return (
    <div className="app-shell">
      <a
        className="skip"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        Skip to content
      </a>
      <aside className="sidebar">
        <a className="brand" href="#/">
          <span className="brand-mark">
            <Cpu size={21} />
          </span>
          <div>
            FirmwareLens<span>RESEARCH WORKBENCH</span>
          </div>
        </a>
        <div className="workspace-label">
          WORKSPACE <span>LOCAL</span>
        </div>
        <label className="sr-only" htmlFor="project-picker">
          Selected project
        </label>
        <select
          id="project-picker"
          value={project}
          onChange={(e) => {
            location.hash = href(e.target.value);
          }}
        >
          <option value="" disabled>
            Select a project
          </option>
          {projects.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button className="new-project" onClick={() => setCreateOpen(true)}>
          <Plus size={14} />
          New project
        </button>
        <nav aria-label="Main navigation">
          <a
            className={current.project !== "settings" ? "active" : ""}
            href={href(project)}
          >
            <LayoutDashboard size={18} />
            Research overview
          </a>
          <button disabled={!project} onClick={() => setUploadOpen(true)}>
            <Upload size={18} />
            Analyze firmware
          </button>
          <a
            className={current.project === "settings" ? "active" : ""}
            href="#/settings"
          >
            <Settings2 size={18} />
            Settings & diagnostics
          </a>
        </nav>
        <div className="sidebar-bottom">
          <div className="isolation">
            <ShieldCheck size={21} />
            <div>
              <strong>
                {settings.data?.supervisor.sandbox.ready
                  ? "Sandbox ready"
                  : "Check sandbox status"}
              </strong>
              <span>Static analysis · Network isolated</span>
            </div>
          </div>
          <a href="/api/docs" target="_blank" rel="noreferrer">
            <CircleHelp size={16} />
            API documentation
            <ArrowRight size={14} />
          </a>
          <button onClick={() => void logout()}>
            <LogOut size={16} />
            Sign out
          </button>
          <small>FirmwareLens 0.1.0 · Local instance</small>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div>
            <span className="muted">Workspace</span>
            <ChevronRight size={14} />
            <strong>{projectData?.name ?? "Research"}</strong>
            {current.scan && (
              <>
                <ChevronRight size={14} />
                <span>{scan.data?.label ?? "Scan"}</span>
              </>
            )}
          </div>
          <span className="local-pill">
            <span className="dot" /> Local workspace
          </span>
        </header>
        <main id="main-content" tabIndex={-1}>
          <ErrorBox>
            {error ||
              projects.error ||
              scans.error ||
              scan.error ||
              settings.error}
          </ErrorBox>
          {current.project === "settings" ? (
            <Diagnostics
              data={settings.data}
              project={project}
              onDelete={() => {
                location.hash = "#/";
                bump();
              }}
            />
          ) : !current.scan ? (
            <>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">FIRMWARE SECURITY RESEARCH</p>
                  <h1>
                    Research overview<span className="accent">.</span>
                  </h1>
                  <p>From firmware bytes to findings you can verify.</p>
                </div>
                <button
                  className="primary"
                  disabled={!project}
                  onClick={() => setUploadOpen(true)}
                >
                  <Plus size={17} />
                  New analysis
                </button>
              </div>
              {!project ? (
                <section className="panel">
                  <Empty title="Start with a research project">
                    Organize firmware releases, evidence, and your investigation
                    in one place.
                  </Empty>
                  <button
                    className="primary center"
                    onClick={() => setCreateOpen(true)}
                  >
                    <Plus size={16} />
                    Create your first project
                  </button>
                </section>
              ) : (
                <>
                  <div className="project-banner">
                    <div className="project-icon">
                      <FolderKanban size={30} />
                    </div>
                    <div>
                      <p className="eyebrow">CURRENT PROJECT</p>
                      <h2>{projectData?.name}</h2>
                      <p>
                        {projectData?.description ||
                          "An evidence-first workspace for authorized firmware research."}
                      </p>
                    </div>
                    <div className="project-count">
                      <strong>{scans.data?.total ?? "—"}</strong>
                      <span>persisted scans</span>
                    </div>
                  </div>
                  <section className="panel scans-panel">
                    <div className="panel-title">
                      <div>
                        <h2>Firmware releases</h2>
                        <p className="small muted">
                          Upload → analyze → inspect evidence → investigate →
                          compare → report
                        </p>
                      </div>
                      <span className="small muted">Most recent 50</span>
                    </div>
                    {scans.loading && !scans.data ? (
                      <Loading />
                    ) : scans.data?.items.length ? (
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Release / artifact</th>
                              <th>Outcome</th>
                              <th>Findings</th>
                              <th>Components</th>
                              <th>Created</th>
                              <th>
                                <span className="sr-only">Open</span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {scans.data.items.map((s) => (
                              <tr key={s.id}>
                                <td>
                                  <a
                                    className="release-link"
                                    href={href(project, s.id)}
                                  >
                                    <span className="file-icon">
                                      <Cpu size={19} />
                                    </span>
                                    <span>
                                      <strong>
                                        {s.label || "Unnamed release"}
                                      </strong>
                                      <code>{s.artifact_id.slice(0, 18)}…</code>
                                    </span>
                                  </a>
                                </td>
                                <td>
                                  <Badge value={s.status} />
                                </td>
                                <td>
                                  <strong>
                                    {completed.includes(s.status)
                                      ? s.summary.findings
                                      : "—"}
                                  </strong>
                                  {s.summary.severity.high > 0 && (
                                    <span className="small high-label">
                                      {s.summary.severity.high} high
                                    </span>
                                  )}
                                </td>
                                <td>
                                  {completed.includes(s.status)
                                    ? s.summary.components
                                    : "—"}
                                </td>
                                <td className="muted small">
                                  {date(s.created_at)}
                                </td>
                                <td>
                                  <a
                                    className="icon-button"
                                    href={href(project, s.id)}
                                    aria-label={`Open ${s.label}`}
                                  >
                                    <ArrowRight size={17} />
                                  </a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty title="Your first firmware release belongs here">
                        Analyze a supported image to start building a traceable
                        security assessment.
                      </Empty>
                    )}
                  </section>
                  <div className="principles">
                    <div>
                      <FileSearch size={20} />
                      <h3>Evidence behind every finding</h3>
                      <p>
                        Inspect paths, hashes, parser observations, and original
                        filesystem metadata.
                      </p>
                    </div>
                    <div>
                      <GitCompareArrows size={20} />
                      <h3>Compare with context</h3>
                      <p>
                        Track changes in firmware, tools, and intelligence
                        without confusing missing coverage with a fix.
                      </p>
                    </div>
                    <div>
                      <LockKeyhole size={20} />
                      <h3>Your artifacts stay local</h3>
                      <p>
                        Offline static analysis. Cloud assistance is optional
                        and requires explicit configuration.
                      </p>
                    </div>
                  </div>
                </>
              )}
            </>
          ) : (
            <>
              {!scan.data ? (
                <Loading />
              ) : (
                <>
                  <div className="page-heading">
                    <div>
                      <a className="back-link" href={href(project)}>
                        ← All firmware releases
                      </a>
                      <h1>{scan.data.label || "Firmware analysis"}</h1>
                      <div className="scan-subtitle">
                        <Badge value={scan.data.status} />
                        <span>{date(scan.data.created_at)}</span>
                        <code>{scan.data.artifact_id.slice(0, 16)}…</code>
                      </div>
                    </div>
                    <button onClick={() => setUploadOpen(true)}>
                      <Plus size={16} />
                      Analyze another release
                    </button>
                  </div>
                  <nav className="tabs" aria-label="Scan views">
                    {tabs.map((t) => (
                      <a
                        key={t.id}
                        className={current.tab === t.id ? "active" : ""}
                        href={href(project, current.scan, t.id)}
                      >
                        <t.icon size={16} />
                        {t.label}
                      </a>
                    ))}
                  </nav>
                  <div key={`${current.scan}-${current.tab}`}>
                    {current.tab === "overview" ? (
                      <Overview scan={scan.data} base={base} refresh={bump} />
                    ) : !readyResult ? (
                      <Empty title="Results are not available yet">
                        Return to Overview for progress and stage diagnostics.
                      </Empty>
                    ) : current.tab === "findings" ? (
                      <Findings
                        base={base}
                        selected={current.finding}
                        onSelect={(id) => {
                          location.hash = href(
                            project,
                            current.scan,
                            "findings",
                            id,
                          );
                        }}
                      />
                    ) : current.tab === "components" ? (
                      <Components base={base} />
                    ) : current.tab === "files" ? (
                      <Files base={base} />
                    ) : current.tab === "compare" ? (
                      <CompareView
                        project={project}
                        scan={scan.data}
                        scans={scans.data?.items ?? []}
                      />
                    ) : current.tab === "assistant" ? (
                      <Assistant
                        base={base}
                        project={project}
                        scan={current.scan}
                        settings={settings.data}
                        scans={scans.data?.items ?? []}
                      />
                    ) : (
                      <Reports base={base} scan={scan.data} />
                    )}
                  </div>
                </>
              )}
            </>
          )}
        </main>
        <footer className="footer">
          <span>
            <FlaskConical size={14} /> Built for authorized research
          </span>
          <span>
            Static observations. Traceable evidence. Honest uncertainty.
          </span>
        </footer>
      </div>
      {uploadOpen && (
        <UploadModal
          project={project}
          onClose={() => setUploadOpen(false)}
          onCreated={(s) => {
            setUploadOpen(false);
            location.hash = href(project, s.id);
            bump();
          }}
        />
      )}
      {createOpen && (
        <Modal
          title="Create research project"
          onClose={() => setCreateOpen(false)}
        >
          <form onSubmit={create}>
            <p className="muted">
              Group releases from the same product so their files and findings
              can be compared.
            </p>
            <label htmlFor="project-name">Project name</label>
            <input
              id="project-name"
              required
              maxLength={100}
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Gateway firmware study"
            />
            <label htmlFor="project-description">Research scope</label>
            <textarea
              id="project-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={1000}
              placeholder="Authorized product, release family, and research objective"
            />
            <ErrorBox>{error}</ErrorBox>
            <button className="primary wide" disabled={creating}>
              {creating ? "Creating…" : "Create project"}
              <ArrowRight size={16} />
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
