import { useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  FileCode2,
  FileSearch,
  GitCompareArrows,
  Search,
  Send,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { api } from "./api";
import type {
  AIResult,
  Comparison,
  Conversation,
  FindingDetail,
  FindingRow,
  Page,
  Scan,
  Settings,
  Triage,
} from "./api";
import type {
  Component,
  Evidence,
  FileRecord,
  TriageUpdate,
} from "./generated";
import {
  Badge,
  date,
  Empty,
  ErrorBox,
  human,
  Json,
  Loading,
  Modal,
  Pager,
  size,
  useLoad,
} from "./ui";
import { href } from "./App";

function EvidenceBlock({ evidence }: { evidence: Evidence }) {
  return (
    <article className="evidence">
      <div className="evidence-heading">
        <FileCode2 size={16} />
        <strong>{evidence.path}</strong>
        {evidence.line && <span>line {evidence.line}</span>}
      </div>
      <p className="small muted">
        {evidence.key} · {evidence.analyzer}
      </p>
      {evidence.excerpt && <pre className="code">{evidence.excerpt}</pre>}
      <Json value={evidence.observation} />
      <dl className="evidence-meta">
        <dt>Evidence ID</dt>
        <dd>
          <code>{evidence.id}</code>
        </dd>
        <dt>Artifact SHA-256</dt>
        <dd>
          <code>{evidence.artifact_sha256}</code>
        </dd>
      </dl>
    </article>
  );
}

function TriageForm({
  detail,
  base,
  onSaved,
}: {
  detail: FindingDetail;
  base: string;
  onSaved: () => void;
}) {
  const [status, setStatus] = useState<TriageUpdate["status"]>(
    detail.triage.status,
  );
  const [note, setNote] = useState(detail.triage.note ?? "");
  const [suppress, setSuppress] = useState(detail.triage.suppress ?? false);
  const [reason, setReason] = useState(detail.triage.reason ?? "");
  const [expiry, setExpiry] = useState(
    detail.triage.expires_at?.slice(0, 10) ?? "",
  );
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api<Triage>(`${base}/findings/${detail.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          status,
          note,
          suppress,
          reason,
          expires_at: expiry
            ? new Date(`${expiry}T23:59:59Z`).toISOString()
            : null,
        }),
      });
      setSaved(true);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="triage-form" onSubmit={submit}>
      <h3>Analyst assessment</h3>
      <label htmlFor="triage-status">Status</label>
      <select
        id="triage-status"
        value={status}
        onChange={(e) => {
          setStatus(e.target.value as TriageUpdate["status"]);
          setSaved(false);
        }}
      >
        {[
          "open",
          "acknowledged",
          "false-positive",
          "accepted-risk",
          "resolved",
        ].map((s) => (
          <option key={s} value={s}>
            {human(s)}
          </option>
        ))}
      </select>
      <label htmlFor="triage-note">Research notes</label>
      <textarea
        id="triage-note"
        value={note}
        onChange={(e) => {
          setNote(e.target.value);
          setSaved(false);
        }}
        placeholder="Validation steps, context, or remediation decisions…"
        maxLength={4000}
      />
      <label className="check">
        <input
          type="checkbox"
          checked={suppress}
          onChange={(e) => setSuppress(e.target.checked)}
        />
        Suppress this fingerprint within this project
      </label>
      {suppress && (
        <>
          <label htmlFor="suppression-reason">Suppression reason</label>
          <input
            id="suppression-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
            maxLength={1000}
          />
          <label htmlFor="expiry">Expiry date (optional, UTC)</label>
          <input
            id="expiry"
            type="date"
            value={expiry}
            onChange={(e) => setExpiry(e.target.value)}
          />
        </>
      )}
      <ErrorBox>{error}</ErrorBox>
      <button className="primary" disabled={busy}>
        {saved ? <Check size={15} /> : null}
        {busy ? "Saving…" : saved ? "Assessment saved" : "Save assessment"}
      </button>
      <p className="small muted">
        Triage follows the stable fingerprint across scans in this project.
        Original analyzer results stay unchanged.
      </p>
    </form>
  );
}

export function Findings({
  base,
  selected,
  onSelect,
}: {
  base: string;
  selected: string;
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("priority");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const list = useLoad<Page<FindingRow>>(
    `${base}/findings?${new URLSearchParams({ q: query, severity, status, sort, offset: String(offset) })}`,
    refresh,
  );
  const detail = useLoad<FindingDetail>(
    selected ? `${base}/findings/${selected}` : null,
    refresh,
  );
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>Investigate the findings</h2>
          <p>
            Inspect the observation. Validate the context. Record your decision.
          </p>
        </div>
        <span className="count-label">{list.data?.total ?? "—"} findings</span>
      </div>
      <div className="toolbar">
        <div className="search-input">
          <Search size={16} />
          <input
            aria-label="Search findings"
            placeholder="Search title, path, or rule…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOffset(0);
            }}
          />
        </div>
        <select
          aria-label="Severity filter"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          aria-label="Status filter"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All statuses</option>
          {[
            "open",
            "acknowledged",
            "false-positive",
            "accepted-risk",
            "resolved",
          ].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          aria-label="Sort findings"
          value={sort}
          onChange={(e) => setSort(e.target.value)}
        >
          <option value="priority">Priority</option>
          <option value="title">Title</option>
          <option value="path">Path</option>
          <option value="confidence">Confidence</option>
        </select>
      </div>
      <ErrorBox>{list.error || detail.error}</ErrorBox>
      <div className={`findings-layout ${selected ? "with-detail" : ""}`}>
        <section className="panel flush">
          {list.loading && !list.data ? (
            <Loading />
          ) : list.data?.items.length ? (
            <>
              <div className="table-wrap">
                <table className="findings-table">
                  <thead>
                    <tr>
                      <th>Finding / evidence location</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.data.items.map((f) => (
                      <tr
                        key={f.id}
                        className={selected === f.id ? "selected" : ""}
                      >
                        <td>
                          <button
                            className="finding-link"
                            onClick={() => onSelect(f.id)}
                          >
                            <strong>{f.title}</strong>
                            <span>
                              <code>{f.rule_id}</code> ·{" "}
                              {f.path || "Component metadata"}
                            </span>
                          </button>
                          {f.triage.suppressed && (
                            <span className="small muted">
                              Suppressed for this project
                            </span>
                          )}
                        </td>
                        <td>
                          <Badge value={f.severity} />
                        </td>
                        <td>
                          <span className="confidence">{f.confidence}</span>
                        </td>
                        <td className="small">{human(f.triage.status)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager
                total={list.data.total}
                offset={offset}
                setOffset={setOffset}
              />
            </>
          ) : (
            <Empty title="No findings match this view">
              Check filters and analysis coverage before interpreting an empty
              result.
            </Empty>
          )}
          <div className="table-footnote">
            Priority = severity rank × 10 + confidence rank. Scores order
            review; they are not CVSS or proof of exploitation.
          </div>
        </section>
        {selected && (
          <aside className="detail-panel" aria-label="Finding evidence panel">
            <div className="detail-top">
              <span className="eyebrow">EVIDENCE & ASSESSMENT</span>
              <button
                className="icon-button"
                aria-label="Close finding detail"
                onClick={() => onSelect("")}
              >
                <X size={18} />
              </button>
            </div>
            {!detail.data ? (
              <Loading />
            ) : (
              <>
                <div className="detail-title">
                  <Badge value={detail.data.severity} />
                  <h2>{detail.data.title}</h2>
                  <p className="small muted">
                    {detail.data.confidence} confidence · {detail.data.rule_id}{" "}
                    v{detail.data.rule_version}
                  </p>
                </div>
                <p>{detail.data.explanation}</p>
                <div className="recommendation">
                  <ShieldAlert size={18} />
                  <div>
                    <strong>Recommended next step</strong>
                    <p>{detail.data.remediation}</p>
                  </div>
                </div>
                <h3>Traceable evidence</h3>
                {detail.data.evidence.map((e) => (
                  <EvidenceBlock key={e.id} evidence={e} />
                ))}
                {detail.data.references?.length ? (
                  <div className="references">
                    <h3>Advisory references</h3>
                    {detail.data.references
                      .filter((url) => url.startsWith("https://"))
                      .map((url) => (
                        <a
                          key={url}
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {url}
                        </a>
                      ))}
                  </div>
                ) : null}
                <details>
                  <summary>Structured finding details</summary>
                  <Json value={detail.data.details} />
                  <code>{detail.data.fingerprint}</code>
                </details>
                <TriageForm
                  key={detail.data.id}
                  detail={detail.data}
                  base={base}
                  onSaved={() => setRefresh((v) => v + 1)}
                />
                <details>
                  <summary>
                    Audit history ({detail.data.history.length})
                  </summary>
                  {detail.data.history.map((entry, i) => (
                    <div key={i}>
                      <p className="small">{date(entry.at)}</p>
                      <Json value={entry.change} />
                    </div>
                  ))}
                </details>
              </>
            )}
          </aside>
        )}
      </div>
    </>
  );
}

export function Components({ base }: { base: string }) {
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [evidenceId, setEvidenceId] = useState("");
  const data = useLoad<Page<Component>>(
    `${base}/components?q=${encodeURIComponent(query)}&offset=${offset}`,
  );
  const evidence = useLoad<Evidence>(
    evidenceId ? `${base}/evidence/${evidenceId}` : null,
  );
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>Component inventory</h2>
          <p>Package metadata and heuristic identities stay distinct.</p>
        </div>
        <a
          className="button primary"
          href={`/api/v1${base}/report?format=sbom`}
        >
          <ArrowDownToLine size={16} />
          CycloneDX SBOM
        </a>
      </div>
      <div className="notice">
        <FileSearch size={19} />
        <p>
          Inventory may be incomplete on firmware without package metadata.
          Versions reflect the evidence Syft identified; confirm heuristic
          binary matches manually.
        </p>
      </div>
      <div className="search-input solo">
        <Search size={16} />
        <input
          aria-label="Search components"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOffset(0);
          }}
          placeholder="Search component, ecosystem or version…"
        />
      </div>
      <ErrorBox>{data.error}</ErrorBox>
      <section className="panel flush">
        {data.data?.items.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Version</th>
                    <th>Ecosystem</th>
                    <th>Identity basis</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.data.items.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <strong>{c.name}</strong>
                        <code className="purl">{c.purl}</code>
                      </td>
                      <td>
                        <code>{c.version || "Unknown"}</code>
                      </td>
                      <td>{c.ecosystem}</td>
                      <td>
                        <span
                          className={
                            c.identity_method === "heuristic-binary"
                              ? "high-label"
                              : ""
                          }
                        >
                          {human(c.identity_method ?? "unknown")}
                        </span>
                      </td>
                      <td>
                        {c.evidence_ids?.map((id, i) => (
                          <button
                            className="text-button"
                            key={id}
                            onClick={() => setEvidenceId(id)}
                          >
                            Record {i + 1}
                            <ChevronRight size={14} />
                          </button>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              total={data.data.total}
              offset={offset}
              setOffset={setOffset}
            />
          </>
        ) : data.loading ? (
          <Loading />
        ) : (
          <Empty title="No components recorded">
            Review component-stage coverage. An empty inventory does not
            establish the absence of third-party software.
          </Empty>
        )}
      </section>
      {evidenceId && (
        <Modal
          title="Component identity evidence"
          onClose={() => setEvidenceId("")}
        >
          <ErrorBox>{evidence.error}</ErrorBox>
          {evidence.data ? (
            <EvidenceBlock evidence={evidence.data} />
          ) : (
            <Loading />
          )}
        </Modal>
      )}
    </>
  );
}

export function Files({ base }: { base: string }) {
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [path, setPath] = useState("");
  const data = useLoad<Page<FileRecord>>(
    `${base}/files?q=${encodeURIComponent(query)}&offset=${offset}`,
  );
  const preview = useLoad<FileRecord>(
    path ? `${base}/file?path=${encodeURIComponent(path)}` : null,
  );
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>Filesystem explorer</h2>
          <p>
            Original metadata. Bounded, redacted text previews. No active
            content.
          </p>
        </div>
        <span className="count-label">{data.data?.total ?? "—"} entries</span>
      </div>
      <div className="search-input solo">
        <Search size={16} />
        <input
          aria-label="Search files"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setOffset(0);
          }}
          placeholder="Filter by relative path…"
        />
      </div>
      <ErrorBox>{data.error || preview.error}</ErrorBox>
      <div className="file-layout">
        <section className="panel flush">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Original mode</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {data.data?.items.map((f) => (
                  <tr
                    key={f.path}
                    className={path === f.path ? "selected" : ""}
                  >
                    <td>
                      <button
                        className="file-link"
                        onClick={() => setPath(f.path)}
                      >
                        <FileCode2 size={15} />
                        <span>
                          {f.path}
                          {f.kind === "directory" ? "/" : ""}
                        </span>
                      </button>
                    </td>
                    <td>
                      <code>{f.mode.toString(8).padStart(4, "0")}</code>
                    </td>
                    <td className="small">{size(f.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.data && (
            <Pager
              total={data.data.total}
              offset={offset}
              setOffset={setOffset}
            />
          )}
        </section>
        <section className="panel file-preview">
          {preview.data ? (
            <>
              <div className="panel-title">
                <h2>{preview.data.path}</h2>
                <span className="small muted">{preview.data.kind}</span>
              </div>
              <dl className="facts">
                <dt>SHA-256</dt>
                <dd>
                  <code>{preview.data.sha256 || "Not a regular file"}</code>
                </dd>
                <dt>Original owner</dt>
                <dd>
                  {preview.data.uid}:{preview.data.gid}
                </dd>
                <dt>Original mode</dt>
                <dd>{preview.data.mode.toString(8)}</dd>
                <dt>Classification</dt>
                <dd>{preview.data.role}</dd>
              </dl>
              {preview.data.link_target && (
                <p>
                  Link metadata only: <code>{preview.data.link_target}</code>
                </p>
              )}
              {preview.data.preview !== null &&
              preview.data.preview !== undefined ? (
                <pre className="code numbered">
                  {preview.data.preview.split("\n").map((line, i) => (
                    <span key={i}>
                      <i>{i + 1}</i>
                      {line}
                      {"\n"}
                    </span>
                  ))}
                </pre>
              ) : (
                <div className="notice">
                  <p>
                    No text preview for this entry. Binary bytes and special
                    files are never rendered as active content.
                  </p>
                </div>
              )}
              {preview.data.elf && (
                <>
                  <h3>ELF observations</h3>
                  <Json value={preview.data.elf} />
                </>
              )}
              <p className="small muted">
                Previews are limited to 16 KiB. Secret patterns are redacted;
                review raw artifacts only in a controlled local environment.
              </p>
            </>
          ) : (
            <Empty title="Inspect a filesystem entry">
              Select a path to see its hash, original permissions, content
              preview, and available ELF metadata.
            </Empty>
          )}
        </section>
      </div>
    </>
  );
}

export function CompareView({
  project,
  scan,
  scans,
}: {
  project: string;
  scan: Scan;
  scans: Scan[];
}) {
  const eligible = scans.filter((s) => s.id !== scan.id && s.stages.length);
  const [before, setBefore] = useState(eligible[0]?.id ?? "");
  const [submitted, setSubmitted] = useState("");
  const result = useLoad<Comparison>(
    submitted
      ? `/projects/${project}/compare?before=${submitted}&after=${scan.id}`
      : null,
  );
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>What changed between releases?</h2>
          <p>
            Separate firmware changes from changes in analysis and intelligence.
          </p>
        </div>
      </div>
      <section className="panel compare-picker">
        <div>
          <label htmlFor="baseline">Baseline release</label>
          <select
            id="baseline"
            value={before}
            onChange={(e) => setBefore(e.target.value)}
          >
            <option value="" disabled>
              Select baseline
            </option>
            {eligible.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label} · {s.status}
              </option>
            ))}
          </select>
        </div>
        <ArrowRight size={22} />
        <div>
          <label>Selected release</label>
          <strong>{scan.label}</strong>
        </div>
        <button
          className="primary"
          disabled={!before}
          onClick={() => setSubmitted(before)}
        >
          <GitCompareArrows size={17} />
          Compare releases
        </button>
      </section>
      <ErrorBox>{result.error}</ErrorBox>
      {result.loading ? (
        <Loading />
      ) : result.data ? (
        <>
          <div className="notice">
            <GitCompareArrows size={20} />
            <div>
              <strong>{result.data.interpretation}</strong>
              <p>
                Tool/rule changes:{" "}
                {result.data.method_changes.tools_or_rules_changed
                  ? "yes"
                  : "no"}{" "}
                · Database changed:{" "}
                {result.data.method_changes.database_changed ? "yes" : "no"}
              </p>
            </div>
          </div>
          <div className="stats">
            {Object.entries(result.data.findings).map(([key, ids]) => (
              <div className="stat" key={key}>
                <span>{human(key)}</span>
                <strong>{ids.length}</strong>
              </div>
            ))}
          </div>
          <section className="panel">
            <div className="panel-title">
              <h2>Finding changes</h2>
              <a
                className="button"
                href={`/api/v1/projects/${project}/compare/export?before=${submitted}&after=${scan.id}&format=html`}
              >
                <ArrowDownToLine size={16} />
                Export comparison
              </a>
            </div>
            {Object.entries(result.data.findings).map(([key, ids]) => (
              <details key={key}>
                <summary>
                  {human(key)} ({ids.length})
                </summary>
                {ids.length ? (
                  <ul>
                    {ids.map((id) => (
                      <li key={id}>
                        <a
                          href={href(
                            project,
                            key === "no_longer_detected" ||
                              key === "unknown_due_to_coverage"
                              ? submitted
                              : scan.id,
                            "findings",
                            id,
                          )}
                        >
                          Inspect finding {id}
                          <ChevronRight size={13} />
                        </a>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted">None in this category.</p>
                )}
              </details>
            ))}
          </section>
          <div className="two-col">
            <section className="panel">
              <h2>Filesystem changes</h2>
              {Object.entries(result.data.files).map(([key, paths]) => (
                <details key={key}>
                  <summary>
                    {human(key)} ({paths?.length ?? 0})
                  </summary>
                  <ul>
                    {paths?.map((path) => (
                      <li key={path}>
                        <code>{path}</code>
                      </li>
                    ))}
                  </ul>
                </details>
              ))}
            </section>
            <section className="panel">
              <h2>Component changes</h2>
              {result.data.components.version_changes.map((c, i) => (
                <div className="version-change" key={i}>
                  <strong>{c.name}</strong>
                  <code>{c.before}</code>
                  <ArrowRight size={15} />
                  <code>{c.after}</code>
                </div>
              ))}
              <details>
                <summary>Added and removed candidates</summary>
                <Json
                  value={{
                    added: result.data.components.added,
                    removed_candidates:
                      result.data.components.removed_candidates,
                  }}
                />
              </details>
            </section>
          </div>
          <section className="panel">
            <h2>Security-relevant changes</h2>
            {result.data.configuration_changes.map((change) => (
              <details key={change.path}>
                <summary>
                  {change.path} · {change.mode_before} → {change.mode_after}
                </summary>
                <div className="two-col">
                  <div>
                    <p className="eyebrow">BEFORE</p>
                    <pre className="code">{change.before}</pre>
                  </div>
                  <div>
                    <p className="eyebrow">AFTER</p>
                    <pre className="code">{change.after}</pre>
                  </div>
                </div>
              </details>
            ))}
            {result.data.hardening_changes.map((change) => (
              <details key={change.path}>
                <summary>ELF hardening: {change.path}</summary>
                <div className="two-col">
                  <Json value={change.before} />
                  <Json value={change.after} />
                </div>
              </details>
            ))}
            <details>
              <summary>Analysis coverage comparison</summary>
              <Json value={result.data.coverage} />
            </details>
            <ul className="small muted">
              {result.data.limitations.map((text) => (
                <li key={text}>{text}</li>
              ))}
            </ul>
          </section>
        </>
      ) : (
        <Empty
          title={
            eligible.length
              ? "Choose a baseline to compare"
              : "A second analyzed release is needed"
          }
        >
          Both releases must belong to this project. Incomplete coverage is
          shown explicitly and never treated as a fix.
        </Empty>
      )}
    </>
  );
}

export function Assistant({
  base,
  project,
  scan,
  settings,
  scans,
}: {
  base: string;
  project: string;
  scan: string;
  settings: Settings | null;
  scans: Scan[];
}) {
  const [question, setQuestion] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [comparison, setComparison] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [evidenceId, setEvidenceId] = useState("");
  const controller = useRef<AbortController | null>(null);
  const conversations = useLoad<Conversation[]>(
    base + "/conversations",
    refresh,
  );
  const findings = useLoad<Page<FindingRow>>(base + "/findings?limit=100");
  const evidence = useLoad<Evidence>(
    evidenceId ? `${base}/evidence/${evidenceId}` : null,
  );
  const enabled = settings?.ai.provider !== "disabled";
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    controller.current = new AbortController();
    try {
      await api<AIResult>(base + "/assistant", {
        method: "POST",
        signal: controller.current.signal,
        body: JSON.stringify({
          question,
          finding_ids: selected,
          compare_scan_id: comparison || null,
        }),
      });
      setQuestion("");
    } catch (err) {
      setError(
        err instanceof DOMException && err.name === "AbortError"
          ? "Request cancelled. Provider generation has been interrupted where supported."
          : (err as Error).message,
      );
    } finally {
      setBusy(false);
      setRefresh((v) => v + 1);
    }
  }
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>
            <Sparkles size={23} /> Research assistant
          </h2>
          <p>
            Ask about the evidence in this scan. Keep your judgment in the loop.
          </p>
        </div>
        <span className="count-label">
          {settings?.ai.provider ?? "Checking provider"}
        </span>
      </div>
      {!enabled ? (
        <section className="panel">
          <Empty title="AI assistance is disabled">
            All analysis, evidence, comparison, and export features remain
            available. Configure an existing local Ollama model or explicitly
            enable OpenAI in Settings.
          </Empty>
          <a className="button primary center" href="#/settings">
            Provider settings
            <ArrowRight size={16} />
          </a>
        </section>
      ) : (
        <>
          <div className="notice">
            <Sparkles size={19} />
            <p>{settings?.ai.disclosure}</p>
          </div>
          <section className="panel">
            <details>
              <summary>Scope the evidence context</summary>
              <p className="small muted">
                Choose up to 20 findings. Retrieval remains bounded to this scan
                and project.
              </p>
              <div className="finding-picker">
                {findings.data?.items.map((f) => (
                  <label className="check" key={f.id}>
                    <input
                      type="checkbox"
                      checked={selected.includes(f.id)}
                      disabled={
                        !selected.includes(f.id) && selected.length >= 20
                      }
                      onChange={(e) =>
                        setSelected((ids) =>
                          e.target.checked
                            ? [...ids, f.id]
                            : ids.filter((id) => id !== f.id),
                        )
                      }
                    />
                    {f.title}
                  </label>
                ))}
              </div>
              <label htmlFor="ai-compare">Include comparison with</label>
              <select
                id="ai-compare"
                value={comparison}
                onChange={(e) => setComparison(e.target.value)}
              >
                <option value="">No comparison</option>
                {scans
                  .filter((s) => s.id !== scan && s.stages.length)
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
              </select>
            </details>
            <form onSubmit={submit}>
              <label htmlFor="question">Research question</label>
              <textarea
                id="question"
                placeholder="Which findings should I investigate first, and what evidence supports them?"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                required
                maxLength={2000}
              />
              <div className="assistant-controls">
                <span className="small muted">
                  No shell, arbitrary SQL, or URL-fetching tools.
                </span>
                {busy ? (
                  <button
                    type="button"
                    onClick={() => controller.current?.abort()}
                  >
                    <X size={16} />
                    Cancel request
                  </button>
                ) : (
                  <button className="primary" disabled={!question.trim()}>
                    <Send size={16} />
                    Ask about this evidence
                  </button>
                )}
              </div>
            </form>
          </section>
        </>
      )}
      <ErrorBox>{error || conversations.error}</ErrorBox>
      {busy && <Loading />}
      {conversations.data?.map((conversation) => (
        <section className="panel conversation" key={conversation.id}>
          <div className="question">
            <span className="eyebrow">YOUR QUESTION</span>
            <h3>{conversation.question}</h3>
            <span className="small muted">{date(conversation.at)}</span>
          </div>
          {conversation.answer ? (
            <>
              <p className="ai-label">
                <Sparkles size={15} />
                AI-generated · {conversation.answer.provider} /{" "}
                {conversation.answer.model}
              </p>
              {conversation.answer.answer.claims.map((claim, i) => (
                <div className={`claim claim-${claim.kind}`} key={i}>
                  <span className="eyebrow">{claim.kind}</span>
                  <p>{claim.text}</p>
                  <div className="citations">
                    {claim.citations.map((id) => {
                      const citation = conversation.answer!.citations[id];
                      return citation?.type === "finding" ? (
                        <a key={id} href={href(project, scan, "findings", id)}>
                          <FileSearch size={13} />
                          {citation.path || id.slice(0, 8)}
                        </a>
                      ) : citation?.type === "evidence" ? (
                        <button key={id} onClick={() => setEvidenceId(id)}>
                          <FileCode2 size={13} />
                          {citation.path}
                        </button>
                      ) : (
                        <span key={id}>{citation?.fact ?? id}</span>
                      );
                    })}
                  </div>
                </div>
              ))}
              <p className="small muted">{conversation.answer.notice}</p>
            </>
          ) : (
            <Badge value={conversation.state} />
          )}
        </section>
      ))}
      {evidenceId && (
        <Modal title="Cited evidence" onClose={() => setEvidenceId("")}>
          <ErrorBox>{evidence.error}</ErrorBox>
          {evidence.data ? (
            <EvidenceBlock evidence={evidence.data} />
          ) : (
            <Loading />
          )}
        </Modal>
      )}
    </>
  );
}

export function Reports({ base, scan }: { base: string; scan: Scan }) {
  const formats = [
    {
      id: "html",
      title: "Research report",
      extension: "HTML",
      description:
        "Standalone report with scope, coverage, findings, evidence, recommendations, and print styling.",
    },
    {
      id: "markdown",
      title: "Portable write-up",
      extension: "MARKDOWN",
      description:
        "A redacted, reviewable research write-up for source control and documentation.",
    },
    {
      id: "json",
      title: "Structured results",
      extension: "JSON",
      description:
        "Complete normalized analysis results, reproducibility manifest, and analyst triage.",
    },
    {
      id: "sbom",
      title: "Software bill of materials",
      extension: "CYCLONEDX",
      description:
        "Syft-generated component inventory in standard CycloneDX JSON format.",
    },
    {
      id: "sarif",
      title: "Static-analysis findings",
      extension: "SARIF 2.1.0",
      description:
        "Representable findings with source paths, locations, severity, and stable fingerprints.",
    },
  ];
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>Research exports</h2>
          <p>
            Share the evidence, the methodology, and the limits of the
            assessment.
          </p>
        </div>
      </div>
      <div className="notice">
        <ShieldAlert size={20} />
        <p>
          Reports reflect this scan’s <strong>{scan.status}</strong> coverage.
          Secret values are redacted by default. Review exports before sharing
          outside your research environment.
        </p>
      </div>
      <div className="export-grid">
        {formats.map((format) => (
          <section className="panel export-card" key={format.id}>
            <div>
              <span className="eyebrow">{format.extension}</span>
              <ArrowDownToLine size={20} />
            </div>
            <h2>{format.title}</h2>
            <p>{format.description}</p>
            <a
              className="button"
              href={`/api/v1${base}/report?format=${format.id}`}
              download
            >
              Download {format.extension}
              <ArrowRight size={15} />
            </a>
          </section>
        ))}
      </div>
      <section className="panel">
        <h2>Scope follows the artifact</h2>
        <p>
          Every report includes the immutable input hash and tool manifest.
          Missing intelligence and failed stages remain visible. An advisory
          match is potential applicability, not a demonstrated device
          vulnerability.
        </p>
        <code className="hash">{scan.artifact_id}</code>
      </section>
    </>
  );
}
