// Generated from Pydantic. Run scripts/generate_types.py; do not edit.
export type AIAnswer = {
  claims: (AIClaim)[];
  cannot_answer: boolean;
};

export type AIClaim = {
  kind: "observation" | "interpretation" | "hypothesis" | "limitation";
  text: string;
  citations: (string)[];
};

export type AnalysisResult = {
  schema_version?: string;
  artifact_sha256: string;
  outcome: "complete" | "partial" | "failed" | "unsupported";
  format: string;
  payloads?: (Record<string, unknown>)[];
  files?: (FileRecord)[];
  findings?: (Finding)[];
  evidence?: (Evidence)[];
  components?: (Component)[];
  stages?: (Stage)[];
  sbom?: Record<string, unknown> | null;
  native_inventory?: Record<string, unknown> | null;
  manifest?: Record<string, unknown>;
  limitations?: (string)[];
};

export type Component = {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl?: string;
  identity_method?: string;
  evidence_ids?: (string)[];
  locations?: (string)[];
};

export type Evidence = {
  id: string;
  path: string;
  artifact_sha256: string;
  line?: number | null;
  offset?: number | null;
  key?: string | null;
  excerpt?: string;
  observation?: Record<string, unknown>;
  analyzer: string;
};

export type FileRecord = {
  path: string;
  sha256?: string;
  size: number;
  mode: number;
  uid?: number;
  gid?: number;
  kind?: string;
  link_target?: string | null;
  preview?: string | null;
  role?: string;
  elf?: Record<string, unknown> | null;
};

export type Finding = {
  id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  path: string;
  component_id?: string | null;
  evidence_ids: (string)[];
  explanation: string;
  remediation: string;
  analyzer: string;
  analyzer_version?: string;
  rule_version?: string;
  references?: (string)[];
  details?: Record<string, unknown>;
};

export type Limits = {
  max_files?: number;
  max_bytes?: number;
  max_file_bytes?: number;
  max_depth?: number;
  tool_timeout?: number;
  max_output?: number;
};

export type ScanOptions = {
  limits?: Limits;
  components?: boolean;
  vulnerabilities?: boolean;
};

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Stage = {
  id: string;
  version?: string;
  state: "success" | "failure" | "skipped" | "unsupported" | "partial";
  message: string;
  duration_ms?: number;
  diagnostics?: (string)[];
};

export type TriageUpdate = {
  status: "open" | "acknowledged" | "false-positive" | "accepted-risk" | "resolved";
  note?: string;
  suppress?: boolean;
  reason?: string;
  expires_at?: string | null;
};
