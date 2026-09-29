import type {
  Component,
  Evidence,
  FileRecord,
  Finding,
  Stage,
  TriageUpdate,
} from "./generated";

export type Project = {
  id: string;
  name: string;
  description: string;
  created_at: string;
};
export type Scan = {
  id: string;
  project_id: string;
  label: string;
  artifact_id: string;
  status: string;
  created_at: string;
  finished_at: string | null;
  attempts: number;
  cancel_requested: boolean;
  error: string | null;
  format: string | null;
  summary: {
    files: number;
    components: number;
    findings: number;
    severity: Record<string, number>;
  };
  stages: Stage[];
  manifest: Record<string, unknown>;
  limitations: string[];
  payloads: Record<string, unknown>[];
};
export type Triage = TriageUpdate & {
  suppressed: boolean;
  updated_at?: string;
};
export type FindingRow = Finding & { triage: Triage; priority: number };
export type FindingDetail = FindingRow & {
  evidence: Evidence[];
  history: { at: string; change: Record<string, unknown> }[];
};
export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
};
export type Settings = {
  database: string;
  supervisor: {
    alive: boolean;
    last_seen: number | null;
    sandbox: {
      ready: boolean;
      checks?: Record<string, boolean>;
      image?: string;
      engine?: string;
      tools?: Record<string, string>;
    };
  };
  limits: {
    upload_bytes: number;
    job_timeout_seconds: number;
    max_attempts: number;
  };
  ai: {
    provider: string;
    model: string;
    cloud_enabled: boolean;
    key_configured: boolean;
    disclosure: string;
    daily_requests: number;
    context_chars: number;
  };
};
export type Comparison = {
  before: string;
  after: string;
  artifact_hashes: { before: string; after: string };
  files: {
    added: string[];
    removed?: string[];
    modified: string[];
    not_observed_with_incomplete_coverage?: string[];
  };
  findings: Record<string, string[]>;
  components: {
    added: Component[];
    removed_candidates: Component[];
    version_changes: { name: string; before: string; after: string }[];
  };
  configuration_changes: {
    path: string;
    before: string | null;
    after: string | null;
    mode_before: string;
    mode_after: string;
  }[];
  hardening_changes: {
    path: string;
    before: FileRecord["elf"];
    after: FileRecord["elf"];
  }[];
  method_changes: {
    tools_or_rules_changed: boolean;
    database_changed: boolean;
  };
  interpretation: string;
  limitations: string[];
  coverage: Record<string, Record<string, Stage>>;
};
export type AIResult = {
  answer: {
    claims: { kind: string; text: string; citations: string[] }[];
    cannot_answer: boolean;
  };
  citations: Record<
    string,
    { type: string; path?: string; finding_id?: string; fact: string }
  >;
  provider: string;
  model: string;
  notice: string;
  ai_generated: boolean;
};
export type Conversation = {
  id: string;
  question: string;
  answer: AIResult | null;
  state: string;
  at: string;
};
export let csrf = "";
export function setCSRF(value: string) {
  csrf = value;
}
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch("/api/v1" + path, {
    ...init,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      ...init.headers,
    },
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(
      data.error?.message ?? `Request failed (${response.status})`,
    );
  }
  return response.json() as Promise<T>;
}
export function upload(
  project: string,
  file: File,
  onProgress: (value: number) => void,
): Promise<{ id: string; duplicate: boolean }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/v1/projects/${project}/artifacts`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.setRequestHeader("X-Filename", encodeURIComponent(file.name));
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable)
        onProgress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status >= 400)
          reject(new Error(data.error?.message ?? "Upload failed"));
        else resolve(data);
      } catch {
        reject(new Error("Upload response was invalid"));
      }
    };
    xhr.onerror = () =>
      reject(new Error("Upload interrupted. Check local server connectivity."));
    xhr.send(file);
  });
}
