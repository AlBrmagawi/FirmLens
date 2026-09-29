# Threat model

## Assets and adversaries

Protect the researcher's host, original firmware, local credentials, provider keys, project isolation and the integrity of evidence. Firmware filenames, filesystem metadata, strings, package inventories, binary parser output and model output are adversarial. The local operator, built application, container runtime, operating system and installed analyzer supply chain are trusted. This is a single-user application, not a hostile multi-tenant service.

| Threat | Implemented control | Remaining boundary |
|---|---|---|
| Archive traversal, symlink/hardlink escapes | Signature-led parsing, relative path checks, duplicate rejection, no links in sanitized root | SquashFS external parser runs in the sandbox before normalization |
| Special files and dangerous modes | Never materialize archive device/FIFO entries; normalize copied regular files to 0600 | Original mode is retained as data; sandbox extraction itself may temporarily have firmware modes |
| Decompression or nesting bombs | File/byte/depth limits, stage deadlines, 768 MiB tmpfs, process/output/job limits | Resource limits cap damage; large malformed inputs can still exhaust their sandbox and fail |
| Parser compromise | UID 65532, no network, read-only root, no capabilities, no-new-privileges, Docker default seccomp, noexec/nosuid/nodev scratch | Containers share the Linux kernel; this is not a VM boundary or a claim of perfect containment |
| Secret exposure | Pattern redaction in previews/evidence, exports and retrieval; raw input download authenticated; no request bodies/tool stderr in logs | Pattern redaction cannot recognize every proprietary secret format; review exports before sharing |
| Report/UI injection | React text nodes, escaped standalone HTML, escaped Markdown, attachment downloads, CSP, nosniff | Raw firmware is intentionally available to the authenticated owner as an inert download |
| Session/CSRF abuse | Random first-run token, HttpOnly SameSite=Strict session, bounded expiry, per-session CSRF header and exact Origin checks | Local HTTP uses non-Secure cookies; use TLS and FL_SECURE_COOKIE=true for a deliberate reverse-proxy deployment |
| DNS rebinding | Restricted Host allowlist and localhost published port | Do not publish the service on an untrusted interface |
| Prompt injection | Firm firmware/data boundary, no model tools, scoped catalog, secret redaction, citation validation | Language models can still make misleading interpretations; hypotheses remain unverified |
| Cross-project access | Every scan/evidence/comparison lookup checks project ownership | One authenticated local owner can deliberately access all their projects |
| Restart/cancel races | Durable state, lease tokens, bounded recovery, cancellation check before result promotion | Abrupt host loss can leave a container until recovery; the trusted supervisor removes stale job containers |
| Supervisor compromise | No public supervisor interface, fixed container parameters, no request-controlled command/image/mount | Docker socket grants host-level capability; isolate this deployment from valuable host workloads |

Default analysis limits: 128 MiB upload, 20,000 entries, 256 MiB extracted regular-file bytes, 32 MiB per file, nesting depth 3, 16 MiB promoted JSON, 90-second external-tool timeout, 600-second whole-job timeout. Container limits: one CPU, 1536 MiB memory including tmpfs, no extra swap, 64 processes, 768 MiB scratch plus 16 MiB temporary space. Limits are explicit and bounded; failures do not fall back to host execution.

The local Docker daemon retains capped container logs until the sandbox is removed. Tmpfs can interact with host swap; avoid unencrypted host swap for sensitive investigations. PostgreSQL, Docker volumes, backups and downloaded raw artifacts require local disk access controls. `.env`, exports, generated images and databases are ignored by Git.
