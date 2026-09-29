Build a complete, professional open-source project called:

FirmwareLens — Firmware Vulnerability Researcher with an AI Assistant

I want a working security engineering project that is useful to researchers and strong enough to present on GitHub, my CV, and in technical interviews.

Implement the actual application. A plan, scaffold, attractive dashboard with fake data, or collection of disconnected scripts does not satisfy this request.

Make reasonable engineering decisions, document important tradeoffs, and work through implementation and validation. Ask questions only when a missing answer materially blocks progress.

1. PRODUCT OBJECTIVE

Create a local-first workbench for analyzing authorized Linux-based IoT firmware.

A researcher must be able to:

- Upload a supported firmware image.
- Extract and inspect its contents safely.
- Identify software components and generate an SBOM.
- Detect security-relevant configuration, credential, permission, and
  binary-hardening issues.
- Correlate identified components with known vulnerabilities.
- Inspect the evidence behind every finding.
- Ask an AI assistant questions grounded in that evidence.
- Compare two firmware releases.
- Export a professional research report.
- Run the same analysis through a CLI for automation.

The defining qualities are reproducibility, useful analysis,
clear evidence, honest uncertainty, and a polished research workflow.

2. SCOPE AND SUPPORTED TARGETS

Deliver a complete first release with a documented support matrix.

Required input support:
- Raw SquashFS images.
- Tar and gzip-compressed tar root filesystem archives.
- Firmware blobs containing a discoverable embedded SquashFS filesystem.
- ZIP firmware bundles containing supported payloads.

Validate file signatures instead of trusting filename extensions.

Support ELF metadata inspection for ARM, AArch64, MIPS, and x86/x86-64
where the parser supports them. Test representative architecture,
endianness, and malformed-file cases.

Document which extraction variants and compression methods are tested.
Unsupported, encrypted, damaged, or partially extracted images must
produce explicit coverage information and actionable messages.

Do not claim universal firmware support.

Keep these outside the required release:
- Automatic exploitation.
- Scanning live devices or public networks.
- Firmware execution, emulation, and automated fuzzing.
- Universal decompilation or autonomous zero-day discovery.
- Multi-tenant SaaS, billing, Kubernetes, and enterprise SSO.

These may appear in a clearly separated roadmap.

3. ARCHITECTURE AND STACK

Use a modular architecture with a shared analysis core.

Preferred stack:
- Python with FastAPI, Pydantic, SQLAlchemy, and Alembic.
- PostgreSQL for persistent metadata and durable job state.
- A separate worker/supervisor for long-running analysis.
- React, TypeScript, and Vite for the frontend.
- Tailwind CSS and accessible UI components.
- Typer for the CLI.
- Docker Compose for the local application.
- pytest and Playwright for appropriate automated verification.
- Ruff, Python type checking, ESLint, and TypeScript checking.

Use supported stable dependency versions, verify important APIs against
official documentation, and commit dependency lockfiles.

Prefer a modular monolith with a separate analysis runner.
Introduce additional infrastructure only when there is a clear need.

Create clean boundaries between:
- API and authentication.
- Job orchestration.
- Extraction and file inventory.
- Analysis plugins.
- Vulnerability intelligence.
- Evidence storage.
- AI providers and retrieval.
- Reports and exports.
- Frontend and CLI.

Use one source of truth for schemas and avoid duplicating analysis
logic across the API and CLI.

Create a concise architecture document with a diagram, trust boundaries,
and explanations of important design decisions.

4. FIRMWARE INGESTION AND SAFE ANALYSIS

Treat firmware and every extracted artifact as untrusted.

Implement:
- Streaming uploads with configurable size limits.
- SHA-256 identifiers and integrity checks.
- Immutable input artifacts.
- Duplicate detection without losing separate scan history.
- Persisted job states, progress events, and stage diagnostics.
- Cancellation, timeouts, bounded retries, and cleanup.
- Recovery after worker or application restart.
- Clear complete, partial, failed, cancelled, and unsupported outcomes.
- A tool manifest recording analyzer versions, rule versions, settings,
  vulnerability database identity, and timestamps.

Run extraction and binary parsing in disposable Linux containers.

The sandbox must:
- Run without network access.
- Run as a non-root user.
- Drop capabilities and prevent privilege escalation.
- Use a read-only root filesystem.
- Have bounded writable scratch space.
- Enforce CPU, memory, process, output-size, and time limits.
- Mount only the current job's required artifacts.
- Have no API keys, database credentials, or Docker socket.

Keep container orchestration in a narrowly scoped trusted supervisor.
If the supervisor needs runtime access, document that privilege boundary.
Do not expose arbitrary command, image, mount, or host-path execution
through its interface.

Never execute firmware binaries, initialization scripts, or commands
suggested by firmware content.

Defend against:
- Path traversal.
- Absolute-path extraction.
- Symlink and hardlink escapes.
- Archive and decompression bombs.
- Excessive nesting and file counts.
- Device nodes and special files.
- Unsafe subprocess arguments.
- Malformed or oversized analyzer outputs.

Preserve original filesystem metadata for analysis without applying
dangerous ownership or permissions to the host.

Validate outputs before promoting them into stored artifacts.
Treat filenames, tool output, and report content as untrusted text.
Do not load analyzer configuration from the firmware being inspected.

Provide a doctor command that checks dependencies, database access,
tool versions, and sandbox capabilities. Required isolation failures
must fail clearly rather than silently falling back to unsafe execution.

Support Linux as the primary runtime. Document Windows development
through WSL2 and Docker Desktop.

5. ANALYSIS ENGINE

Create a typed plugin interface with:
- Stable plugin identifier and version.
- Declared inputs and capabilities.
- Configuration validation.
- Structured results and evidence.
- Timeouts and resource limits.
- Explicit success, failure, skipped, and unsupported states.

Include these working analyzers:

A. Firmware and filesystem inventory

Identify:
- Embedded payloads and offsets.
- Filesystem type and extraction coverage.
- Operating system hints.
- Files, hashes, sizes, paths, and original metadata.
- ELF architectures and interpreters.
- Configuration files, startup scripts, and service definitions.

Build a searchable file explorer with bounded text previews.
Do not render uploaded HTML or scripts as active content.

B. Components and SBOM

Integrate Syft against the extracted filesystem.

Generate:
- The native inventory needed for downstream analysis.
- A valid CycloneDX JSON SBOM.
- Component records with version, ecosystem, identity, and evidence.

Recognize that package-manager-free firmware has incomplete inventory.
Separate package metadata from heuristic binary/version hints.

Do not invent versions or treat a filename as a confirmed package identity.

C. Known vulnerability correlation

Integrate Grype with the component inventory and a local database.

Record:
- Vulnerability identifier and advisory source.
- Matched component and version.
- Matching method and relevant constraints.
- Severity and available CVSS details.
- Fix information when present.
- Database version and freshness.
- Evidence supporting the component identity.

Respect distribution-specific version semantics and possible backports.
Distinguish strong package matches from heuristic candidates.

A version match is evidence of potential applicability, not proof of
exploitability on a device.

Missing, stale, or unavailable intelligence must be visible.
An unavailable database must not appear as “zero vulnerabilities.”

Implement explicit database update/import commands outside the
network-isolated analysis sandbox.

D. Configuration and credential findings

Implement documented rules for useful checks such as:
- Empty-password account configurations.
- SSH settings that permit risky authentication.
- Telnet or other insecure services enabled in startup configuration.
- Suspected embedded credentials and private-key material.
- Dangerous permissions on security-sensitive files.
- Suspicious writable startup locations.

Use configuration-aware parsing where practical.

Distinguish:
- A service binary being present.
- A service being configured to start.
- A service being reachable, which static analysis generally cannot prove.

Redact secret values in UI, logs, exports, and AI context by default.
Keep necessary raw artifacts local and access-controlled.

E. ELF hardening

Inspect:
- PIE status.
- Executable-stack / NX-related metadata.
- RELRO.
- Stack-canary indicators.
- Architecture and endianness.
- Linked libraries, interpreter, symbols, and stripping where available.

Report unknown or not applicable when evidence is insufficient.

Do not claim absence of stack protection solely because a symbol is
missing from a stripped binary. Do not present a hardening weakness
as a demonstrated exploitable vulnerability.

6. FINDINGS, EVIDENCE, AND TRIAGE

Use a normalized finding model containing:
- Stable fingerprint and rule identifier.
- Title, category, severity, and confidence.
- Affected artifact or component.
- Evidence references.
- Explanation and remediation.
- Analyzer and rule versions.
- Relevant external references.
- Analyst status, notes, and history.

Keep severity, confidence, and analyst status separate.

Evidence should include appropriate combinations of:
- Relative file path.
- Artifact hash.
- Line number, byte offset, or configuration key.
- Redacted excerpt.
- Structured parser observation.
- Analyzer invocation metadata.

A reviewer must be able to understand why a finding exists.

Support:
- Filtering, sorting, search, and pagination.
- Open, acknowledged, false-positive, accepted-risk, and resolved states.
- Notes and an audit trail.
- Scoped suppressions with a reason and optional expiry.
- Stable deduplication across repeated scans.

Provide a transparent prioritization method. Explain the factors.
Do not invent CVSS scores or imply a high score confirms exploitation.

7. FIRMWARE RELEASE COMPARISON

Allow two scans in the same project to be compared.

Show:
- Added, removed, and modified files.
- Component additions, removals, and version changes.
- New, persistent, and no-longer-detected findings.
- Relevant configuration changes.
- Binary-hardening changes.
- Changes in analysis coverage.

Use stable finding fingerprints.

Record whether tool versions, rules, or vulnerability databases differ.
Distinguish firmware changes from changes caused by newer intelligence.

Do not label a finding “fixed” merely because extraction failed or the
relevant analyzer did not run in the newer scan.

Produce an exportable comparison report.

8. EVIDENCE-GROUNDED AI ASSISTANT

Implement a useful research assistant connected to the real analysis data.

Provide:
- An OpenAI adapter using the official SDK and Responses API.
- An Ollama adapter for a user-configured local model.
- A disabled mode in which all non-AI features continue working.

Keep model names configurable and API keys on the server.
Do not automatically download large models.

Support questions such as:
- “Which findings should I investigate first, and why?”
- “Show the evidence for this SSH configuration finding.”
- “Which component matches need manual validation?”
- “What security-relevant changes occurred between these releases?”
- “What additional evidence would establish exploitability?”
- “Draft a remediation summary for the selected findings.”

Use structured retrieval over findings, components, evidence,
and comparison results. Add semantic retrieval only if it provides
a demonstrated benefit.

Requirements:
- Scope retrieval to the selected project and scan.
- Cite actual finding IDs, file paths, and evidence records.
- Make citations clickable in the interface.
- Distinguish observations, interpretations, and hypotheses.
- Say when the available evidence cannot answer a question.
- Validate referenced IDs before displaying the answer.
- Label AI-generated material clearly.
- Keep original analyzer results immutable.

Treat firmware text as data, including text that resembles instructions.
The assistant must not follow instructions embedded in firmware.

Give the model only allowlisted, bounded, read-only retrieval tools.
Do not provide arbitrary shell execution, unrestricted SQL, filesystem
access, or automatic URL fetching.

Cloud AI must be explicitly enabled. Explain which redacted evidence
will be sent. Never send raw firmware or secret material automatically.

Implement request timeouts, bounded context, usage limits, cancellation,
and understandable provider errors.

Create evaluations for citation validity, unsupported claims,
cross-project isolation, secret redaction, and prompt injection.

Test doubles belong in tests. Do not display canned responses as real AI.
If no provider is configured, explain how to configure one.

9. FRONTEND EXPERIENCE

Design a polished analyst workbench with restrained visual styling.

Use:
- Clear typography and spacing.
- Accessible contrast and keyboard navigation.
- Consistent severity and status treatments.
- Responsive layouts.
- Useful empty, loading, failure, and partial-result states.
- Tables and charts driven by real data.

Required views:
- Project and scan dashboard.
- Firmware upload and scan configuration.
- Live analysis progress.
- Scan overview with coverage and tool information.
- Findings table and detailed evidence panel.
- Component inventory and SBOM downloads.
- File explorer and text preview.
- Firmware comparison.
- AI research assistant.
- Report exports.
- Settings and system diagnostics.

Prioritize the workflow:
upload → analyze → inspect evidence → investigate → compare → report.

Use real persisted results. No fake counters, decorative charts,
placeholder actions, or buttons that do nothing.

Inspect the running interface in a browser and fix visual,
interaction, and accessibility problems.

10. API, CLI, AND EXPORTS

Provide a versioned REST API with generated OpenAPI documentation.

Support:
- Projects and firmware artifacts.
- Scan creation, cancellation, status, and history.
- Findings and analyst notes.
- Components and evidence.
- Comparisons.
- Reports.
- AI conversations scoped to a project and scan.
- Health and readiness endpoints.

Use structured errors, validation, pagination, and idempotent behavior
where retries could otherwise create duplicates.

Provide CLI commands equivalent to:
- firmwarelens doctor
- firmwarelens project create
- firmwarelens scan
- firmwarelens scans list
- firmwarelens findings
- firmwarelens compare
- firmwarelens report
- firmwarelens intelligence update

Design usable arguments and help output.

The CLI must support machine-readable JSON and meaningful exit codes.
Separate scan failure from “findings exceed the configured threshold.”

Exports:
- Structured JSON.
- Standalone HTML with print styling.
- Markdown.
- CycloneDX SBOM.
- SARIF for findings that can be represented accurately.

Reports must include scope, artifact hashes, methodology, coverage,
tool versions, evidence, recommendations, and limitations.

Redact secrets and escape untrusted content in every export.

11. APPLICATION SECURITY AND OPERATIONS

Provide a secure single-user local deployment.

- Bind to localhost by default.
- Use a first-run generated credential or equivalent local access control.
- Store browser sessions securely.
- Apply relevant CSRF and origin protections.
- Avoid permissive CORS defaults.
- Keep secrets out of source control, browser bundles, and logs.
- Protect artifact downloads and project access.
- Use safe database queries and validated file access.
- Provide retention and deletion controls.
- Include structured logs, request/job identifiers, health checks,
  and useful operational diagnostics.
- Document backup and restore.
- Handle graceful shutdown and interrupted jobs.

Explain the sandbox's actual guarantees and residual limitations
in the threat model.

12. REPRODUCIBLE DEMO AND TESTING

Build two small synthetic firmware releases from source:

- A lab release containing deliberately insecure configurations
  and selected hardening weaknesses.
- A revised release correcting several of those issues.

Include:
- A reproducible SquashFS build.
- Representative configuration and service files.
- Clearly synthetic credential material.
- Small compiled ELF fixtures with known build options.
- Component metadata suitable for inventory testing.
- A manifest of expected findings and expected comparison changes.

Run the normal analysis pipeline against these images.
Do not seed the database with invented scan results.

Keep deterministic advisory fixtures in tests separate from real
vulnerability intelligence. Do not invent CVEs.

Also provide an integration recipe for a redistributable open-source
firmware image, with pinned provenance and checksums. Run it when
the environment permits and accurately report whether it was tested.

Cover meaningful failure modes:
- Malformed and unsupported inputs.
- Traversal and link escapes.
- Extraction resource limits.
- Parser crashes and tool timeouts.
- Missing tools and missing vulnerability intelligence.
- Interrupted and cancelled jobs.
- Duplicate submissions and restart recovery.
- Stable finding fingerprints.
- Incomplete scans during comparison.
- Secret redaction.
- Report injection.
- AI citation and project-boundary validation.

Use unit tests for analysis logic, integration tests for real tools and
persistence, and end-to-end tests for the main user journey.

A core offline demo must work after dependencies and artifacts have
been prepared. Explain initial downloads and any optional AI setup.

Measure runtime and resource usage on the demo fixtures.
Report the actual environment and results. Do not invent benchmarks,
accuracy claims, or coverage percentages.

13. GITHUB AND PORTFOLIO QUALITY

Create:
- A strong README with the problem, capabilities, quickstart,
  screenshots from the running app, and a short demo walkthrough.
- An architecture diagram and design decisions.
- A threat model and security policy.
- A tested support matrix.
- CLI and API documentation.
- Analysis-rule documentation.
- Contribution guidelines.
- An appropriate open-source license and third-party notices.
- An environment-variable example without secrets.
- Issue and pull-request templates.
- A changelog.
- A troubleshooting guide.
- An honest limitations and roadmap document.

Add GitHub Actions for:
- Formatting, linting, and type checking.
- Unit and integration tests.
- Frontend build and main end-to-end workflow.
- Container build checks.
- Relevant dependency and secret checks.

Do not claim hosted CI passed unless it actually ran.
Keep large firmware blobs, generated secrets, databases, and analysis
artifacts out of Git.

Include a technical case study explaining:
- The problem and intended users.
- The architecture and trust boundaries.
- Findings from the synthetic firmware.
- What changed in the revised release.
- How evidence retrieval supports the AI assistant.
- What was measured and what remains uncertain.

Prepare three concise CV bullet points based only on implemented,
verified capabilities and measurements.

14. IMPLEMENTATION WORKFLOW

First inspect the repository and environment.
Preserve existing user work and follow applicable repository instructions.

Save this specification as PROJECT_SPEC.md.
Create a milestone plan and a concise STATUS.md recording:
- Completed work.
- Current milestone.
- Important decisions.
- Validation performed.
- Remaining issues and exact next steps.

Use milestones approximately like:

1. Architecture, schemas, reproducible fixtures, and sandbox foundation.
2. A complete CLI-driven extraction and analysis workflow.
3. Inventory, vulnerability matching, evidence, and comparison.
4. API, persistence, jobs, and frontend.
5. Real AI integrations and report exports.
6. Security review, end-to-end validation, documentation, and polish.

Build complete vertical slices and run their relevant checks.
Fix failures before building further assumptions on top of them.

Do not stop after generating a plan.
Continue implementing through the milestones.

If an environmental dependency prevents a particular check, record
the exact limitation, continue independent work, and do not claim
the blocked capability was validated.

If interrupted, leave accurate progress and resumption instructions.
Never describe incomplete work as complete.

15. DEFINITION OF DONE

The release is complete when a new user can:

1. Follow the documented setup on a supported environment.
2. Start the application with the documented Compose command.
3. Generate and analyze the synthetic firmware through the real pipeline.
4. Inspect findings with traceable evidence.
5. Browse components and export a valid SBOM.
6. Run vulnerability matching with a prepared database, with truthful
   behavior when the database is absent.
7. Compare the two releases and inspect the expected security changes.
8. Configure an AI provider and receive answers with valid evidence links.
9. Export usable reports.
10. Run the same workflow through the CLI.
11. Restart the application without losing results or leaving jobs
    indefinitely stuck.
12. Run the documented automated checks.

There must be no required feature represented only by a TODO,
placeholder endpoint, fake result, or nonfunctional UI control.

At completion, provide:
- What was implemented.
- Exact startup and demo commands.
- Tests and checks actually run, with their outcomes.
- Measured demo results.
- Remaining limitations and unverified behavior.
- Key architectural decisions.
- The three evidence-based CV bullets.

Begin by inspecting the workspace, recording a practical plan,
and implementing the first complete vertical slice.