# Limits and roadmap

FirmwareLens is a local static research workbench. Findings identify observations and potential advisory applicability; they do not prove reachability, exploitability, a working attack, or the absence of vulnerabilities. Results are limited by extraction, metadata, rule coverage, parser behavior and database freshness.

Implemented tradeoffs include conservative omission of links/special-file contents, bounded text previews, package metadata plus clearly labeled binary hints, a small documented configuration rule set, and bounded JSON result storage. The interface shows the most recent 50 scans while the API supports paginated history. Findings, components and files are searchable/paginated. Reports include immutable analysis plus current analyst triage. Cross-scan triage keys intentionally omit hashes and component versions.

Redaction is pattern-based, not a proof that all proprietary secret formats have been recognized. Review exports and retrieved excerpts before external sharing. Raw original firmware remains local and authenticated. AI observations are exact catalog facts and citations are checked, but semantic accuracy of generated interpretations still needs human review. Provider-backed evaluation depends on the configured model; adapter tests cannot establish real-model quality or prompt-injection immunity.

The Docker supervisor has host-level runtime authority; containers are a kernel-sharing boundary. The project is not hardened for hostile multi-tenant use or internet exposure. Automatic exploitation, live-device scanning, firmware execution, emulation, autonomous zero-day discovery and fuzzing are not implemented. There is no placeholder endpoint for them.

Future work, outside this release: additional filesystem parsers under the same sandbox, a larger independently evaluated rule corpus, targeted semantic retrieval if measured useful, richer package-free inventory, signed release images, measured VM isolation alternatives, improved large-result indexing and optional execution/fuzzing integrations as a separately reviewed design.
