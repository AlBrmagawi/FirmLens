# Case study: evidence-driven firmware release review

## Problem and users

Firmware researchers need to answer which observations deserve investigation and whether a new release changes them. A list of version matches cannot establish device exploitability, and an extraction failure must not look like a successful remediation. FirmwareLens connects source artifacts, immutable parser observations, analyst decisions and reports in one local workflow.

## Implementation and trust boundaries

The FastAPI service authenticates a single local researcher and persists metadata in PostgreSQL. A leased database queue survives process restarts without adding a broker. A separate trusted supervisor alone accesses Docker; each job gets a fixed image, the current input subdirectory and a read-only intelligence volume. Analysis runs as UID 65532 with no network, dropped capabilities, no privilege escalation, a read-only root, bounded scratch, one CPU, 1.5 GiB memory and 64 processes. It never executes firmware binaries or startup scripts.

Typed plugins share a Python core and Pydantic contracts. The React workbench and Typer CLI use the same API. Original metadata is recorded while regular extracted files receive safe working permissions; symlinks and special files are not reconstructed in the analysis tree. Details and residual parser/kernel risks are in the [threat model](THREAT_MODEL.md).

## Synthetic release observations

The lab release was compiled and packaged from repository source. Its 12 deterministic static findings include an empty root password field, three risky SSH directives, configured Telnet startup, a synthetic password assignment, nonfunctional private-key material, two permission issues, and missing PIE/RELRO plus executable-stack metadata on the compiled probe. Evidence links include paths, hashes, redacted excerpts, directive names and ELF observations.

The revised release locks the account, restricts SSH, removes Telnet startup and credential material, tightens permissions, and compiles the probe with PIE, full RELRO, a non-executable stack and stack-protector indicators. All 12 static findings were no longer detected under successful relevant analysis stages. Static analysis does not establish whether either image could boot or expose a reachable service.

Synthetic Alpine package metadata changed BusyBox from `1.36.1-r15` to `1.36.1-r29`. Syft identified one component in each image. With the prepared real Grype database, 7 advisory matches appeared for the lab metadata and 3 for the revised metadata: totals of 19 and 3 findings. One lab candidate used a lower-confidence CPE match. The comparison reported 16 no longer detected, 3 persistent and no new findings. No fixture CVEs or scan results were invented; no corresponding BusyBox implementation is included in the fixture.

## AI retrieval

Retrieval ranks selected findings, question terms and severity, then builds a bounded catalog of actual findings, component identities and redacted evidence. Comparison data is included only after project/scan validation. The server sends this read-only catalog to a configured OpenAI Responses or Ollama adapter, with no shell, SQL, file or URL execution tools. Responses distinguish quoted observations, interpretations, hypotheses and limitations. Citation IDs are checked before display and link back to real records. AI output is separate from immutable analyzer results.

Automated evaluations exercise foreign IDs, fabricated observations, missing citations, secret redaction, context limits, hostile firmware instructions and provider request structure. These are deterministic boundary tests; they do not establish that a live model always resists prompt injection. Live provider quality remains unverified because no key or model was configured.

## Measurements and uncertainty

Single full pipeline runs measured 15.252 seconds for the lab and 10.052 seconds for the revised SquashFS. The largest child-process RSS observations were 175,992 and 187,528 KiB. These values exclude upload/queue/startup and are not total container peak memory. All seven synthetic input variants passed real extraction and inventory checks. The pinned OpenWrt integration inspected 1,398 entries, 368 components and 161 ELF files in 13.715 seconds of pipeline time, with explicit partial extraction coverage.

See [VALIDATION.md](VALIDATION.md) for the environment, database identity, exact checks, and unverified behaviors. There are no claimed precision/recall rates, production throughput numbers, exploitability confirmations or hosted CI badges.

## Evidence-based CV bullets

- Built a local firmware research workbench with FastAPI, PostgreSQL, React and a shared CLI, validating seven archive/filesystem variants through isolated Linux analysis containers.
- Integrated Syft, Grype and ELF/configuration analysis with traceable evidence, CycloneDX/SARIF exports and release comparison; measured 19 versus 3 findings across source-built synthetic releases.
- Implemented leased job recovery, authenticated local access and constrained analysis sandboxes; verified the browser workflow, adversarial extraction tests, secret redaction and scoped AI citation validation.
