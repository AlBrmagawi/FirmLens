# Analysis rules v1.0.0

| Rule | Observation | Severity / confidence | Interpretation limits |
|---|---|---|---|
| AUTH-001 | Empty password field in passwd/shadow | High / high | PAM, shell, daemon settings and account state determine actual authentication |
| SSH-001 | First directive in a global/Match scope permits root/password/empty-password authentication | High (password authentication: medium) / medium | Include ordering, Match conditions and daemon command-line settings need runtime validation |
| SVC-001 | Active startup/inetd/inittab line invokes telnetd | High / high | Configured startup is not proof of reachability; mere binary presence is not this rule |
| CRED-001 | Literal assignment to a credential-like key, including prefixed keys | High / medium | Heuristic; examples and nonsecret configuration values may match |
| CRED-002 | Private-key PEM markers | High / medium | Can include synthetic fixtures; no key validity or key reuse claim |
| PERM-001 | World-writable security-sensitive file, or world-accessible shadow | High / high | Uses original metadata, not normalized extraction permissions |
| PERM-002 | World-writable startup directory | High / high | Actual ability to affect boot depends on ownership and boot behavior |
| ELF-001 | ET_EXEC rather than confirmed PIE | Medium / high | Build hardening observation, not exploitability |
| ELF-002 | PT_GNU_STACK requests execute permission | High / high | Missing stack segment is unknown, not NX failure |
| ELF-003 | Executable/shared object lacks GNU_RELRO | Medium / high | No claim of an exploitable memory-safety bug |
| ELF-004 | GNU_RELRO without immediate binding | Low / high | Partial RELRO; build compatibility may constrain changes |
| VULN-001 | Grype local advisory match | Advisory severity / high or low | CPE/binary hints are candidates; distribution backports and build applicability require review |

Configuration checks read regular textual files up to 1 MiB. Preview sampling reads 64 KiB and stores at most 16 KiB after redaction. Binary-embedded arbitrary secrets are not exhaustively searched. SSH parsing is deliberately scoped, first-value-aware and comment-aware; it is not `sshd -T` and never executes a firmware daemon.

ELF inspection records architecture, endianness, ELF type, interpreter, linked libraries, stripping, symbol counts, PIE, stack metadata, RELRO and canary indicators. Absence of canary symbols is always **unknown**, including stripped/static binaries. ET_DYN without interpreter or DF_1_PIE remains unknown rather than mislabeling a shared library as PIE.

Evidence records carry a relative path, input/file SHA-256, line/config key when applicable, a redacted excerpt, structured observation, and analyzer identity. Finding fingerprints use rule + relative path + stable semantic key; vulnerability fingerprints use advisory + package identity without the version. A hash change does not itself discard analyst triage.

Review priority is `severity rank × 10 + confidence rank`, with severity critical/high/medium/low/info = 5/4/3/2/1 and confidence high/medium/low = 3/2/1. This is an ordering heuristic, not CVSS. Analyst status and suppression are separate and never rewrite analyzer findings. Suppressions are scoped to project and fingerprint, require a reason, and can expire.
