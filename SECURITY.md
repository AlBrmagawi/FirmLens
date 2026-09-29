# Security policy

FirmwareLens 0.1.x is the initial development release. Use only for authorized firmware research and keep the application bound to localhost. Read [THREAT_MODEL.md](docs/THREAT_MODEL.md) for the actual guarantees and limitations.

Report vulnerabilities using [GitHub's private vulnerability reporting channel for FirmwareLens](https://github.com/AlBrmagawi/FirmLens/security/advisories/new). Private reporting is enabled on the canonical repository. Keep undisclosed security boundary failures and exploit details out of public issues and pull requests. If you are using a fork, report upstream defects to the canonical repository.

Useful reports include affected version/commit, a minimal synthetic reproducer, the trust boundary crossed, and expected versus actual behavior. Never attach provider keys, `.env`, original proprietary firmware, local databases or exported secrets. Acknowledgment and remediation timing depend on maintainer availability; no SLA is claimed.
