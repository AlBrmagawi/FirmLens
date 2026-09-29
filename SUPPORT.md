# Getting help

Start with the [quickstart](README.md#quickstart), [operations guide](docs/OPERATIONS.md) and [supported input matrix](docs/SUPPORT_MATRIX.md). FirmwareLens is intended for local, authorized research. The [release qualification](docs/RELEASE_READINESS.md) records what has been tested and what remains unverified.

## Check the local environment

Run these commands from the repository root after setup:

```sh
docker compose ps
docker compose exec api firmwarelens doctor --json
```

Allow the supervisor's initial isolation self-test to finish. If a scan is partial or unsupported, read its coverage diagnostics in the workbench. A missing advisory database requires the explicit intelligence preparation step in the [operations guide](docs/OPERATIONS.md#intelligence-maintenance). Unsupported containers, filesystems and codecs are documented in the support matrix. AI is optional and disabled until you configure a provider.

## Ask a question or report a problem

Search [existing issues](https://github.com/AlBrmagawi/FirmLens/issues), then choose the appropriate form:

- [Usage question](https://github.com/AlBrmagawi/FirmLens/issues/new?template=question.yml) for setup, supported workflows and interpreting coverage.
- [Bug report](https://github.com/AlBrmagawi/FirmLens/issues/new?template=bug_report.yml) for unexpected behavior with reproducible steps.
- [Feature proposal](https://github.com/AlBrmagawi/FirmLens/issues/new?template=feature_request.yml) for a concrete research need or coverage improvement.

Include the commit (`git rev-parse --short HEAD`), operating system, Docker version, browser when relevant and a minimal synthetic reproducer. Review diagnostic output and screenshots before sharing: remove access tokens, keys, private paths and identifying data. Never attach `.env`, proprietary firmware, database backups or unreviewed research exports.

For security vulnerabilities, use the **private** channel in [SECURITY.md](SECURITY.md). Community support is best effort; there is no guaranteed response time.
