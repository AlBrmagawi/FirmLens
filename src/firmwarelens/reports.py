import html
import json
import re
from typing import Any
from urllib.parse import quote

from firmwarelens.redaction import clean


def md(value: Any) -> str:
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", html.escape(str(value)))


def report(data: dict, format: str) -> tuple[str, str]:
    data = clean(data)
    if format == "json":
        return json.dumps(data, indent=2, ensure_ascii=False), "application/json"
    if format == "sbom":
        if not data.get("result", {}).get("sbom"):
            raise ValueError("SBOM unavailable: component analysis did not complete")
        return json.dumps(data["result"]["sbom"], indent=2), "application/vnd.cyclonedx+json"
    if format == "sarif":
        result = data.get("result", {})
        findings = result.get("findings", [])
        rules = {
            f["rule_id"]: {
                "id": f["rule_id"],
                "shortDescription": {"text": f["rule_id"]},
                "help": {"text": f["remediation"]},
            }
            for f in findings
        }
        evidence = {e["id"]: e for e in result.get("evidence", [])}
        sarif_results = []
        for finding in findings:
            entry = {
                "ruleId": finding["rule_id"],
                "level": "error"
                if finding["severity"] in ("critical", "high")
                else "warning"
                if finding["severity"] == "medium"
                else "note",
                "message": {"text": finding["title"] + ". " + finding["explanation"]},
                "partialFingerprints": {"firmwarelens/v1": finding["fingerprint"]},
                "properties": {
                    "confidence": finding["confidence"],
                    "severity": finding["severity"],
                    "evidenceIds": finding["evidence_ids"],
                },
            }
            if finding["path"]:
                physical: dict[str, Any] = {
                    "artifactLocation": {
                        "uri": quote(finding["path"], safe="/"),
                        "uriBaseId": "%FIRMWARE_ROOT%",
                    }
                }
                lines = [
                    evidence[e]["line"]
                    for e in finding["evidence_ids"]
                    if e in evidence and evidence[e].get("line")
                ]
                if lines:
                    physical["region"] = {"startLine": min(lines)}
                entry["locations"] = [{"physicalLocation": physical}]
            sarif_results.append(entry)
        return json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "FirmwareLens",
                                "version": "0.1.0",
                                "rules": list(rules.values()),
                            }
                        },
                        "results": sarif_results,
                        "invocations": [
                            {"executionSuccessful": data.get("status") in ("complete", "partial")}
                        ],
                    }
                ],
            },
            indent=2,
        ), "application/sarif+json"
    result = data.get("result", {})
    title = (
        "FirmwareLens release comparison"
        if "comparison" in data
        else "FirmwareLens research report"
    )
    lines = [
        f"# {title}",
        "",
        "## Scope",
        "",
        f"Project: {md(data.get('project', ''))}",
        f"Scan: {md(data.get('id', 'comparison'))}",
        f"Outcome: {md(data.get('status', 'comparison'))}",
        f"SHA-256: {md(result.get('artifact_sha256', data.get('comparison', {}).get('artifact_hashes', {})))}",
        "",
        "## Methodology and limitations",
        "",
        "Static analysis of an authorized firmware artifact in an offline disposable container. Findings represent observations and potential applicability; they do not establish exploitability or reachability. Secret values are redacted. Prioritization uses severity and confidence separately; no invented CVSS scores.",
        "",
    ]
    if "comparison" in data:
        lines += ["## Comparison", "", md(json.dumps(data["comparison"], indent=2))]
    else:
        lines += [
            "## Coverage",
            "",
            *[
                f"- {md(s['id'])}: {md(s['state'])} — {md(s['message'])}"
                for s in result.get("stages", [])
            ],
            "",
            "## Findings and recommendations",
            "",
        ]
        evidence = {e["id"]: e for e in result.get("evidence", [])}
        for finding in result.get("findings", []):
            lines += [
                f"### {md(finding['title'])}",
                "",
                f"{md(finding['severity'])} severity · {md(finding['confidence'])} confidence · {md(finding['id'])}",
                "",
                md(finding["explanation"]),
                "",
                f"Recommendation: {md(finding['remediation'])}",
                "",
            ]
            for eid in finding["evidence_ids"]:
                if eid in evidence:
                    e = evidence[eid]
                    lines += [
                        f"Evidence {md(eid)}: {md(e['path'])}, line {md(e.get('line'))}, SHA-256 {md(e['artifact_sha256'])}",
                        md(e.get("excerpt", "")),
                        md(json.dumps(e.get("observation", {}))),
                        "",
                    ]
        lines += [
            "## Analyst triage",
            "",
            md(json.dumps(data.get("triage", []), indent=2)),
            "",
            "## Tool manifest",
            "",
            md(json.dumps(result.get("manifest", {}), indent=2)),
            "",
            *[md(v) for v in result.get("limitations", [])],
        ]
    markdown = "\n".join(lines)
    if format == "markdown":
        return markdown, "text/markdown"
    if format == "html":
        # Render our fixed structure directly; never interpret firmware or model text as HTML.
        body = []
        for line in lines:
            text = html.escape(re.sub(r"\\([\\`*_{}\[\]()#+.!|>~-])", r"\1", html.unescape(line)))
            if line.startswith("### "):
                body.append(f"<h3>{text[4:]}</h3>")
            elif line.startswith("## "):
                body.append(f"<h2>{text[3:]}</h2>")
            elif line.startswith("# "):
                body.append(f"<h1>{text[2:]}</h1>")
            else:
                body.append(f"<p>{text}</p>")
        return (
            '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>'
            + title
            + "</title><style>body{font:15px/1.6 system-ui;max-width:1000px;margin:40px auto;padding:24px;color:#172b3a}h1{border-bottom:4px solid #13796d}h2{margin-top:36px}p{white-space:pre-wrap;overflow-wrap:anywhere}h3{break-after:avoid}@media print{body{margin:0;font-size:10pt}h2{break-after:avoid}}</style><main>"
            + "\n".join(body)
            + "</main></html>",
            "text/html",
        )
    raise ValueError("Unsupported export format")
