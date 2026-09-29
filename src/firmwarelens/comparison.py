from typing import Any

from firmwarelens.schemas import AnalysisResult


def compare(old: AnalysisResult, new: AnalysisResult) -> dict[str, Any]:
    old_files = {f.path: f for f in old.files}
    new_files = {f.path: f for f in new.files}
    old_stages = {s.id: s.model_dump() for s in old.stages}
    new_stages = {s.id: s.model_dump() for s in new.stages}
    extraction_ok = new_stages.get("extraction", {}).get("state") == "success"
    modified = [
        path
        for path in sorted(old_files.keys() & new_files.keys())
        if (old_files[path].sha256, old_files[path].mode, old_files[path].link_target)
        != (new_files[path].sha256, new_files[path].mode, new_files[path].link_target)
    ]
    old_findings = {f.fingerprint: f for f in old.findings}
    new_findings = {f.fingerprint: f for f in new.findings}
    missing = old_findings.keys() - new_findings.keys()
    no_longer = [
        f
        for f in sorted(missing)
        if extraction_ok and new_stages.get(old_findings[f].analyzer, {}).get("state") == "success"
    ]
    unknown = sorted(missing - set(no_longer))

    def component_key(c):
        # PURL qualifiers and subpaths matter; remove only its version portion.
        return (
            c.ecosystem
            + ":"
            + c.name
            + ":"
            + (c.purl.partition("?")[2] if "?" in c.purl else "")
            + ":"
            + "|".join(sorted(c.locations))
        )

    oc = {component_key(c): c for c in old.components}
    nc = {component_key(c): c for c in new.components}
    db_old = old.manifest.get("intelligence", {}).get("sha256")
    db_new = new.manifest.get("intelligence", {}).get("sha256")
    tool_changes = {
        key: {"before": old.manifest.get(key), "after": new.manifest.get(key)}
        for key in ("firmwarelens", "syft", "grype", "pyelftools", "rules", "options")
        if old.manifest.get(key) != new.manifest.get(key)
    }
    # Invocation timestamps do not represent analyzer changes.
    versions_old = {s.id: s.version for s in old.stages}
    versions_new = {s.id: s.version for s in new.stages}
    tools_changed = versions_old != versions_new or bool(tool_changes)
    image_old = old.manifest.get("sandbox", {}).get("image")
    image_new = new.manifest.get("sandbox", {}).get("image")
    if image_old != image_new:
        tool_changes["sandbox_image"] = {"before": image_old, "after": image_new}
        tools_changed = True
    return {
        "artifact_hashes": {"before": old.artifact_sha256, "after": new.artifact_sha256},
        "files": {
            "added": sorted(new_files.keys() - old_files.keys()),
            "removed" if extraction_ok else "not_observed_with_incomplete_coverage": sorted(
                old_files.keys() - new_files.keys()
            ),
            "modified": modified,
        },
        "components": {
            "added": [nc[k].model_dump() for k in sorted(nc.keys() - oc.keys())],
            "removed_candidates": [oc[k].model_dump() for k in sorted(oc.keys() - nc.keys())],
            "version_changes": [
                {"name": nc[k].name, "before": oc[k].version, "after": nc[k].version}
                for k in sorted(oc.keys() & nc.keys())
                if oc[k].version != nc[k].version
            ],
        },
        "findings": {
            "new": sorted(new_findings.keys() - old_findings.keys()),
            "persistent": sorted(new_findings.keys() & old_findings.keys()),
            "no_longer_detected": no_longer,
            "unknown_due_to_coverage": unknown,
        },
        "configuration_changes": [
            {
                "path": p,
                "before": old_files[p].preview,
                "after": new_files[p].preview,
                "mode_before": oct(old_files[p].mode),
                "mode_after": oct(new_files[p].mode),
            }
            for p in modified
            if old_files[p].role in ("configuration", "startup")
        ],
        "hardening_changes": [
            {"path": p, "before": old_files[p].elf, "after": new_files[p].elf}
            for p in sorted(old_files.keys() & new_files.keys())
            if old_files[p].elf != new_files[p].elf
        ],
        "coverage": {"before": old_stages, "after": new_stages},
        "method_changes": {
            "tools_or_rules_changed": tools_changed,
            "details": tool_changes,
            "database_changed": db_old != db_new,
            "database_before": db_old,
            "database_after": db_new,
        },
        "interpretation": "Firmware bytes are unchanged; differences may come from tools, options, or intelligence."
        if old.artifact_sha256 == new.artifact_sha256
        else "Firmware bytes differ; tool and intelligence differences must also be considered.",
        "limitations": [
            "No longer detected does not mean fixed or unexploitable.",
            "Missing findings with incomplete extraction or analyzer failure are marked unknown.",
            "Component removals are candidates: inspect inventory and extraction coverage.",
        ],
    }
