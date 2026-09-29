import { createHash } from "node:crypto";

export function verifyBackport(receipt, hashes, patch, regression) {
  const digest = (content) =>
    createHash("sha256").update(content).digest("hex");
  const entries = Object.fromEntries(
    [...receipt.matchAll(/^([a-f0-9]{64})  (\S+)$/gm)].map((match) => [
      match[2],
      match[1],
    ]),
  );
  return (
    receipt.includes(
      "CVE-2026-85091 upstream patch df84af25dc1942490e1d1c899a07619152a46148",
    ) &&
    receipt.includes(
      "negative-control=86 patched-regression=0 dynamic-regression=0 upstream-make-check=passed",
    ) &&
    entries["/opt/zlib-backport/CVE-2026-85091.patch"] === digest(patch) &&
    entries["/opt/zlib-backport/regression.c"] === digest(regression) &&
    Object.entries(entries).length === 4 &&
    Object.entries(entries).every(([path, hash]) => hashes[path] === hash)
  );
}

export function verifyAnalyzerScope(packages, build) {
  const list = packages.trim().split(/\s+/);
  return (
    list.includes("github.com/anchore/grype/cmd/grype") &&
    list.some((name) => name.startsWith("github.com/docker/docker/")) &&
    !list.some((name) =>
      /github\.com\/(docker\/docker|moby\/moby)(\/v2)?\/(daemon|api\/server|pkg\/authorization)(\/|$)/.test(
        name,
      ),
    ) &&
    /\bgo1\.26\.8\b/.test(build) &&
    build.includes("github.com/anchore/grype/cmd/grype") &&
    build.includes("v28.5.2+incompatible")
  );
}

export function disposition(match, evidence) {
  const { vulnerability, artifact } = match;
  if (
    vulnerability.id === "CVE-2026-85091" &&
    artifact.name === "zlib" &&
    artifact.version === "1.3.2-r0" &&
    artifact.type === "apk" &&
    artifact.locations?.length > 0 &&
    artifact.locations.every(
      (location) => location.path === "/lib/apk/db/installed",
    ) &&
    evidence.zlib_backport_verified
  ) {
    return {
      status: "fixed_by_backport",
      reason:
        "Upstream fix applied; negative control, patched regression, upstream tests and installed-library hash verified",
      source:
        "https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148",
    };
  }
  if (
    vulnerability.id === "GO-2026-4887" &&
    artifact.name === "github.com/docker/docker" &&
    artifact.version === "v28.5.2+incompatible" &&
    artifact.type === "go-module" &&
    artifact.metadata?.goCompiledVersion === "go1.26.8" &&
    artifact.locations?.length > 0 &&
    artifact.locations.every(
      (location) => location.path === "/usr/local/bin/grype",
    ) &&
    evidence.grype_client_only_verified
  ) {
    return {
      status: "not_affected",
      reason:
        "Docker daemon AuthZ middleware is absent from Grype's compiled package graph; the client library does not implement the affected server",
      source:
        "https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2",
    };
  }
  return {
    status: ["Critical", "High", "Unknown"].includes(vulnerability.severity)
      ? "blocked"
      : "review",
    reason: "No verified disposition applies",
  };
}
