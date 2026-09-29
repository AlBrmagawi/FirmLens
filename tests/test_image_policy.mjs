import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  disposition,
  verifyAnalyzerScope,
  verifyBackport,
} from "../scripts/image_policy.mjs";

const match = (id, name = "zlib", version = "1.3.2-r0", severity = "High") => ({
  vulnerability: { id, severity },
  artifact: {
    name,
    version,
    type: name === "zlib" ? "apk" : "go-module",
    locations: [
      {
        path:
          name === "zlib" ? "/lib/apk/db/installed" : "/usr/local/bin/grype",
      },
    ],
    metadata: { goCompiledVersion: "go1.26.8" },
  },
});
test("security gate fails closed for unknown advisories, missing proof and changed packages", () => {
  for (const item of [
    match("CVE-2026-85091"),
    match("NEW-ADVISORY"),
    match("NEW-ADVISORY", "zlib", "1.3.2-r0", "Critical"),
    match("NEW-ADVISORY", "other", "1", "Unknown"),
  ])
    assert.equal(disposition(item, {}).status, "blocked");
  assert.equal(
    disposition(match("CVE-2026-85091", "zlib", "1.3.3-r0"), {
      zlib_backport_verified: true,
    }).status,
    "blocked",
  );
  assert.equal(
    disposition(match("CVE-2026-85091", "unrelated"), {
      zlib_backport_verified: true,
    }).status,
    "blocked",
  );
  const misplaced = match("CVE-2026-85091");
  misplaced.artifact.locations = [{ path: "/opt/other/library" }];
  assert.equal(
    disposition(misplaced, { zlib_backport_verified: true }).status,
    "blocked",
  );
});
test("backport requires the tested source and exact installed bytes", () => {
  const patch = Buffer.from("trusted upstream patch"),
    regression = Buffer.from("bounded regression");
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  const hashes = {
    "/usr/lib/libz.so.1.3.2": hash("library"),
    "/opt/zlib-backport/CVE-2026-85091.patch": hash(patch),
    "/opt/zlib-backport/regression.c": hash(regression),
    "/usr/local/share/firmwarelens/backports/zlib-regression":
      hash("test binary"),
  };
  const receipt =
    "CVE-2026-85091 upstream patch df84af25dc1942490e1d1c899a07619152a46148\nnegative-control=86 patched-regression=0 dynamic-regression=0 upstream-make-check=passed\n" +
    Object.entries(hashes)
      .map(([path, digest]) => `${digest}  ${path}`)
      .join("\n");
  assert(verifyBackport(receipt, hashes, patch, regression));
  assert(
    !verifyBackport(
      receipt,
      { ...hashes, "/usr/lib/libz.so.1.3.2": hash("unpatched") },
      patch,
      regression,
    ),
  );
  assert(
    !verifyBackport(receipt, hashes, Buffer.from("changed patch"), regression),
  );
  assert(
    !verifyBackport(
      receipt.replace("patched-regression=0", "patched-regression=1"),
      hashes,
      patch,
      regression,
    ),
  );
  assert.equal(
    disposition(match("CVE-2026-85091"), { zlib_backport_verified: true })
      .status,
    "fixed_by_backport",
  );
});
test("Docker advisory requires evidence that no affected server code was compiled", () => {
  const client =
    "github.com/anchore/grype/cmd/grype\ngithub.com/docker/docker/client\n";
  const build =
    "go1.26.8\npath github.com/anchore/grype/cmd/grype\ndep github.com/docker/docker v28.5.2+incompatible\n";
  assert(verifyAnalyzerScope(client, build));
  for (const server of [
    "github.com/docker/docker/api/server/middleware",
    "github.com/docker/docker/pkg/authorization",
    "github.com/moby/moby/v2/daemon",
  ])
    assert(!verifyAnalyzerScope(client + server, build));
  assert(!verifyAnalyzerScope("", build));
  assert(!verifyAnalyzerScope(client, build.replace("go1.26.8", "go1.26.3")));
  const item = match(
    "GO-2026-4887",
    "github.com/docker/docker",
    "v28.5.2+incompatible",
  );
  assert.equal(disposition(item, {}).status, "blocked");
  assert.equal(
    disposition(item, { grype_client_only_verified: true }).status,
    "not_affected",
  );
  item.artifact.locations.push({ path: "/usr/local/bin/unverified-tool" });
  assert.equal(
    disposition(item, { grype_client_only_verified: true }).status,
    "blocked",
  );
});
