# zlib security backport

FirmwareLens builds zlib 1.3.2 with the upstream fix for [CVE-2026-85091](https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148). At preparation time the Alpine 3.23/3.24 packages still shipped the affected `1.3.2-r0` library. The modified library is a FirmwareLens backport, not an unchanged Alpine package or a new upstream release.

`build.sh` verifies the upstream source archive SHA-256, applies the included upstream patch, and runs the original zlib tests. The bounded local regression fills a non-blocking pipe and checks that a stalled gzip writer relinquishes its caller's buffer. The unpatched library must return the dedicated failure code 86. The patched static and installed shared libraries must pass. The negative control exits before using the unsafe state.

The build retains distribution package metadata and records the installed library, patch, regression source and test-binary hashes under `/usr/local/share/firmwarelens/backports/`. Consequently a package-only scanner may still report this CVE. The image gate retains that raw match, verifies the receipt against checked-in source and installed bytes, reruns the shared-library regression inside the image, and records `fixed_by_backport` only when every check passes. Changed versions and unrelated advisories do not inherit this disposition.

Remove this backport when supported Alpine packages include the fix, rebuild all runtime images, rerun the image gate and firmware/restore tests, and remove the corresponding policy branch. The [upstream license](LICENSE) applies to zlib and its patch. The regression and build wrapper are FirmwareLens project code.
