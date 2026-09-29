# Supported inputs and tested coverage

This release supports a bounded set of Linux firmware containers. It does not provide universal firmware support. The primary runtime is Linux Docker with cgroup v2; validation used Windows Docker Desktop's WSL2 Linux engine on x86-64. Analyzer builds use pinned source archives and the target architecture's Go compiler. ARM64 builds and hardware execution remain unverified.

| Input | Implementation | Real pipeline validation |
|---|---|---|
| Raw SquashFS | v4 little-endian superblock, `unsquashfs` 4.7.4 | Synthetic gzip, xz and zstd images passed |
| Embedded SquashFS | Validated superblock/bytes-used, bounded discovery | Synthetic payload at offset 4096 passed |
| Tar root filesystem | Header/checksum signature, regular-file extraction and original metadata | USTAR fixture passed |
| Gzip tar root filesystem | Bounded decompression followed by tar validation | Deterministic fixture passed |
| ZIP firmware bundle | Supported payload discovery, Store/Deflate support, bounded nesting/expansion | Deflate bundle containing raw SquashFS passed |
| Gzip raw filesystem | Prepare/decompress externally using pinned integration recipe | Not accepted as gzip tar |
| Other/encrypted/damaged filesystems | Explicit unsupported/failure or partial result | Adversarial unit cases and unsupported signature tests |

Other unsquashfs-supported compressors (lzo/lz4) and alternative SquashFS variants have not been tested. Legacy/big-endian SquashFS, UBIFS, JFFS2, cramfs, ext4 images, UBI layout discovery, encrypted firmware and execution/emulation are outside this release. The OpenWrt integration recipe is pinned in `scripts/openwrt_integration.py`; its measured status belongs in [VALIDATION.md](VALIDATION.md), not an assumption of universal device support.

ELF metadata tests cover 32-bit ARM little-endian, 64-bit AArch64 little-endian, MIPS little- and big-endian, x86 and x86-64, plus malformed input. These architecture cases use minimal generated ELF headers; full hardening behavior is additionally tested using real compiled x86-64 fixtures. Other architectures and complete vendor-specific ELF variants are unverified. No target firmware binary is executed.

Coverage states are explicit per stage: success, failure, skipped, unsupported, partial. Scan outcomes are complete, partial, failed, cancelled or unsupported. Link/special-file metadata is retained without dereference; this omission is diagnostic and makes extraction conservative. File/size/depth/time/output limits may yield partial results. Inventory does not provide a guessed completeness percentage. Package-free firmware may legitimately produce little component data.
