#!/bin/sh
set -eu
build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT
cd "$build_root"
wget -q https://zlib.net/fossils/zlib-1.3.2.tar.gz -O source.tar.gz
echo 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16  source.tar.gz' | sha256sum -c -
tar xzf source.tar.gz
cd zlib-1.3.2
./configure --prefix=/usr --shared --disable-crcvx
make -s -j2
cc -I. /opt/zlib-backport/regression.c ./libz.a -o negative-control
set +e
./negative-control
original_status=$?
set -e
test "$original_status" -eq 86
patch -p1 < /opt/zlib-backport/CVE-2026-85091.patch
make -s -j2
make -s check
cc -I. /opt/zlib-backport/regression.c ./libz.a -o patched-regression
./patched-regression
# Replace the shared library only. Retain distribution package metadata, so the
# scanner's original match remains available alongside the backport evidence.
install -m 755 libz.so.1.3.2 /usr/lib/libz.so.1.3.2
mkdir -p /usr/local/share/firmwarelens/backports
cc -I. /opt/zlib-backport/regression.c -L/usr/lib -Wl,-rpath,/usr/lib -l:libz.so.1 -o /usr/local/share/firmwarelens/backports/zlib-regression
/usr/local/share/firmwarelens/backports/zlib-regression
receipt=/usr/local/share/firmwarelens/backports/zlib.txt
{
    echo 'CVE-2026-85091 upstream patch df84af25dc1942490e1d1c899a07619152a46148'
    echo 'zlib 1.3.2; distribution package version retained'
    echo 'negative-control=86 patched-regression=0 dynamic-regression=0 upstream-make-check=passed'
    sha256sum /usr/lib/libz.so.1.3.2 /opt/zlib-backport/CVE-2026-85091.patch /opt/zlib-backport/regression.c /usr/local/share/firmwarelens/backports/zlib-regression
} > "$receipt"
cat "$receipt"
