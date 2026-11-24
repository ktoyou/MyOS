#!/bin/sh
set -eu
root=$PWD
port=$root/ext/instructions/netsurf
src=$1
prefix=$2
export PATH="$prefix/bin:$PATH" PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
target_cc="gcc -m32 -ffreestanding -fno-builtin -fno-stack-protector -nostdinc -I$port/compat -I$root/user/include -I$root/user/lib"
for lib in libnslog librosprite libnsfb; do
    make -C "$src/$lib" install PREFIX="$prefix" CC="$target_cc" WARNFLAGS="-Wall -Wno-error"
done
# Генератор привязок выполняется на машине сборки.
make -C "$src/nsgenbind" install PREFIX="$prefix" CC=gcc
cat > "$prefix/lib/pkgconfig/libcurl.pc" <<EOF
Name: libcurl
Description: MyOS libcurl
Version: $(awk '/^#define LIBCURL_VERSION "/ {gsub(/"/,"",$3);print $3}' "$root/user/lib/curl/include/curl/curlver.h")
Libs: -L$root/build/curl -lcurl
Cflags: -I$root/user/lib/curl/include
EOF
make -C "$src/netsurf" -f Makefile -f "$port/link.mk" myos-link \
    TARGET=framebuffer MYOS_ROOT="$root" NS_PREFIX="$prefix" \
    NETSURF_FB_RESPATH=/ext/share/netsurf NETSURF_FB_FONTLIB=internal \
    NETSURF_USE_DUKTAPE=YES NETSURF_USE_JPEG=NO BUILD_CC="${BUILD_CC:-gcc}" \
    CC="$target_cc -include $port/compat/prelude.h"
mkdir -p "$root/build/netsurf-res"
for resource in Messages default.css internal.css quirks.css adblock.css welcome.html; do
    cp -L "$src/netsurf/frontends/framebuffer/res/$resource" "$root/build/netsurf-res/"
done
printf '%s\n' 'ca_bundle:/etc/ssl/cert.pem' 'enable_javascript:1' 'homepage_url:file:///ext/share/netsurf/welcome.html' > "$root/build/netsurf-res/Choices"
install -Dm755 "$root/build/user/netsurf" "$root/build/netsurf-dist/ext/bin/netsurf"
install -Dm644 "$port/netsurf.desktop" "$root/build/netsurf-dist/usr/share/applications/netsurf.desktop"
mkdir -p "$root/build/netsurf-dist/ext/share/netsurf"
cp "$root"/build/netsurf-res/* "$root/build/netsurf-dist/ext/share/netsurf/"
tar --format=ustar --owner=0 --group=0 -czf "$root/build/netsurf.tar.gz" \
    -C "$root/build/netsurf-dist" ext/bin/netsurf ext/share/netsurf usr/share/applications/netsurf.desktop
