NS_RELEASE := netsurf-all-3.11
NS_ARCHIVE := $(BUILD)/$(NS_RELEASE).tar.gz
NS_ROOT := $(BUILD)/netsurf-src/$(NS_RELEASE)/libnsfb
NS_PORT := ext/instructions/netsurf
NS_FLAGS := $(UCFLAGS) -I$(NS_ROOT)/include -I$(NS_ROOT)/src -I$(NS_PORT)/compat
NS_SOURCES := libnsfb cursor palette surface/surface surface/ram plot/api plot/util plot/generic plot/32bpp-xrgb8888 plot/32bpp-xbgr8888 plot/16bpp plot/8bpp
NS_OBJECTS := $(addprefix $(BUILD)/netsurf-obj/,$(addsuffix .o,$(NS_SOURCES)))

$(NS_ARCHIVE): | $(BUILD)
	curl -fL https://deb.debian.org/debian/pool/main/n/netsurf/netsurf_3.11.orig.tar.gz -o $@.tmp
	mv $@.tmp $@

$(BUILD)/netsurf-src/.unpacked: $(NS_ARCHIVE)
	echo "4dea880ff3c2f698bfd62c982b259340f9abcd7f67e6c8eb2b32c61f71644b7b  $<" | sha256sum -c -
	mkdir -p $(BUILD)/netsurf-src
	tar -xzf $< -C $(BUILD)/netsurf-src
	touch $@

$(BUILD)/netsurf-obj/%.o: $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/cross.mk $(NS_PORT)/compat/endian.h
	mkdir -p $(@D)
	$(CC) $(NS_FLAGS) -c $(NS_ROOT)/src/$*.c -o $@

$(BUILD)/netsurf-obj/myos-surface.o: $(NS_PORT)/myos-surface.c $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/compat/endian.h user/lib/win.h
	mkdir -p $(@D)
	$(CC) $(NS_FLAGS) -c $< -o $@

.PHONY: netsurf-surface
netsurf-surface: $(BUILD)/user/netsurf-surface-check

$(BUILD)/user/netsurf-surface-check: tests/netsurf_surface_check.c $(BUILD)/libnsfb-myos.a $(ULIB) user/user.ld
	$(CC) $(NS_FLAGS) -c $< -o $(BUILD)/netsurf-obj/check.o
	$(LD) $(ULDFLAGS) $(BUILD)/netsurf-obj/check.o $(BUILD)/libnsfb-myos.a $(ULIB) -o $@

$(BUILD)/libnsfb-myos.a: $(NS_OBJECTS) $(BUILD)/netsurf-obj/myos-surface.o
	$(AR) rcs $@ $^

.PHONY: netsurf-libs netsurf-surface-smoke
netsurf-libs: $(BUILD)/netsurf-src/.dom-patched
	set -e; src="$(abspath $(NS_ROOT)/..)"; prefix="$(abspath $(BUILD))/netsurf-sdk"; \
	export PKG_CONFIG_LIBDIR="$$prefix/lib/pkgconfig"; \
	for component in buildsystem libwapcaplet libparserutils libcss libhubbub libdom libnsbmp libnsgif libnsutils libutf8proc libnspsl libsvgtiny; do \
		$(MAKE) -C "$$src/$$component" install PREFIX="$$prefix" \
			CC="$(CC) -m32 -ffreestanding -fno-builtin -nostdinc -I$(abspath $(NS_PORT))/compat -I$(abspath user/include) -I$(abspath user/lib)" \
			WARNFLAGS='-Wall -Wno-error'; \
	done

$(BUILD)/netsurf-src/.dom-patched: $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/dom-open.patch
	patch --forward -d $(NS_ROOT)/.. -p1 < $(NS_PORT)/dom-open.patch
	touch $@

netsurf-surface-smoke: netsurf-surface $(HWBUILD)/kernel.bin $(BUILD)/myfs $(BUILD)/ld.so $(BUILD)/user/libc.so $(BUILD)/user/libgfx.so $(addprefix $(BUILD)/user/,sh desktop sleep)
	python3 tests/netsurf_surface_smoke.py

.PHONY: netsurf-browser
ifeq ($(WITH_NETSURF),1)
install: netsurf-browser
endif
.PHONY: netsurf-browser-smoke
netsurf-browser-smoke: netsurf-browser $(BUILD)/os.img $(BUILD)/myfs $(BUILD)/ld.so $(BUILD)/user/libc.so $(BUILD)/user/libgfx.so $(addprefix $(BUILD)/user/,sh desktop sleep tar ext)
	python3 tests/netsurf_browser_smoke.py

netsurf-browser: netsurf-libs $(BUILD)/netsurf-src/.browser-patched $(BUILD)/netsurf-src/.raster-patched $(BUILD)/netsurf-src/.https-patched $(BUILD)/netsurf-src/.schedule-patched $(BUILD)/libnsfb-myos.a $(ULIB) $(BUILD)/user/libcurl.so $(MLIBS)
	+sh $(NS_PORT)/build-browser.sh "$(abspath $(NS_ROOT)/..)" "$(abspath $(BUILD))/netsurf-sdk"

$(BUILD)/netsurf-src/.browser-patched: $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/browser.patch
	patch -d $(NS_ROOT)/../netsurf -p1 < $(NS_PORT)/browser.patch
	touch $@

$(BUILD)/netsurf-src/.raster-patched: $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/raster.patch
	patch -d $(NS_ROOT)/../netsurf -p1 < $(NS_PORT)/raster.patch
	touch $@

$(BUILD)/netsurf-src/.https-patched: $(NS_PORT)/https.patch | $(BUILD)/netsurf-src/.browser-patched
	patch -d $(NS_ROOT)/../netsurf -p1 < $(NS_PORT)/https.patch
	touch $@

$(BUILD)/netsurf-src/.schedule-patched: $(BUILD)/netsurf-src/.unpacked $(NS_PORT)/schedule.patch
	patch -d $(NS_ROOT)/../netsurf -p1 < $(NS_PORT)/schedule.patch
	touch $@
