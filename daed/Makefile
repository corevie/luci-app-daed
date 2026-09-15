# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=daed
PKG_VERSION:=2026.06.14
DAED_VERSION:=daed-4d6a433
WING_VERSION:=wing-dc50308
CORE_VERSION:=core-5a51cc7
WING_HASH_SHORT:=$(shell echo $(WING_VERSION) | cut -d- -f2)
CORE_HASH_SHORT:=$(shell echo $(CORE_VERSION) | cut -d- -f2)
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=4d6a43331f2f6e25961935b9e7ac09a7568bb2b4
PKG_SOURCE_URL:=https://github.com/daeuniverse/daed.git
PKG_MIRROR_HASH:=skip

# ─────────────────────────────────────────────────────────────────────────
# dae-wing / daed dashboard are NO LONGER built (this package now ships the
# standalone dae binary from the vendored dae-core source below).
#
# Lines 7-17 above are kept byte-for-byte ONLY because .github/workflows/
# autoupdate.yml rewrites them by fixed line number (it deletes and
# re-inserts one line per variable to stay balanced). PKG_SOURCE_* would
# download the old daed frontend tarball, which Build/Prepare discards.
#
# Real inputs of this package:
#   daed/dae-core/         vendored dae-2.0.0 (kix fork) source tree
#   daed/dae-kern-headers/ vendored dae_bpf_headers snapshot (eBPF headers)
# ─────────────────────────────────────────────────────────────────────────

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=dae-core/LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host bpf-headers
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/daeuniverse/dae
GO_PKG_EXCLUDES:=control/kern/tests

DAED_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(DAED_BUILD_DIR)/dae-core

GO_PKG_LDFLAGS:= \
	-s -w -buildid= \
	-linkmode external -extldflags '-static -Wl,-s'
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/cmd.Version=$(PKG_VERSION) \
	$(GO_PKG)/common/consts.MaxMatchSetLen_=1024
GO_PKG_TAGS:=trace

PGO_PROFILE:=$(CURDIR)/pprof/default.pgo

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

GO_PKG_BUILD_VARS+= \
	GOFLAGS="-trimpath -buildvcs=false -pgo=auto"

GO_PKG_TARGET_VARS+= \
	CGO_LDFLAGS="$(TARGET_LDFLAGS) -static -Wl,-s" \
	GOEXPERIMENT=newinliner,simd

define Package/daed/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  URL:=https://github.com/daeuniverse/dae
endef

define Package/daed
  $(call Package/daed/Default)
  TITLE:=A lightweight high-performance transparent proxy solution (dae)
  USERID:=dae=:dae
  DEPENDS:=$(GO_ARCH_DEPENDS) \
    +ca-bundle +kmod-sched-core +kmod-sched-bpf \
    +kmod-veth +v2ray-geoip +v2ray-geosite \
    +@KERNEL_XDP_SOCKETS \
    +DAE_USE_VMLINUX_BTF:vmlinux-btf
endef

define Package/daed/config
	choice
		prompt "BTF source for CO-RE"
		default DAE_USE_KERNEL_BTF
		depends on PACKAGE_daed

	config DAE_USE_KERNEL_BTF
		bool "Use kernel BTF (integrated)"
		depends on KERNEL_DEBUG_INFO_BTF

	config DAE_USE_VMLINUX_BTF
		bool "Use vmlinux-btf package"
	endchoice
endef

define Package/daed/description
  dae is a high-performance transparent proxy solution based on eBPF
  (kix fork with the ech-workers ECH websocket tunnel, cfMac nodes.json
  subscriptions and GitHub Gist sync built in). This package builds the
  standalone dae binary from the vendored dae-core source; the daed
  dashboard (dae-wing) is intentionally not included.
endef

define Package/daed/conffiles
/etc/dae/
/etc/config/daed
endef

DAE_CFLAGS:= \
	-O2 -Wall -Werror \
	-DMAX_MATCH_SET_LEN=1024 \
	-I$(BPF_HEADERS_DIR)/tools/lib \
	-I$(BPF_HEADERS_DIR)/arch/$(BPF_KARCH)/include/asm/mach-generic

define Build/Prepare
	( \
		rm -rf $(DAED_BUILD_DIR) ; \
		mkdir -p $(DAED_BUILD_DIR) ; \
		$(CP) $(CURDIR)/dae-core $(PKG_BUILD_DIR) ; \
		rm -rf $(PKG_BUILD_DIR)/control/kern/headers \
			$(PKG_BUILD_DIR)/trace/kern/headers ; \
		$(CP) $(CURDIR)/dae-kern-headers $(PKG_BUILD_DIR)/control/kern/headers ; \
		$(CP) $(CURDIR)/dae-kern-headers $(PKG_BUILD_DIR)/trace/kern/headers ; \
		if [ -f "$(PGO_PROFILE)" ]; then \
			$(CP) "$(PGO_PROFILE)" "$(PKG_BUILD_DIR)/default.pgo" ; \
		fi ; \
		pushd $(PKG_BUILD_DIR) ; \
			go mod tidy ; \
		popd ; \
	)
endef

define Build/Compile
	( \
		pushd $(PKG_BUILD_DIR) ; \
		export \
		$(GO_GENERAL_BUILD_CONFIG_VARS) \
		$(GO_PKG_BUILD_CONFIG_VARS) \
		$(GO_PKG_BUILD_VARS) \
		BPF_CLANG="$(CLANG)" \
		BPF_STRIP_FLAG="-strip=$(LLVM_STRIP)" \
		BPF_CFLAGS="$(DAE_CFLAGS)" \
		BPF_TARGET="bpfel,bpfeb" \
		BPF_TRACE_TARGET="$(GO_ARCH)" ; \
		go generate ./control/control.go ; \
		if ! go generate ./trace/trace.go; then \
			echo "trace generation failed; building without trace tags" ; \
		fi ; \
		popd ; \
	)
	$(call GoPackage/Build/Compile)
endef

define Package/daed/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/dae $(1)/usr/bin/dae

	$(INSTALL_DIR) $(1)/etc/dae/
	$(INSTALL_CONF) $(CURDIR)/files/config.dae $(1)/etc/dae/config.dae
	$(INSTALL_DIR) $(1)/etc/dae/config.d/
	$(INSTALL_CONF) $(CURDIR)/files/config.d/dns.dae $(1)/etc/dae/config.d/dns.dae
	$(INSTALL_CONF) $(CURDIR)/files/config.d/node.dae $(1)/etc/dae/config.d/node.dae
	$(INSTALL_CONF) $(CURDIR)/files/config.d/route.dae $(1)/etc/dae/config.d/route.dae
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/example.dae $(1)/etc/dae/example.dae
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_CONF) $(CURDIR)/files/daed.config $(1)/etc/config/daed
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(CURDIR)/files/daed.init $(1)/etc/init.d/dae
endef

$(eval $(call GoBinPackage,daed))
$(eval $(call BuildPackage,daed))
