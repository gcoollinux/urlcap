# 
# Copyright (C) 2006-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=urlcap
PKG_VERSION:=20141118
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)


include $(INCLUDE_DIR)/package.mk

define Package/urlcap
  SECTION:=net
  CATEGORY:=Network
  MAINTAINER:=pichina <meichonghua@gmail.com>
  TITLE:=urlcap
  URL:=http://tcpdump.org/
  DEPENDS:=+libpcap +libpthread +libcurl
endef

define Package/urlcap/description
 The urlpcap is pcap with http package.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/urlcap/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/urlcap $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/rc.d
	$(CP) files/urlcap.conf $(1)/etc/
	$(CP) files/urlcap $(1)/etc/init.d/
	$(LN) /etc/init.d/urlcap $(1)/etc/rc.d/S95urlcap
endef

$(eval $(call BuildPackage,urlcap))
