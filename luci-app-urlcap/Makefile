include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-urlcap
PKG_VERSION=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-urlcap
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=urlcap Client for LuCI
	PKGARCH:=all
endef

define Package/luci-app-urlcap/description
	This package contains LuCI configuration pages for urlcap.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-urlcap/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	
	$(INSTALL_DATA) ./files/etc/config/urlcap $(1)/etc/config/urlcap
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/urlcap.lua $(1)/usr/lib/lua/luci/controller/urlcap.lua
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/cbi/urlcap.lua $(1)/usr/lib/lua/luci/model/cbi/urlcap.lua
endef

$(eval $(call BuildPackage,luci-app-urlcap))
