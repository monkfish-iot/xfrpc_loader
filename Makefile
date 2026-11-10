#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Monkfish
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xfrpc_loader
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

LOCAL_SKEY=1（默认）：从本地文件读取密钥，不依赖 libskey
#LOCAL_SKEY=0：使用 libskey 静态库
# LOCAL_SKEY ?= 1

# INSTALL_PASSWD_SH=1（默认）：安装 show_luci_passwd.sh（解密显示 LuCI 明文密码）
INSTALL_PASSWD_SH=0：不安装
#INSTALL_PASSWD_SH ?= 1

ifeq ($(LOCAL_SKEY),1)
    # skey_gen.sh 运行时调用 openssl 命令行（由 openssl-util 提供，
    # libopenssl 仅含共享库）；缺失时脚本以 127 退出
    SKEY_PKG_DEPS:=+openssl-util
    SKEY_LINK_LIBS:=-lcrypto
else
    SKEY_PKG_DEPS:=+skey
    SKEY_LINK_LIBS:=-lskey -lcrypto
endif

include $(INCLUDE_DIR)/package.mk

define Package/xfrpc_loader
  SECTION:=Monkfish
  CATEGORY:=Monkfish Softwares
  DEPENDS:=+libevent2 +libcurl +libjson-c $(SKEY_PKG_DEPS) +libopenssl
  TITLE:=xfrpc loader daemon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += -Wall -Wextra
ifeq ($(LOCAL_SKEY),1)
    TARGET_CFLAGS += -DLOCAL_SKEY
endif

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/xfrpc_loader \
		$(PKG_BUILD_DIR)/*.c \
		-levent -lcurl -ljson-c $(SKEY_LINK_LIBS)
endef

define Package/xfrpc_loader/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xfrpc_loader $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xfrpc_loader.init $(1)/etc/init.d/xfrpc_loader
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/xfrpc_loader.uci $(1)/etc/config/xfrpc_loader
ifeq ($(LOCAL_SKEY),1)
	# 开源本地模式：密钥由 xfrpc_loader 进程内 libcrypto 首次启动时生成
	# （/etc/config/skey/），不安装任何脚本，也不依赖 openssl 命令行
else
	# libskey 模式：sysupgrade 时保留 /etc/skey（产线烧录的设备证书链）
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/xfrpc-loader-skey \
		$(1)/etc/uci-defaults/80-xfrpc-loader-skey
endif
ifeq ($(INSTALL_PASSWD_SH),1)
	$(INSTALL_BIN) ./files/show_luci_passwd.sh $(1)/usr/bin/show_luci_passwd.sh
endif
	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_DATA) ./files/etc/nginx/conf.d/ubus.conf $(1)/etc/nginx/conf.d/ubus.conf
endef

$(eval $(call BuildPackage,xfrpc_loader))
