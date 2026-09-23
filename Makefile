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
# xfrpc_loader 本地开发构建（standalone）
#
# 用途：直接在 xfrpc_loader/src 下用主机构建系统编译、验证，
#      不依赖 OpenWrt 的 $(TOPDIR)/rules.mk。
#        make          编译生成 ./xfrpc_loader
#        make clean    删除构建产物
#
# 正式打包仍以仓库顶层 xfrpc_loader/Makefile（OpenWrt）为准，
# 以及 src/openwrt-xfrpc_loader/Makefile（Git 拉取版）。

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
CPPFLAGS += -DLOCAL_SKEY
LDLIBS  += -levent -lcurl -ljson-c -lcrypto

TARGET  := xfrpc_loader
SRCS    := $(wildcard *.c)
OBJS    := $(SRCS:.c=.o)
DEPS    := $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

# 依赖文件由 -MMD 生成；若存在则纳入
-include $(DEPS)

clean:
	rm -f $(TARGET) $(OBJS) $(DEPS)