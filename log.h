/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Monkfish
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef XFRPC_LOADER_LOG_H
#define XFRPC_LOADER_LOG_H

#include <syslog.h>

#define LOG_TAG "xfrpc_loader"

#define log_err(fmt, ...)   syslog(LOG_ERR,     LOG_TAG " ERROR: " fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  syslog(LOG_WARNING, LOG_TAG " WARN:  " fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  syslog(LOG_INFO,    LOG_TAG " INFO:  " fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) syslog(LOG_DEBUG,   LOG_TAG " DEBUG: " fmt, ##__VA_ARGS__)

static inline void log_init(int foreground)
{
	openlog(LOG_TAG, LOG_PID | (foreground ? LOG_PERROR : 0), LOG_DAEMON);
}

#endif /* XFRPC_LOADER_LOG_H */
