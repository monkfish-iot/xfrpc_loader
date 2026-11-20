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
#include "instance.h"

int main(int argc, char **argv)
{
	inst_t inst;

	/* 初始化：解析命令行、日志、PID 锁、libcurl/libevent、状态机、信号事件 */
	if (inst_init(&inst, argc, argv) < 0)
		return 1;

	/* 进入初始状态，启动状态机 */
	sm_transition(&inst, ST_INIT);

	/* 进入事件循环 */
	event_base_dispatch(inst.base);

	/* 清理 */
	inst_cleanup(&inst);

	return 0;
}
