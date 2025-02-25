/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025, Rivos Inc. All rights reserved.
 */

#ifndef __RAS_RISCV_HANDLER_H
#define __RAS_RISCV_HANDLER_H

#include <traceevent/event-parse.h>

#include "ras-events.h"

int ras_riscv_event_handler(struct trace_seq *s,
			    struct tep_record *record,
			    struct tep_event *event, void *context);

#endif
