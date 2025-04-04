// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <event-parse.h>
#include <trace-seq.h>

#include "utils.h"

void print_le_hex(struct trace_seq *s, const uint8_t *buf, int index)
{
	trace_seq_printf(s, "%02x%02x%02x%02x",
			 buf[index + 3], buf[index + 2],
			 buf[index + 1], buf[index]);
}

void display_raw_data(struct trace_seq *s, const uint8_t *buf, uint32_t datalen)
{
	int i = 0, line_count = 0;

	trace_seq_printf(s, "  %08x: ", i);
	while (datalen >= 4) {
		print_le_hex(s, buf, i);
		i += 4;
		datalen -= 4;
		if (++line_count == 4) {
			trace_seq_printf(s, "\n  %08x: ", i);
			line_count = 0;
		} else {
			trace_seq_printf(s, " ");
		}
	}
}