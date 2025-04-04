/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __TRIGGER_H__
#define __TRIGGER_H__

#include <stdint.h>

struct trace_seq;

void print_le_hex(struct trace_seq *s, const uint8_t *buf, int index);
void display_raw_data(struct trace_seq *s, const uint8_t *buf, uint32_t datalen);

#endif
