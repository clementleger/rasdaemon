// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <traceevent/kbuffer.h>
#include <unistd.h>

#include "ras-riscv-handler.h"
#include "ras-cpu-isolation.h"
#include "ras-logger.h"
#include "ras-report.h"
#include "types.h"
#include "utils.h"

#define CPER_RISCV_RERI_BANK_INFO_INSTID	GENMASK_ULL(15, 0)
#define CPER_RISCV_RERI_BANK_INFO_N_ERR_RECS	GENMASK_ULL(21, 16)
#define CPER_RISCV_RERI_BANK_INFO_LAYOUT	GENMASK_ULL(23, 22)
#define CPER_RISCV_RERI_BANK_VERSION		GENMASK_ULL(63, 56)
#define CPER_RISCV_RERI_VENDOR_VENDOR_ID	GENMASK_ULL(31, 0)
#define CPER_RISCV_RERI_VENDOR_IMP_ID		GENMASK_ULL(47, 32)

#define CPER_RISCV_ERROR_RECORD_STATUS_V	BIT(0)
#define CPER_RISCV_ERROR_RECORD_STATUS_CE	BIT(1)
#define CPER_RISCV_ERROR_RECORD_STATUS_UED	BIT(2)
#define CPER_RISCV_ERROR_RECORD_STATUS_UEC	BIT(3)
#define CPER_RISCV_ERROR_RECORD_STATUS_PRI	GENMASK_ULL(5, 4)
#define CPER_RISCV_ERROR_RECORD_STATUS_MO	BIT(6)
#define CPER_RISCV_ERROR_RECORD_STATUS_C	BIT(7)
#define CPER_RISCV_ERROR_RECORD_STATUS_TT	GENMASK_ULL(10,8)
#define CPER_RISCV_ERROR_RECORD_STATUS_IV	BIT(11)
#define CPER_RISCV_ERROR_RECORD_STATUS_AIT	GENMASK_ULL(15, 12)
#define CPER_RISCV_ERROR_RECORD_STATUS_SIV	BIT(16)
#define CPER_RISCV_ERROR_RECORD_STATUS_TSV	BIT(17)
#define CPER_RISCV_ERROR_RECORD_STATUS_SCRUB	BIT(20)
#define CPER_RISCV_ERROR_RECORD_STATUS_CECO	BIT(21)
#define CPER_RISCV_ERROR_RECORD_STATUS_RDIP	BIT(23)
#define CPER_RISCV_ERROR_RECORD_STATUS_EC	GENMASK_ULL(31, 24)
#define CPER_RISCV_ERROR_RECORD_STATUS_CEC	GENMASK_ULL(63, 48)

struct cper_riscv_error_header {
	uint64_t vendor_n_imp_id;
	uint64_t bank_info;
	uint64_t valid_summary;
	uint64_t reserved[4];
	uint64_t custom;
};

struct cper_riscv_error_record {
	uint64_t control;
	uint64_t status;
	uint64_t addr_info;
	uint64_t info;
	uint64_t suppl_info;
	uint64_t timestamp;
	uint64_t reserved[2];
};

static const char * const reri_status_ec_str[] = {
	"None",
	"Other unspecified error",
	"Corrupted data access",
	"Cache block data error",
	"Cache scrubbing detected",
	"Cache address/state error",
	"Cache unspecified error",
	"Snoop/directory state error",
	"Snoop unspecified error",
	"TLB/Page-walk data",
	"TLB/Page-walk addr ctrl",
	"TLB/Page-walk unknown",
	"Hart state error",
	"Interrupt controller state",
	"Interconnect data error",
	"Interconnect other error",
	"Internal watchdog error",
	"Internal datapath/execution unit error",
	"System memory bus error",
	"System memory unspecified error",
	"System memory data error",
	"System memory scrub detected",
	"Illegal IO protocol error",
	"Protocol unexpected state",
	"Protocol timeout",
	"System internal controller",
	"Deferred error passthrough",
	"PCI/CXL error",
};

static const char *const reri_status_tt_str[] = {
	"Unspecified",
	"Custom",
	"Reserved 1",
	"Reserved 2",
	"Explicit Read",
	"Explicit Write",
	"Implicit Read",
	"Implicit Write",
};

static bool instance_id_is_cpu(uint16_t instance_id)
{
	return true;
}

static int parse_riscv_processor_err_hdr(struct trace_seq *s,
					 struct tep_record *record,
					 struct tep_event *event,
					 struct ras_riscv_event *ev)
{
	struct cper_riscv_error_header *err_hdr;
	uint64_t info;
	int len;

	ev->err_hdr = tep_get_field_raw(s, event, "err_hdr", record, &len, 1);
	if (!ev->err_hdr)
		return -1;

	display_raw_data(s, ev->err_hdr, ev->err_hdr_len);

	if (len != ev->err_hdr_len) {
		log(TERM, LOG_ERR,
			"Size of error header does not match size of the buffer\n");
		return -1;
	}

	if (ev->err_hdr_len != sizeof(struct cper_riscv_error_header)) {
		log(TERM, LOG_ERR,
			"Size of error header does not match the RISCV Processor Error Header Structure\n");
		return -1;
	}

	err_hdr = (struct cper_riscv_error_header *)ev->err_hdr;
	trace_seq_printf(s, "RISC-V processor error header:\n");
	info = FIELD_GET(CPER_RISCV_RERI_VENDOR_VENDOR_ID, err_hdr->vendor_n_imp_id);
	trace_seq_printf(s, "  Vendor ID: 0x%lx\n", info);
	info = FIELD_GET(CPER_RISCV_RERI_VENDOR_IMP_ID, err_hdr->vendor_n_imp_id);
	trace_seq_printf(s, "  Implementation ID: 0x%lx\n", info);
	info = FIELD_GET(CPER_RISCV_RERI_BANK_INFO_INSTID, err_hdr->bank_info);
	trace_seq_printf(s, "  Instance ID: 0x%lx\n", info);
	if (instance_id_is_cpu(info))
		ev->is_cpu_error = true;
	info = FIELD_GET(CPER_RISCV_RERI_BANK_INFO_LAYOUT, err_hdr->bank_info);
	trace_seq_printf(s, "  Layout: %ld\n", info);

	trace_seq_printf(s, "  Valid Summary: 0x%lx\n", err_hdr->valid_summary);
	trace_seq_printf(s, "  Custom: 0x%lx\n", err_hdr->custom);

	return 0;
}

static const char *riscv_get_tt_str(uint8_t tt)
{
	if (tt > ARRAY_SIZE(reri_status_tt_str))
		return "Unkown transaction type";

	return reri_status_tt_str[tt];
}

static const char *riscv_get_ec_str(uint8_t ec)
{
	if (ec > ARRAY_SIZE(reri_status_ec_str))
		return "Unkown error";

	return reri_status_ec_str[ec];
}

static int parse_riscv_processor_err_record(struct trace_seq *s,
					    struct tep_record *record,
					    struct tep_event *event,
					    struct ras_riscv_event *ev)
{
	struct cper_riscv_error_record *err_info;
	int err_count = ev->err_len / sizeof(struct cper_riscv_error_record);
	int len;
	int i;

	ev->err = tep_get_field_raw(s, event, "err", record, &len, 1);
	if (!ev->err)
		return -1;

	display_raw_data(s, ev->err, ev->err_len);

	if (len != ev->err_len) {
		log(TERM, LOG_ERR,
			"Size of error records does not match size of the buffer\n");
		ev->err = NULL;
		return -1;
	}

	if (ev->err_len % sizeof(struct cper_riscv_error_record)) {
		log(TERM, LOG_ERR,
			"Size of error records does not match the RISCV Processor Record Structure\n");
		return -1;
	}

	err_info = (struct cper_riscv_error_record *)ev->err;
	trace_seq_printf(s, "RISC-V processor error records:\n");
	for (i = 0; i < err_count; i++) {
		uint32_t val;
		const char *str;
		trace_seq_printf(s, "Error record %d:\n", i);
		trace_seq_printf(s, "  Status      : 0x%016lx\n", err_info->status);

		val = FIELD_GET(CPER_RISCV_ERROR_RECORD_STATUS_EC, err_info->status);
		str = riscv_get_ec_str(val);
		trace_seq_printf(s, "    ErrorCode : 0x%02x (%s)\n", val, str);

		val = FIELD_GET(CPER_RISCV_ERROR_RECORD_STATUS_TT, err_info->status);
		str = riscv_get_tt_str(val);
		trace_seq_printf(s, "    TxnType   : 0x%x (%s)\n", val, str);
		val = FIELD_GET(CPER_RISCV_ERROR_RECORD_STATUS_CEC, err_info->status);
		trace_seq_printf(s, "    ErrorCount   : 0x%x\n", val);
		ev->error_count += val;

		trace_seq_printf(s, "  Control     : 0x%016lx\n", err_info->control);
		trace_seq_printf(s, "  Addr        : 0x%016lx\n", err_info->addr_info);
		trace_seq_printf(s, "  Info        : 0x%016lx\n", err_info->info);
		trace_seq_printf(s, "  SupplInfo   : 0x%016lx\n", err_info->suppl_info);
		trace_seq_printf(s, "  Timestamp   : %ld\n", err_info->timestamp);

		err_info++;
	}

	return 0;
}

#ifdef HAVE_CPU_FAULT_ISOLATION

static int ras_handle_cpu_error(struct trace_seq *s, struct tep_record *record,
				struct tep_event *event,
				struct ras_riscv_event *ev, time_t now)
{
	unsigned long long val;
	int cpu;
	char *severity;
	struct error_info err_info;

	if (tep_get_field_val(s, event, "cpu", record, &val, 1) < 0)
		return -1;
	cpu = val;
	trace_seq_printf(s, "\n  cpu: %d\n", cpu);

	/* record cpu error */
	if (tep_get_field_val(s, event, "severity", record, &val, 1) < 0)
		return -1;
	/* refer to UEFI_2_9 specification chapter N2.2 Table N-5 */
	switch (val) {
	case GHES_SEV_NO:
		severity = "Informational";
		break;
	case GHES_SEV_CORRECTED:
		severity = "Corrected";
		break;
	case GHES_SEV_RECOVERABLE:
		severity = "Recoverable";
		break;
	default:
	case GHES_SEV_PANIC:
		severity = "Fatal";
	}
	trace_seq_printf(s, "  severity: %s\n", severity);

	if ((val == GHES_SEV_CORRECTED || val == GHES_SEV_RECOVERABLE) &&
	    ev->is_cpu_error) {
		err_info.nums = ev->error_count;
		err_info.time = now;
		err_info.err_type = val;
		ras_record_cpu_error(&err_info, cpu);
	}

	return 0;
}
#endif

int ras_riscv_event_handler(struct trace_seq *s,
			    struct tep_record *record,
			    struct tep_event *event, void *context)
{
	unsigned long long val;
	struct ras_events *ras = context;
	time_t now;
	struct tm *tm;
	struct ras_riscv_event ev = {0};

	/*
	 * Newer kernels (3.10-rc1 or upper) provide an uptime clock.
	 * On previous kernels, the way to properly generate an event would
	 * be to inject a fake one, measure its timestamp and diff it against
	 * gettimeofday. We won't do it here. Instead, let's use uptime,
	 * falling-back to the event report's time, if "uptime" clock is
	 * not available (legacy kernels).
	 */

	if (ras->use_uptime)
		now = record->ts / user_hz + ras->uptime_diff;
	else
		now = time(NULL);

	tm = localtime(&now);
	if (tm)
		strftime(ev.timestamp, sizeof(ev.timestamp),
			 "%Y-%m-%d %H:%M:%S %z", tm);
	trace_seq_printf(s, "%s", ev.timestamp);

	if (tep_get_field_val(s, event, "cpu_version", record, &val, 1) < 0)
		return -1;
	ev.cpu_version = val;
	trace_seq_printf(s, " cpu_version: 0x%lx", ev.cpu_version);

	if (tep_get_field_val(s, event, "cpu_vendor", record, &val, 1) < 0)
		return -1;
	ev.cpu_vendor = val;
	trace_seq_printf(s, " cpu_vendor: 0x%lx", ev.cpu_vendor);

	if (tep_get_field_val(s, event, "cpu_architecture", record, &val, 1) < 0)
		return -1;
	ev.cpu_architecture = val;
	trace_seq_printf(s, " cpu_architecture: 0x%lx", ev.cpu_architecture);

	if (tep_get_field_val(s, event, "hart_id", record, &val, 1) < 0)
		return -1;
	ev.hart_id = val;
	trace_seq_printf(s, " hart_id: 0x%lx", ev.hart_id);

	if (tep_get_field_val(s, event, "err_hdr_len", record, &val, 1) < 0)
		return -1;
	ev.err_hdr_len = val;
	trace_seq_printf(s, "Riscv Processor Err Header data len: %d\n",
			 ev.err_hdr_len);

	if (ev.err_hdr_len)
		parse_riscv_processor_err_hdr(s, record, event, &ev);

	if (tep_get_field_val(s, event, "err_len", record, &val, 1) < 0)
		return -1;
	ev.err_len = val;
	trace_seq_printf(s, "Riscv Processor Err Record data len: %d\n",
			 ev.err_len);
	if (ev.err_len)
		parse_riscv_processor_err_record(s, record, event, &ev);

#ifdef HAVE_CPU_FAULT_ISOLATION
	if (ras_handle_cpu_error(s, record, event, &ev, now) < 0)
		printf("Can't do CPU fault isolation!\n");
#endif

	/* Insert data into the SGBD */
#ifdef HAVE_SQLITE3
	ras_store_riscv_record(ras, &ev);
#endif

#ifdef HAVE_ABRT_REPORT
	/* Report event to ABRT */
	ras_report_riscv_event(ras, &ev);
#endif

	return 0;
}
