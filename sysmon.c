/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <Block.h>
#include <dispatch/dispatch.h>
#include <libproc.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include "sysmon.h"

enum { KIND_REQUEST = 1, KIND_TABLE };

struct object {
	int kind;
	atomic_int refs;
};

struct sysmon_request_s {
	struct object o;
	sysmon_request_type_t type;
	void (^handler)(sysmon_table_t, const char *);
	bool want[SYSMON_ATTR_MAX + 1];
};

struct sysmon_row_s {
	xpc_object_t value[SYSMON_ATTR_MAX + 1];
};

struct sysmon_table_s {
	struct object o;
	size_t count;
	struct sysmon_row_s *rows;
};

sysmon_request_t
sysmon_request_create_with_error(sysmon_request_type_t type, void (^handler)(sysmon_table_t, const char *))
{
	sysmon_request_t r = calloc(1, sizeof(*r));
	if (r == NULL) {
		return NULL;
	}
	r->o.kind = KIND_REQUEST;
	atomic_init(&r->o.refs, 1);
	r->type = type;
	r->handler = Block_copy(handler);
	return r;
}

void
sysmon_request_add_attribute(sysmon_request_t r, sysmon_attribute_t attribute)
{
	if (attribute >= 1 && attribute <= SYSMON_ATTR_MAX) {
		r->want[attribute] = true;
	}
}

void *
sysmon_retain(void *object)
{
	if (object != NULL) {
		atomic_fetch_add(&((struct object *)object)->refs, 1);
	}
	return object;
}

void
sysmon_release(void *object)
{
	struct object *o = object;
	if (o == NULL || atomic_fetch_sub(&o->refs, 1) != 1) {
		return;
	}
	if (o->kind == KIND_REQUEST) {
		Block_release(((sysmon_request_t)o)->handler);
	} else {
		sysmon_table_t t = (sysmon_table_t)o;
		for (size_t i = 0; i < t->count; i++) {
			for (int a = 1; a <= SYSMON_ATTR_MAX; a++) {
				if (t->rows[i].value[a] != NULL) {
					xpc_release(t->rows[i].value[a]);
				}
			}
		}
		free(t->rows);
	}
	free(o);
}

size_t
sysmon_table_get_count(sysmon_table_t t)
{
	return t->count;
}

sysmon_row_t
sysmon_table_get_row(sysmon_table_t t, size_t index)
{
	return index < t->count ? &t->rows[index] : NULL;
}

xpc_object_t
sysmon_row_get_value(sysmon_row_t row, sysmon_attribute_t attribute)
{
	return row != NULL && attribute >= 1 && attribute <= SYSMON_ATTR_MAX ? row->value[attribute] : NULL;
}

static xpc_object_t
copy_arguments(pid_t pid)
{
	int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
	int max = 0;
	size_t size = sizeof(max);
	int argmax[2] = { CTL_KERN, KERN_ARGMAX };
	if (sysctl(argmax, 2, &max, &size, NULL, 0) != 0 || max <= 0) {
		return NULL;
	}
	char *buf = malloc((size_t)max);
	size = (size_t)max;
	if (buf == NULL || sysctl(mib, 3, buf, &size, NULL, 0) != 0 || size < sizeof(int)) {
		free(buf);
		return NULL;
	}
	int argc;
	memcpy(&argc, buf, sizeof(argc));
	char *p = buf + sizeof(int), *end = buf + size;
	p += strnlen(p, (size_t)(end - p));
	while (p < end && *p == '\0') {
		p++;
	}
	xpc_object_t args = xpc_array_create(NULL, 0);
	for (int i = 0; i < argc && p < end; i++) {
		size_t len = strnlen(p, (size_t)(end - p));
		char *arg = strndup(p, len);
		if (arg != NULL) {
			xpc_object_t s = xpc_string_create(arg);
			xpc_array_append_value(args, s);
			xpc_release(s);
			free(arg);
		}
		p += len + 1;
	}
	free(buf);
	return args;
}

static sysmon_table_t
process_table(sysmon_request_t r)
{
	int n = proc_listallpids(NULL, 0);
	if (n <= 0) {
		return NULL;
	}
	pid_t *pids = calloc((size_t)n + 16, sizeof(pid_t));
	sysmon_table_t t = calloc(1, sizeof(*t));
	if (pids == NULL || t == NULL) {
		free(pids);
		free(t);
		return NULL;
	}
	n = proc_listallpids(pids, (int)(((size_t)n + 16) * sizeof(pid_t)));
	t->o.kind = KIND_TABLE;
	atomic_init(&t->o.refs, 1);
	t->rows = calloc((size_t)(n > 0 ? n : 1), sizeof(*t->rows));
	if (t->rows == NULL) {
		free(pids);
		free(t);
		return NULL;
	}
	for (int i = 0; i < n; i++) {
		struct proc_bsdinfo bi;
		if (proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &bi, sizeof(bi)) != (int)sizeof(bi)) {
			continue;
		}
		struct sysmon_row_s *row = &t->rows[t->count++];
		uint64_t numbers[SYSMON_ATTR_MAX + 1] = {
			[SYSMON_ATTR_PROC_PID] = bi.pbi_pid,
			[SYSMON_ATTR_PROC_FLAGS] = bi.pbi_flags,
			[SYSMON_ATTR_PROC_UID] = bi.pbi_uid,
			[SYSMON_ATTR_PROC_RUID] = bi.pbi_ruid,
			[SYSMON_ATTR_PROC_RGID] = bi.pbi_rgid,
			[SYSMON_ATTR_PROC_PPID] = bi.pbi_ppid,
			[SYSMON_ATTR_PROC_PGID] = bi.pbi_pgid,
			[SYSMON_ATTR_PROC_TDEV] = bi.e_tdev,
		};
		for (int a = 1; a <= SYSMON_ATTR_MAX; a++) {
			if (!r->want[a]) {
				continue;
			}
			switch (a) {
			case SYSMON_ATTR_PROC_COMM: {
				char comm[MAXCOMLEN + 1];
				strlcpy(comm, bi.pbi_comm, sizeof(comm));
				row->value[a] = xpc_string_create(comm);
				break;
			}
			case SYSMON_ATTR_PROC_ARGUMENTS:
				row->value[a] = copy_arguments(bi.pbi_pid);
				break;
			case SYSMON_ATTR_PROC_START:
				row->value[a] = xpc_date_create((int64_t)bi.pbi_start_tvsec * 1000000000 +
				    (int64_t)bi.pbi_start_tvusec * 1000);
				break;
			default:
				row->value[a] = xpc_uint64_create(numbers[a]);
				break;
			}
		}
	}
	free(pids);
	return t;
}

void
sysmon_request_execute(sysmon_request_t r)
{
	sysmon_retain(r);
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
		sysmon_table_t t = r->type == SYSMON_REQUEST_TYPE_PROCESS ? process_table(r) : NULL;
		r->handler(t, t != NULL ? NULL : "cannot list the processes");
		sysmon_release(t);
		sysmon_release(r);
	});
}
