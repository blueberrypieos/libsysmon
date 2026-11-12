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
#include <sys/param.h>
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

struct proc_info_row {
	uint64_t pid, flags, uid, ruid, rgid, ppid, pgid, tdev;
	int64_t start_sec, start_usec;
	char comm[MAXCOMLEN + 1];
};

static int
proc_row(pid_t pid, struct proc_info_row *pi)
{
	struct proc_bsdinfo bi;
	struct proc_bsdshortinfo si;
	struct kinfo_proc kp;
	size_t len = sizeof(kp);
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

	memset(pi, 0, sizeof(*pi));
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi)) == (int)sizeof(bi)) {
		pi->pid = bi.pbi_pid;
		pi->flags = bi.pbi_flags;
		pi->uid = bi.pbi_uid;
		pi->ruid = bi.pbi_ruid;
		pi->rgid = bi.pbi_rgid;
		pi->ppid = bi.pbi_ppid;
		pi->pgid = bi.pbi_pgid;
		pi->tdev = (uint32_t)bi.e_tdev;
		pi->start_sec = (int64_t)bi.pbi_start_tvsec;
		pi->start_usec = (int64_t)bi.pbi_start_tvusec;
		memcpy(pi->comm, bi.pbi_comm, MAXCOMLEN);
		return 0;
	}
	if (proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof(si)) != (int)sizeof(si)) {
		return -1;
	}
	pi->pid = si.pbsi_pid;
	pi->flags = si.pbsi_flags;
	pi->uid = si.pbsi_uid;
	pi->ruid = si.pbsi_ruid;
	pi->rgid = si.pbsi_rgid;
	pi->ppid = si.pbsi_ppid;
	pi->pgid = si.pbsi_pgid;
	memcpy(pi->comm, si.pbsi_comm, MAXCOMLEN);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) == 0 && len == sizeof(kp) && kp.kp_proc.p_pid == pid) {
		pi->tdev = (uint32_t)kp.kp_eproc.e_tdev;
		pi->start_sec = kp.kp_proc.p_starttime.tv_sec;
		pi->start_usec = kp.kp_proc.p_starttime.tv_usec;
	} else {
		pi->tdev = (uint32_t)NODEV;
	}
	return 0;
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
		struct proc_info_row pi;
		if (proc_row(pids[i], &pi) != 0) {
			continue;
		}
		struct sysmon_row_s *row = &t->rows[t->count++];
		uint64_t numbers[SYSMON_ATTR_MAX + 1] = {
			[SYSMON_ATTR_PROC_PID] = pi.pid,
			[SYSMON_ATTR_PROC_FLAGS] = pi.flags,
			[SYSMON_ATTR_PROC_UID] = pi.uid,
			[SYSMON_ATTR_PROC_RUID] = pi.ruid,
			[SYSMON_ATTR_PROC_RGID] = pi.rgid,
			[SYSMON_ATTR_PROC_PPID] = pi.ppid,
			[SYSMON_ATTR_PROC_PGID] = pi.pgid,
			[SYSMON_ATTR_PROC_TDEV] = pi.tdev,
		};
		for (int a = 1; a <= SYSMON_ATTR_MAX; a++) {
			if (!r->want[a]) {
				continue;
			}
			switch (a) {
			case SYSMON_ATTR_PROC_COMM:
				row->value[a] = xpc_string_create(pi.comm);
				break;
			case SYSMON_ATTR_PROC_ARGUMENTS:
				row->value[a] = copy_arguments(pi.pid);
				break;
			case SYSMON_ATTR_PROC_START:
				row->value[a] = xpc_date_create(pi.start_sec * 1000000000 + pi.start_usec * 1000);
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
