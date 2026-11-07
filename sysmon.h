/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#ifndef _SYSMON_H_
#define _SYSMON_H_

#include <sys/cdefs.h>
#include <stddef.h>
#include <xpc/xpc.h>

__BEGIN_DECLS

typedef enum {
	SYSMON_REQUEST_TYPE_PROCESS = 1,
} sysmon_request_type_t;

typedef enum {
	SYSMON_ATTR_PROC_PID = 1,
	SYSMON_ATTR_PROC_FLAGS,
	SYSMON_ATTR_PROC_UID,
	SYSMON_ATTR_PROC_COMM,
	SYSMON_ATTR_PROC_ARGUMENTS,
	SYSMON_ATTR_PROC_RUID,
	SYSMON_ATTR_PROC_RGID,
	SYSMON_ATTR_PROC_PPID,
	SYSMON_ATTR_PROC_PGID,
	SYSMON_ATTR_PROC_TDEV,
	SYSMON_ATTR_PROC_START,
	SYSMON_ATTR_MAX = SYSMON_ATTR_PROC_START,
} sysmon_attribute_t;

typedef struct sysmon_request_s *sysmon_request_t;
typedef struct sysmon_table_s *sysmon_table_t;
typedef struct sysmon_row_s *sysmon_row_t;

sysmon_request_t sysmon_request_create_with_error(sysmon_request_type_t type,
    void (^handler)(sysmon_table_t table, const char *error_str));
void sysmon_request_add_attribute(sysmon_request_t request, sysmon_attribute_t attribute);
void sysmon_request_execute(sysmon_request_t request);

void *sysmon_retain(void *object);
void sysmon_release(void *object);

size_t sysmon_table_get_count(sysmon_table_t table);
sysmon_row_t sysmon_table_get_row(sysmon_table_t table, size_t index);
xpc_object_t sysmon_row_get_value(sysmon_row_t row, sysmon_attribute_t attribute);

__END_DECLS

#endif
