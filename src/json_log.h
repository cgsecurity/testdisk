/*

    File: json_log.h

    Copyright (C) 2025 JSON logging for PhotoRec progress information

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

#ifndef _JSON_LOG_H
#define _JSON_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "photorec.h"

int json_log_open(const char *filename);

void json_log_session_start(const struct ph_param *params, const char **argv, int argc);

void json_log_cli_params(const struct ph_param *params, const char **argv, int argc);

void json_log_disk_info(const struct ph_param *params);

void json_log_partition_info(const struct ph_param *params);

void json_log_session_resume(const struct ph_param *params, const char *saved_device, const char *saved_cmd, int search_space_regions);

void json_log_progress(const struct ph_param *params, const unsigned int pass, const uint64_t offset);

void json_log_completion(const struct ph_param *params, const char *completion_message);

void json_log_handler(const unsigned int level, const char *format, va_list ap);

void json_log_cleanup(const struct ph_param *params);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif