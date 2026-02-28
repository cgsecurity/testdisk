/*
    File: log_thread.h

    Copyright (C) 2024 TestDisk contributors

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

    Thread-safe wrappers around the existing log.c logging API.
    The _ts (thread-safe) variants serialise concurrent log calls with a
    mutex so that multi-threaded recovery output is not interleaved.

    When HAVE_PTHREAD is not defined all _ts functions delegate directly to
    the standard log_* macros with zero overhead.
*/
#ifndef _LOG_THREAD_H
#define _LOG_THREAD_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

/*
 * log_thread_init - initialise the internal logging mutex.
 * Call once before spawning any worker threads.
 * Safe to call multiple times (subsequent calls are no-ops).
 */
void log_thread_init(void);

/*
 * log_thread_cleanup - destroy the logging mutex.
 * Call after all worker threads have finished logging.
 */
void log_thread_cleanup(void);

/*
 * Thread-safe logging functions — _ts suffix denotes thread-safe variant.
 * These accept printf-style format strings and are safe to call from any
 * worker thread simultaneously.
 *
 * Mapped to LOG_LEVEL_INFO / LOG_LEVEL_WARNING / LOG_LEVEL_ERROR
 * from log.h respectively.
 */
void log_info_ts(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

void log_warning_ts(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

void log_error_ts(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif /* _LOG_THREAD_H */
