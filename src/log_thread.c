/*
    File: log_thread.c

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

    Thread-safe logging wrappers.  All _ts functions acquire a static mutex
    before forwarding to log_redirect() so that concurrent worker threads do
    not interleave their output in the log file.

    When HAVE_PTHREAD is not defined the mutex is omitted entirely and each
    function delegates straight to log_redirect() with no overhead.
*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include "log.h"
#include "log_thread.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>

/* Static mutex — initialised once by log_thread_init() */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_mutex_ready = 0;

void log_thread_init(void)
{
	if (log_mutex_ready)
		return;
	/* PTHREAD_MUTEX_INITIALIZER already applied at compile time;
	 * explicit init here allows re-init after log_thread_cleanup(). */
	pthread_mutex_init(&log_mutex, NULL);
	log_mutex_ready = 1;
}

void log_thread_cleanup(void)
{
	if (!log_mutex_ready)
		return;
	pthread_mutex_destroy(&log_mutex);
	log_mutex_ready = 0;
}

/* -----------------------------------------------------------------------
 * Internal helper — lock, forward to log_redirect(), unlock.
 * ----------------------------------------------------------------------- */
static void log_ts(unsigned int level, const char *format, va_list ap)
{
	/* Build the final message into a stack buffer to avoid holding the
	 * mutex across a potentially slow vfprintf inside log_redirect.
	 * log_redirect takes a format + varargs so we must re-enter via a
	 * single formatted string.  Use a fixed 4096-byte buffer which is
	 * adequate for all diagnostic messages. */
	char buf[4096];
	int n;

	n = vsnprintf(buf, sizeof(buf), format, ap);
	(void)n; /* truncation is acceptable for log messages */

	if (log_mutex_ready)
		pthread_mutex_lock(&log_mutex);

	log_redirect(level, "%s", buf);

	if (log_mutex_ready)
		pthread_mutex_unlock(&log_mutex);
}

void log_info_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_ts(LOG_LEVEL_INFO, format, ap);
	va_end(ap);
}

void log_warning_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_ts(LOG_LEVEL_WARNING, format, ap);
	va_end(ap);
}

void log_error_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	log_ts(LOG_LEVEL_ERROR, format, ap);
	va_end(ap);
}

#else /* !HAVE_PTHREAD — direct passthrough, no mutex overhead */

void log_thread_init(void)   { /* nothing to do */ }
void log_thread_cleanup(void){ /* nothing to do */ }

void log_info_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	/* log_redirect is a varargs function; forward via vsnprintf+redirect */
	{
		char buf[4096];
		vsnprintf(buf, sizeof(buf), format, ap);
		log_redirect(LOG_LEVEL_INFO, "%s", buf);
	}
	va_end(ap);
}

void log_warning_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	{
		char buf[4096];
		vsnprintf(buf, sizeof(buf), format, ap);
		log_redirect(LOG_LEVEL_WARNING, "%s", buf);
	}
	va_end(ap);
}

void log_error_ts(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	{
		char buf[4096];
		vsnprintf(buf, sizeof(buf), format, ap);
		log_redirect(LOG_LEVEL_ERROR, "%s", buf);
	}
	va_end(ap);
}

#endif /* HAVE_PTHREAD */
