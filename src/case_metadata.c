/*

    File: case_metadata.c

    Copyright (C) 2025 TestDisk/PhotoRec forensic case metadata module

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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "case_metadata.h"

/* VERSION is defined by config.h or the build system */
#ifndef VERSION
#define VERSION "unknown"
#endif

/* Fill an ISO 8601 timestamp into buf (size >= 32) */
static void iso8601_now(char *buf, size_t bufsize)
{
	time_t now;
	struct tm *tmp;
#if !defined(__MINGW32__)
	struct tm tm_tmp;
#endif

	time(&now);
#if defined(__MINGW32__)
	tmp = localtime(&now);
#else
	tmp = localtime_r(&now, &tm_tmp);
#endif
	if (!tmp || strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%S%z", tmp) == 0)
		snprintf(buf, bufsize, "1970-01-01T00:00:00+0000");
}

void case_metadata_init(case_metadata_t *meta)
{
	if (!meta)
		return;
	memset(meta, 0, sizeof(*meta));
	snprintf(meta->tool_version, sizeof(meta->tool_version),
		"PhotoRec %s", VERSION);
#ifdef HAVE_UNISTD_H
	if (gethostname(meta->hostname, sizeof(meta->hostname) - 1) != 0)
		snprintf(meta->hostname, sizeof(meta->hostname), "unknown");
	meta->hostname[sizeof(meta->hostname) - 1] = '\0';
#else
	snprintf(meta->hostname, sizeof(meta->hostname), "unknown");
#endif
}

void case_metadata_set_start(case_metadata_t *meta)
{
	if (!meta)
		return;
	iso8601_now(meta->start_time, sizeof(meta->start_time));
}

void case_metadata_set_end(case_metadata_t *meta)
{
	if (!meta)
		return;
	iso8601_now(meta->end_time, sizeof(meta->end_time));
}
