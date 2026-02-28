/*

    File: evidence_report.h

    Copyright (C) 2025 TestDisk/PhotoRec forensic evidence reporting module

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
#ifndef _EVIDENCE_REPORT_H
#define _EVIDENCE_REPORT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "case_metadata.h"

/* One recovered file entry for reporting */
typedef struct {
	char		filename[1024];		/* full path as recovered */
	char		extension[16];		/* file extension, e.g. "jpg" */
	uint64_t	file_size;		/* bytes */
	uint64_t	source_offset;		/* byte offset on source media */
	char		sha256_hex[65];		/* hex-encoded SHA-256 digest  */
	char		timestamp[32];		/* ISO 8601 recovery timestamp */
} evidence_file_t;

/*
 * HTML report — three-call streaming API so callers can append files
 * incrementally without holding all records in memory.
 *
 * Returns 0 on success, -1 on error.
 */
int	report_html_open(const char *output_path, const case_metadata_t *meta);
int	report_html_add_file(const char *output_path, const evidence_file_t *file);
int	report_html_close(const char *output_path, unsigned int total_files,
			  uint64_t total_bytes);

/* CSV report — writes all records in one call */
int	report_csv_write(const char *output_path, const evidence_file_t *files,
			 unsigned int count);

/* JSON report — writes full report with metadata + file list */
int	report_json_write(const char *output_path, const case_metadata_t *meta,
			  const evidence_file_t *files, unsigned int count);

#endif /* _EVIDENCE_REPORT_H */
