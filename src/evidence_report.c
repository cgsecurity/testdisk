/*

    File: evidence_report.c

    Copyright (C) 2025 TestDisk/PhotoRec forensic evidence reporting module

    Generates HTML, CSV, and JSON forensic evidence reports.
    All output uses fprintf/snprintf — no external template deps.
    HTML uses inline CSS only; no JavaScript, no external resources.

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
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "case_metadata.h"
#include "evidence_report.h"

#ifndef VERSION
#define VERSION "unknown"
#endif

/* ---- helpers ------------------------------------------------------- */

/* Write current ISO-8601 wall-clock into buf (size >= 32) */
static void now_iso8601(char *buf, size_t bufsize)
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

/* Escape < > & " for HTML output */
static void html_escape(FILE *fh, const char *s)
{
	if (!s) return;
	for (; *s; s++) {
		switch (*s) {
		case '<':  fputs("&lt;",   fh); break;
		case '>':  fputs("&gt;",   fh); break;
		case '&':  fputs("&amp;",  fh); break;
		case '"':  fputs("&quot;", fh); break;
		default:   fputc(*s, fh);       break;
		}
	}
}

/* Escape " and \ for JSON string values (caller writes surrounding quotes) */
static void json_escape(FILE *fh, const char *s)
{
	if (!s) { fputs("null", fh); return; }
	fputc('"', fh);
	for (; *s; s++) {
		switch (*s) {
		case '"':  fputs("\\\"", fh); break;
		case '\\': fputs("\\\\", fh); break;
		case '\n': fputs("\\n",  fh); break;
		case '\r': fputs("\\r",  fh); break;
		case '\t': fputs("\\t",  fh); break;
		default:
			if ((unsigned char)*s < 0x20)
				fprintf(fh, "\\u%04x", (unsigned char)*s);
			else
				fputc(*s, fh);
			break;
		}
	}
	fputc('"', fh);
}

/* Escape commas and quotes for a single CSV field; wraps in quotes if needed */
static void csv_field(FILE *fh, const char *s)
{
	const char *p;
	int needs_quote = 0;

	if (!s) { fputs("\"\"", fh); return; }
	for (p = s; *p; p++) {
		if (*p == '"' || *p == ',' || *p == '\n' || *p == '\r') {
			needs_quote = 1;
			break;
		}
	}
	if (!needs_quote) { fputs(s, fh); return; }
	fputc('"', fh);
	for (p = s; *p; p++) {
		if (*p == '"') fputc('"', fh); /* double-up quotes per RFC 4180 */
		fputc(*p, fh);
	}
	fputc('"', fh);
}

/* ---- Inline CSS for the HTML report -------------------------------- */

static const char *html_css =
	"body{font-family:Arial,Helvetica,sans-serif;font-size:13px;"
		"background:#f4f4f4;color:#222;margin:0;padding:20px}"
	"h1{font-size:20px;color:#1a3a5c;border-bottom:2px solid #1a3a5c;"
		"padding-bottom:6px}"
	"h2{font-size:15px;color:#1a3a5c;margin-top:24px}"
	".meta-table{border-collapse:collapse;margin-bottom:18px}"
	".meta-table td{padding:4px 12px 4px 0;vertical-align:top}"
	".meta-table td:first-child{font-weight:bold;white-space:nowrap;"
		"color:#444}"
	"table.files{border-collapse:collapse;width:100%;background:#fff;"
		"box-shadow:0 1px 3px rgba(0,0,0,.15)}"
	"table.files th{background:#1a3a5c;color:#fff;padding:7px 10px;"
		"text-align:left;font-size:12px}"
	"table.files td{padding:5px 10px;border-bottom:1px solid #e0e0e0;"
		"font-size:12px;word-break:break-all}"
	"table.files tr:nth-child(even) td{background:#f9f9f9}"
	".hash{font-family:monospace;font-size:11px;color:#555}"
	".summary{background:#fff;border-left:4px solid #1a3a5c;"
		"padding:10px 16px;margin-top:20px;"
		"box-shadow:0 1px 3px rgba(0,0,0,.1)}"
	".footer{margin-top:30px;font-size:11px;color:#888;"
		"border-top:1px solid #ccc;padding-top:8px}";

/* ---- HTML report --------------------------------------------------- */

int report_html_open(const char *output_path, const case_metadata_t *meta)
{
	FILE *fh;
	char now[32];

	if (!output_path || !meta)
		return -1;

	fh = fopen(output_path, "w");
	if (!fh)
		return -1;

	now_iso8601(now, sizeof(now));

	fprintf(fh,
		"<!DOCTYPE html>\n"
		"<html lang=\"en\">\n"
		"<head>\n"
		"<meta charset=\"UTF-8\">\n"
		"<meta name=\"viewport\" content=\"width=device-width,"
		" initial-scale=1.0\">\n"
		"<title>Forensic Evidence Report");
	if (meta->case_id[0]) {
		fputs(" — Case ", fh);
		html_escape(fh, meta->case_id);
	}
	fputs("</title>\n", fh);
	fprintf(fh, "<style>\n%s\n</style>\n</head>\n<body>\n", html_css);

	fputs("<h1>Forensic Evidence Report</h1>\n", fh);

	/* Case metadata table */
	fputs("<h2>Case Information</h2>\n"
		"<table class=\"meta-table\">\n", fh);

	if (meta->case_id[0]) {
		fputs("<tr><td>Case ID</td><td>", fh);
		html_escape(fh, meta->case_id);
		fputs("</td></tr>\n", fh);
	}
	if (meta->examiner[0]) {
		fputs("<tr><td>Examiner</td><td>", fh);
		html_escape(fh, meta->examiner);
		fputs("</td></tr>\n", fh);
	}
	if (meta->evidence_id[0]) {
		fputs("<tr><td>Evidence ID</td><td>", fh);
		html_escape(fh, meta->evidence_id);
		fputs("</td></tr>\n", fh);
	}
	if (meta->start_time[0]) {
		fputs("<tr><td>Start Time</td><td>", fh);
		html_escape(fh, meta->start_time);
		fputs("</td></tr>\n", fh);
	}
	if (meta->end_time[0]) {
		fputs("<tr><td>End Time</td><td>", fh);
		html_escape(fh, meta->end_time);
		fputs("</td></tr>\n", fh);
	}
	if (meta->tool_version[0]) {
		fputs("<tr><td>Tool</td><td>", fh);
		html_escape(fh, meta->tool_version);
		fputs("</td></tr>\n", fh);
	}
	if (meta->hostname[0]) {
		fputs("<tr><td>Host</td><td>", fh);
		html_escape(fh, meta->hostname);
		fputs("</td></tr>\n", fh);
	}
	if (meta->notes[0]) {
		fputs("<tr><td>Notes</td><td>", fh);
		html_escape(fh, meta->notes);
		fputs("</td></tr>\n", fh);
	}
	fputs("</table>\n", fh);

	/* File listing table header */
	fputs("<h2>Recovered Files</h2>\n"
		"<table class=\"files\">\n"
		"<thead><tr>\n"
		"<th>#</th>\n"
		"<th>Filename</th>\n"
		"<th>Extension</th>\n"
		"<th>Size (bytes)</th>\n"
		"<th>Source Offset</th>\n"
		"<th>Timestamp</th>\n"
		"<th>SHA-256</th>\n"
		"</tr></thead>\n"
		"<tbody>\n", fh);

	fclose(fh);
	return 0;
}

int report_html_add_file(const char *output_path, const evidence_file_t *file)
{
	FILE *fh;
	/* Static row counter — incremented per call; not thread-safe but
	 * matches the single-threaded PhotoRec recovery model. */
	static unsigned int row = 0;

	if (!output_path || !file)
		return -1;

	fh = fopen(output_path, "a");
	if (!fh)
		return -1;

	row++;
	fprintf(fh, "<tr>\n<td>%u</td>\n<td>", row);
	html_escape(fh, file->filename);
	fputs("</td>\n<td>", fh);
	html_escape(fh, file->extension);
	fprintf(fh, "</td>\n<td>%llu</td>\n<td>%llu</td>\n<td>",
		(unsigned long long)file->file_size,
		(unsigned long long)file->source_offset);
	html_escape(fh, file->timestamp);
	fputs("</td>\n<td class=\"hash\">", fh);
	html_escape(fh, file->sha256_hex);
	fputs("</td>\n</tr>\n", fh);

	fclose(fh);
	return 0;
}

int report_html_close(const char *output_path, unsigned int total_files,
		      uint64_t total_bytes)
{
	FILE *fh;
	char now[32];

	if (!output_path)
		return -1;

	fh = fopen(output_path, "a");
	if (!fh)
		return -1;

	now_iso8601(now, sizeof(now));

	fputs("</tbody>\n</table>\n", fh);

	/* Summary block */
	fprintf(fh,
		"<div class=\"summary\">\n"
		"<strong>Summary:</strong> %u file(s) recovered, "
		"%llu bytes total.\n"
		"</div>\n",
		total_files, (unsigned long long)total_bytes);

	/* Footer */
	fprintf(fh,
		"<div class=\"footer\">Generated by PhotoRec %s"
		" &mdash; %s</div>\n",
		VERSION, now);

	fputs("</body>\n</html>\n", fh);
	fclose(fh);
	return 0;
}

/* ---- CSV report ---------------------------------------------------- */

int report_csv_write(const char *output_path, const evidence_file_t *files,
		     unsigned int count)
{
	FILE *fh;
	unsigned int i;

	if (!output_path || (!files && count > 0))
		return -1;

	fh = fopen(output_path, "w");
	if (!fh)
		return -1;

	/* Header row */
	fputs("filename,extension,file_size,source_offset,"
		"timestamp,sha256\r\n", fh);

	for (i = 0; i < count; i++) {
		csv_field(fh, files[i].filename);    fputc(',', fh);
		csv_field(fh, files[i].extension);   fputc(',', fh);
		fprintf(fh, "%llu,",
			(unsigned long long)files[i].file_size);
		fprintf(fh, "%llu,",
			(unsigned long long)files[i].source_offset);
		csv_field(fh, files[i].timestamp);   fputc(',', fh);
		csv_field(fh, files[i].sha256_hex);
		fputs("\r\n", fh);
	}

	fclose(fh);
	return 0;
}

/* ---- JSON report --------------------------------------------------- */

int report_json_write(const char *output_path, const case_metadata_t *meta,
		      const evidence_file_t *files, unsigned int count)
{
	FILE *fh;
	unsigned int i;
	char now[32];

	if (!output_path || !meta || (!files && count > 0))
		return -1;

	fh = fopen(output_path, "w");
	if (!fh)
		return -1;

	now_iso8601(now, sizeof(now));

	fputs("{\n", fh);

	/* Metadata section */
	fputs("  \"case_metadata\": {\n", fh);
	fputs("    \"case_id\": ",      fh); json_escape(fh, meta->case_id);
	fputs(",\n    \"examiner\": ",   fh); json_escape(fh, meta->examiner);
	fputs(",\n    \"evidence_id\": ",fh); json_escape(fh, meta->evidence_id);
	fputs(",\n    \"notes\": ",      fh); json_escape(fh, meta->notes);
	fputs(",\n    \"start_time\": ", fh); json_escape(fh, meta->start_time);
	fputs(",\n    \"end_time\": ",   fh); json_escape(fh, meta->end_time);
	fputs(",\n    \"tool_version\": ",fh);json_escape(fh, meta->tool_version);
	fputs(",\n    \"hostname\": ",   fh); json_escape(fh, meta->hostname);
	fputs("\n  },\n", fh);

	/* Summary */
	fprintf(fh, "  \"total_files\": %u,\n", count);

	/* File list */
	fputs("  \"files\": [\n", fh);
	for (i = 0; i < count; i++) {
		fputs("    {\n", fh);
		fputs("      \"filename\": ",      fh);
		json_escape(fh, files[i].filename);
		fputs(",\n      \"extension\": ",  fh);
		json_escape(fh, files[i].extension);
		fprintf(fh, ",\n      \"file_size\": %llu",
			(unsigned long long)files[i].file_size);
		fprintf(fh, ",\n      \"source_offset\": %llu",
			(unsigned long long)files[i].source_offset);
		fputs(",\n      \"timestamp\": ",  fh);
		json_escape(fh, files[i].timestamp);
		fputs(",\n      \"sha256\": ",     fh);
		json_escape(fh, files[i].sha256_hex);
		fputs("\n    }", fh);
		if (i + 1 < count)
			fputc(',', fh);
		fputc('\n', fh);
	}
	fputs("  ],\n", fh);

	/* Generation timestamp */
	fputs("  \"report_generated\": ", fh);
	json_escape(fh, now);
	fputs("\n}\n", fh);

	fclose(fh);
	return 0;
}
