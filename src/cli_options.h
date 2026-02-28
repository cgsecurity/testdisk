/*

    File: cli_options.h

    Copyright (C) 2025 Christophe GRENIER <grenier@cgsecurity.org>

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

#ifndef _CLI_OPTIONS_H
#define _CLI_OPTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/*
 * Extended CLI options for forensic and automation use-cases.
 * Parsed from argv via getopt_long; does not replace the existing
 * phmain.c / testdisk option handling — it is a complementary layer
 * for the new flags introduced in Phase 7.
 */
typedef struct {
  /* Forensic metadata ------------------------------------------------- */
  char     case_id[128];       /* --case-id <id>        */
  char     examiner[128];      /* --examiner <name>     */
  char     evidence_id[128];   /* --evidence-id <id>    */

  /* Output control ---------------------------------------------------- */
  int      json_output;        /* --json                */
  int      dry_run;            /* --dry-run             */
  int      verbose_level;      /* --verbose / -v (0-3)  */

  /* Filtering --------------------------------------------------------- */
  char     filter_ext[256];    /* --filter-ext jpg,png  */
  uint64_t filter_min_size;    /* --min-size <bytes>    */
  uint64_t filter_max_size;    /* --max-size <bytes>    */

  /* Threading --------------------------------------------------------- */
  int      thread_count;       /* --threads N|auto      */

  /* Report ------------------------------------------------------------ */
  char     report_path[1024];  /* --report <path>       */
  int      report_html;        /* --report-html         */
  int      report_csv;         /* --report-csv          */
} cli_options_t;

/* Initialise all fields to safe defaults (zeros / empty strings). */
void cli_options_init(cli_options_t *opts);

/*
 * Parse argv[1..argc-1] for the new long options defined above.
 * Unknown options cause an error message + help and return -1.
 * Returns 0 on success, -1 on error.
 * optind is NOT reset; callers may call getopt_long themselves afterward.
 */
int cli_options_parse(cli_options_t *opts, int argc, char **argv);

/* Print usage to stdout. */
void cli_options_print_help(const char *prog_name);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* _CLI_OPTIONS_H */
