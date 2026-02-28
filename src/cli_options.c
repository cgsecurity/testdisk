/*

    File: cli_options.c

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
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* getopt_long is defined in getopt.h on most platforms */
#include <getopt.h>

#include "cli_options.h"

/* -------------------------------------------------------------------------
 * Long option token IDs (values >= 128 to avoid collision with ASCII chars)
 * ---------------------------------------------------------------------- */
enum {
  OPT_CASE_ID      = 128,
  OPT_EXAMINER,
  OPT_EVIDENCE_ID,
  OPT_JSON,
  OPT_DRY_RUN,
  OPT_FILTER_EXT,
  OPT_MIN_SIZE,
  OPT_MAX_SIZE,
  OPT_THREADS,
  OPT_REPORT,
  OPT_REPORT_HTML,
  OPT_REPORT_CSV,
  OPT_HELP
};

/* Table of recognised long options */
static const struct option long_opts[] = {
  { "case-id",     required_argument, NULL, OPT_CASE_ID     },
  { "examiner",    required_argument, NULL, OPT_EXAMINER    },
  { "evidence-id", required_argument, NULL, OPT_EVIDENCE_ID },
  { "json",        no_argument,       NULL, OPT_JSON        },
  { "dry-run",     no_argument,       NULL, OPT_DRY_RUN     },
  { "verbose",     no_argument,       NULL, 'v'             },
  { "filter-ext",  required_argument, NULL, OPT_FILTER_EXT  },
  { "min-size",    required_argument, NULL, OPT_MIN_SIZE    },
  { "max-size",    required_argument, NULL, OPT_MAX_SIZE    },
  { "threads",     required_argument, NULL, OPT_THREADS     },
  { "report",      required_argument, NULL, OPT_REPORT      },
  { "report-html", no_argument,       NULL, OPT_REPORT_HTML },
  { "report-csv",  no_argument,       NULL, OPT_REPORT_CSV  },
  { "help",        no_argument,       NULL, OPT_HELP        },
  { NULL,          0,                 NULL, 0               }
};

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Safe strncpy that always NUL-terminates dst. */
static void safe_strncpy(char *dst, const char *src, size_t size)
{
  if(size == 0)
    return;
  strncpy(dst, src, size - 1);
  dst[size - 1] = '\0';
}

/* Parse a decimal or 0x-prefixed hex uint64 from str.
 * Returns 0 on success, -1 on parse error. */
static int parse_uint64(const char *str, uint64_t *out)
{
  char *endp;
  unsigned long long v;
  if(str == NULL || *str == '\0')
    return -1;
  v = strtoull(str, &endp, 0);
  if(*endp != '\0')
    return -1;
  *out = (uint64_t)v;
  return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void cli_options_init(cli_options_t *opts)
{
  if(opts == NULL)
    return;
  memset(opts, 0, sizeof(cli_options_t));
  /* Sensible non-zero defaults */
  opts->thread_count    = 1;
  opts->filter_max_size = UINT64_MAX;
}

int cli_options_parse(cli_options_t *opts, int argc, char **argv)
{
  int c;
  int opt_index = 0;

  if(opts == NULL || argc <= 0 || argv == NULL)
    return -1;

  /* Reset getopt state so we scan from the beginning */
  optind = 1;
  opterr = 0; /* suppress automatic error messages; we handle them */

  while((c = getopt_long(argc, argv, "v", long_opts, &opt_index)) != -1)
  {
    switch(c)
    {
      case OPT_CASE_ID:
        safe_strncpy(opts->case_id, optarg, sizeof(opts->case_id));
        break;

      case OPT_EXAMINER:
        safe_strncpy(opts->examiner, optarg, sizeof(opts->examiner));
        break;

      case OPT_EVIDENCE_ID:
        safe_strncpy(opts->evidence_id, optarg, sizeof(opts->evidence_id));
        break;

      case OPT_JSON:
        opts->json_output = 1;
        break;

      case OPT_DRY_RUN:
        opts->dry_run = 1;
        break;

      case 'v':
        /* Each -v / --verbose increments the level, capped at 3 */
        if(opts->verbose_level < 3)
          opts->verbose_level++;
        break;

      case OPT_FILTER_EXT:
        safe_strncpy(opts->filter_ext, optarg, sizeof(opts->filter_ext));
        break;

      case OPT_MIN_SIZE:
        if(parse_uint64(optarg, &opts->filter_min_size) != 0)
        {
          fprintf(stderr, "Error: --min-size requires a numeric value, got: %s\n", optarg);
          cli_options_print_help(argv[0]);
          return -1;
        }
        break;

      case OPT_MAX_SIZE:
        if(parse_uint64(optarg, &opts->filter_max_size) != 0)
        {
          fprintf(stderr, "Error: --max-size requires a numeric value, got: %s\n", optarg);
          cli_options_print_help(argv[0]);
          return -1;
        }
        break;

      case OPT_THREADS:
        if(strcmp(optarg, "auto") == 0)
        {
          /* 0 signals "auto-detect" to the caller */
          opts->thread_count = 0;
        }
        else
        {
          int n = atoi(optarg);
          if(n <= 0)
          {
            fprintf(stderr, "Error: --threads requires a positive integer or 'auto', got: %s\n", optarg);
            cli_options_print_help(argv[0]);
            return -1;
          }
          opts->thread_count = n;
        }
        break;

      case OPT_REPORT:
        safe_strncpy(opts->report_path, optarg, sizeof(opts->report_path));
        break;

      case OPT_REPORT_HTML:
        opts->report_html = 1;
        break;

      case OPT_REPORT_CSV:
        opts->report_csv = 1;
        break;

      case OPT_HELP:
        cli_options_print_help(argv[0]);
        /* Returning -1 lets the caller decide whether to exit */
        return -1;

      case '?':
      default:
        fprintf(stderr, "Error: unknown option '%s'\n",
            (optind > 0 && optind <= argc) ? argv[optind - 1] : "?");
        cli_options_print_help(argv[0]);
        return -1;
    }
  }

  return 0;
}

void cli_options_print_help(const char *prog_name)
{
  const char *name = (prog_name != NULL) ? prog_name : "photorec";
  printf(
    "\nUsage: %s [options] [device|image]\n"
    "\nForensic metadata:\n"
    "  --case-id <id>        Case identifier recorded in reports\n"
    "  --examiner <name>     Examiner name recorded in reports\n"
    "  --evidence-id <id>    Evidence item identifier\n"
    "\nOutput control:\n"
    "  --json                Machine-readable JSON output\n"
    "  --dry-run             Scan without writing recovered files\n"
    "  -v, --verbose         Increase verbosity (repeat up to 3 times)\n"
    "\nFile filtering:\n"
    "  --filter-ext <list>   Comma-separated extension list, e.g. jpg,png,pdf\n"
    "  --min-size <bytes>    Skip files smaller than this size\n"
    "  --max-size <bytes>    Skip files larger than this size\n"
    "\nThreading:\n"
    "  --threads <N|auto>    Worker thread count (auto = detect CPU count)\n"
    "\nReporting:\n"
    "  --report <path>       Write report to this path\n"
    "  --report-html         Generate HTML report\n"
    "  --report-csv          Generate CSV report\n"
    "\nMisc:\n"
    "  --help                Show this help message\n"
    "\n",
    name
  );
}
