/*

    File: color_output.c

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
#ifdef HAVE_UNISTD_H
#include <unistd.h>   /* isatty, fileno */
#endif

#include <stdarg.h>

#include "color_output.h"

/* -------------------------------------------------------------------------
 * Module state
 * ---------------------------------------------------------------------- */

/* 1 = ANSI color output enabled, 0 = disabled */
static int color_enabled = 0;

/* -------------------------------------------------------------------------
 * ANSI escape sequences
 * SGR codes: 30-37 foreground colors, 1 = bold, 0 = reset
 * ---------------------------------------------------------------------- */

/* Map color_t -> SGR parameter string (NULL = reset only) */
static const char *color_to_ansi(color_t color)
{
  switch(color)
  {
    case COLOR_RED:     return "\033[31m";
    case COLOR_GREEN:   return "\033[32m";
    case COLOR_YELLOW:  return "\033[33m";
    case COLOR_BLUE:    return "\033[34m";
    case COLOR_MAGENTA: return "\033[35m";
    case COLOR_CYAN:    return "\033[36m";
    case COLOR_WHITE:   return "\033[37m";
    case COLOR_BOLD:    return "\033[1m";
    case COLOR_NONE:
    default:            return NULL;
  }
}

#define ANSI_RESET "\033[0m"

/* -------------------------------------------------------------------------
 * Terminal capability detection
 *
 * Rules (evaluated in order):
 *   1. NO_COLOR env var set (any value) => disable  (https://no-color.org/)
 *   2. TERM == "dumb"                   => disable
 *   3. isatty(fileno(out)) == 0         => disable (piped output)
 *   4. Otherwise                        => enable
 *
 * When force_color != 0, rules 1-3 are skipped and colors are always on.
 * ---------------------------------------------------------------------- */

static int detect_color_support(FILE *out)
{
  const char *no_color;
  const char *term;

  /* Rule 1: NO_COLOR */
  no_color = getenv("NO_COLOR");
  if(no_color != NULL)
    return 0;

  /* Rule 2: dumb terminal */
  term = getenv("TERM");
  if(term != NULL && strcmp(term, "dumb") == 0)
    return 0;

  /* Rule 3: not a TTY */
#ifdef HAVE_UNISTD_H
  if(out == NULL || !isatty(fileno(out)))
    return 0;
#else
  /* Without isatty, be conservative */
  (void)out;
  return 0;
#endif

  return 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void color_init(int force_color)
{
  if(force_color)
  {
    color_enabled = 1;
    return;
  }
  /* Auto-detect against stderr as the primary diagnostic stream.
   * color_print accepts a FILE* so per-stream detection happens there too. */
  color_enabled = detect_color_support(stderr);
}

int color_supported(void)
{
  return color_enabled;
}

void color_reset(FILE *out)
{
  if(!color_enabled || out == NULL)
    return;
  fputs(ANSI_RESET, out);
}

void color_print(FILE *out, color_t color, const char *fmt, ...)
{
  va_list ap;
  const char *seq;

  if(out == NULL || fmt == NULL)
    return;

  /* Per-stream TTY check: only emit escapes if this specific stream is a TTY
   * (handles cases where stdout is redirected but stderr is a terminal). */
  if(color_enabled && detect_color_support(out))
  {
    seq = color_to_ansi(color);
    if(seq != NULL)
      fputs(seq, out);
  }

  va_start(ap, fmt);
  vfprintf(out, fmt, ap);
  va_end(ap);

  if(color_enabled && detect_color_support(out))
    fputs(ANSI_RESET, out);
}
