/*

    File: color_output.h

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

#ifndef _COLOR_OUTPUT_H
#define _COLOR_OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* Available foreground colors and text attributes */
typedef enum {
  COLOR_NONE    = 0,
  COLOR_RED     = 1,
  COLOR_GREEN   = 2,
  COLOR_YELLOW  = 3,
  COLOR_BLUE    = 4,
  COLOR_MAGENTA = 5,
  COLOR_CYAN    = 6,
  COLOR_WHITE   = 7,
  COLOR_BOLD    = 8
} color_t;

/*
 * Initialise the color subsystem.
 * force_color != 0  => always emit ANSI codes regardless of isatty / TERM.
 * force_color == 0  => auto-detect: requires isatty(fileno(out)) and a
 *                      capable TERM, and respects NO_COLOR env var.
 * Must be called before color_print / color_reset.
 */
void color_init(int force_color);

/*
 * Print a formatted message to 'out' prefixed by the ANSI escape for
 * 'color' and followed by a reset sequence.
 * If colors are not supported the message is printed without any escapes.
 */
void color_print(FILE *out, color_t color, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/*
 * Emit the ANSI reset sequence to 'out'.
 * No-op when colors are not supported.
 */
void color_reset(FILE *out);

/*
 * Return non-zero if ANSI color output is currently enabled.
 */
int color_supported(void);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* _COLOR_OUTPUT_H */
