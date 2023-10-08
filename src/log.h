/*

    File: log.h

    Copyright (C) 2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _LOG_H
#define _LOG_H
#ifdef __cplusplus
extern "C" {
#endif

unsigned int log_set_levels(const unsigned int levels);

/*@
  @ requires valid_read_string(default_filename);
  @ requires \valid(errsv);
  @ requires separation: \separated(default_filename, errsv, &errno);
  @*/
int log_open(const char*default_filename, const int mode, int *errsv);

/*@
  @ requires \valid_read(default_filename);
  @ requires \valid(errsv);
  @ requires separation: \separated(default_filename, errsv, &errno);
  @*/
int log_open_default(const char*default_filename, const int mode, int *errsv);

int log_flush(void);
int log_close(void);

/*@
  @ requires valid_read_string(format);
  @*/
int log_redirect(const unsigned int level, const char *format, ...) __attribute__((format(printf, 2, 3)));

/*@
  @ requires lng <= 1<<30;
  @ requires \valid((char *)nom_dump + (0 .. lng-1));
  @*/
void dump_log(const void *nom_dump, const unsigned int lng);

/*@
  @ requires lng <= 1<<30;
  @ requires \valid((char *)dump_1 + (0 .. lng-1));
  @ requires \valid((char *)dump_2 + (0 .. lng-1));
  @*/
void dump2_log(const void *dump_1, const void *dump_2,const unsigned int lng);

#define TD_LOG_NONE	0
#define TD_LOG_CREATE	1
#define TD_LOG_APPEND	2
#define TD_LOG_DONE	3

#define LOG_LEVEL_DEBUG    (1 <<  0) /* x = 42 */
#define LOG_LEVEL_TRACE    (1 <<  1) /* Entering function x() */
#define LOG_LEVEL_QUIET    (1 <<  2) /* Quietable output */
#define LOG_LEVEL_INFO     (1 <<  3) /* Volume needs defragmenting */
#define LOG_LEVEL_VERBOSE  (1 <<  4) /* Forced to continue */
#define LOG_LEVEL_PROGRESS (1 <<  5) /* 54% complete */
#define LOG_LEVEL_WARNING  (1 <<  6) /* You should backup before starting */
#define LOG_LEVEL_ERROR    (1 <<  7) /* Operation failed, no damage done */
#define LOG_LEVEL_PERROR   (1 <<  8) /* Message : standard error description */
#define LOG_LEVEL_CRITICAL (1 <<  9) /* Operation failed,damage may have occurred */

#define log_debug(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_DEBUG,FORMAT,##ARGS)
#define log_trace(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_TRACE,FORMAT,##ARGS)
#define log_quiet(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_QUIET,FORMAT,##ARGS)
#define log_info(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_INFO,FORMAT,##ARGS)
#define log_verbose(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_VERBOSE,FORMAT,##ARGS)
#define log_progress(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_PROGRESS,FORMAT,##ARGS)
#define log_warning(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_WARNING,FORMAT,##ARGS)
#define log_error(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_ERROR,FORMAT,##ARGS)
#define log_perror(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_PERROR,FORMAT,##ARGS)
#define log_critical(FORMAT, ARGS...)	log_redirect(LOG_LEVEL_CRITICAL,FORMAT,##ARGS)

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
