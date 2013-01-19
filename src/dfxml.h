/*

    File: dfxml.h

    Copyright (C) 2011 Simson Garfinkel
    Copyright (C) 2011 Christophe Grenier
  
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

#ifndef _DFXML_H
#define _DFXML_H

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

FILE *xml_open(const char *default_filename, const unsigned int dir_num);
void xml_close(void);
void xml_push(const char *tag, const char *attribute);
void xml_pop(const char *tag);
void xml_out2s(const char *tag, const char *value);
void xml_out2i(const char *tag, const uint64_t value);
void xml_setup(disk_t *disk, const partition_t *partition);
void xml_set_command_line(const int argc, char **argv);
void xml_clear_command_line(void);
void xml_add_DFXML_creator(const char *package, const char *version);
void xml_shutdown(void);
void xml_log_file_recovered(const file_recovery_t *file_recovery);
void xml_log_file_recovered2(const alloc_data_t *space, const file_recovery_t *file_recovery);
void xml_printf(const char *__restrict __format,...) __attribute__((format(printf,1,2)));
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
