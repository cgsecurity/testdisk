/*

    File: phcfg.h

    Copyright (C) 2020 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _PHCFG_H
#define _PHCFG_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(files_enable);
  @*/
void reset_array_file_enable(file_enable_t *files_enable);

/*@
  @ requires \valid_read(files_enable);
  @*/
int file_options_save(const file_enable_t *files_enable);

/*@
  @ requires \valid(files_enable);
  @*/
int file_options_load(file_enable_t *files_enable);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
