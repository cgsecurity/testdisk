/*

    File: phrecn.h

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _PHRECN_H
#define _PHRECN_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \valid_read(options);
  @ requires \valid(list_search_space);
  @ requires \separated(params, options, list_search_space);
  @ requires params->cmd_run == \null || valid_read_string(params->cmd_run);
  @ requires valid_read_string(params->recup_dir);
  @*/
int photorec(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space);
#ifdef HAVE_NCURSES
void interface_file_select_ncurses(file_enable_t *files_enable);
void interface_options_photorec_ncurses(struct ph_options *options);
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
