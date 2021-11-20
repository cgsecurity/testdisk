/*

    File: phcli.h

    Copyright (C) 2014 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _PHCLI_H
#define _PHCLI_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(list_part);
  @ requires valid_list_part(list_part);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires valid_disk(params->disk);
  @ requires \valid_function(params->disk->description);
  @ requires \valid(options);
  @ requires \valid(list_search_space);
  @ requires valid_read_string(params->cmd_run);
  @ requires \valid_function(params->disk->description);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(&need_to_stop, list_part, params, options, list_search_space);
  @*/
// ensures  valid_list_search_space(list_search_space);
int menu_photorec_cli(list_part_t *list_part, struct ph_param *params, struct ph_options *options, alloc_data_t*list_search_space);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
