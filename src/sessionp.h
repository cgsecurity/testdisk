/*

    File: sessionp.h

    Copyright (C) 2006-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _SESSIONP_H
#define _SESSIONP_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(cmd_device);
  @ requires \valid(current_cmd);
  @ requires valid_list_search_space(list_free_space);
  @ requires \separated(cmd_device, current_cmd, list_free_space);
  @*/
// ensures  *cmd_device==\null  || valid_read_string(*cmd_device);
// ensures  *current_cmd==\null || valid_read_string(*current_cmd);
// ensures  valid_list_search_space(list_free_space);
int session_load(char **cmd_device, char **current_cmd, alloc_data_t *list_free_space);

/*@
  @ requires \valid_read(list_free_space);
  @ requires valid_ph_param(params);
  @ requires \valid_read(options);
  @ requires \separated(list_free_space, params, options);
  @ ensures  valid_ph_param(params);
  @*/
int session_save(const alloc_data_t *list_free_space, const struct ph_param *params, const struct ph_options *options);

/*@
  @ requires \valid_read(list_free_space);
  @ requires params==\null || \valid_read(params);
  @ requires options==\null || \valid_read(options);
  @*/
time_t regular_session_save(alloc_data_t *list_free_space, struct ph_param *params,  const struct ph_options *options, time_t current_time);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
