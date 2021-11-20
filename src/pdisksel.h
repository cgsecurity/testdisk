/*

    File: pdisksel.h

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
#ifndef _PDISKSEL_H
#define _PDISKSEL_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires valid_read_string(cmd_device);
  @ requires \valid_read(list_disk);
  @ requires valid_disk(list_disk->disk);
  @ requires \valid(list_search_space);
  @ requires \separated(cmd_device, list_disk, list_search_space);
  @ ensures  valid_disk(\result);
  @*/
disk_t *photorec_disk_selection_cli(const char *cmd_device, const list_disk_t *list_disk, alloc_data_t *list_search_space);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
