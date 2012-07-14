/*

    File: godmode.h

    Copyright (C) 1998-2004 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef __cplusplus
extern "C" {
#endif

typedef enum part_offset part_offset_t;
int interface_recovery(disk_t *disk_car, const list_part_t * list_part_org, const int verbose, const int dump_ind, const int align, const int ask_part_order, const unsigned int expert, char **current_cmd);
void only_one_bootable( list_part_t *list_part, list_part_t *part_boot);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
