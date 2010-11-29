/*

    File: parti386.h

    Copyright (C) 2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

int parti386_can_be_ext(const disk_t *disk_car, const partition_t *partition);
list_part_t *add_partition_i386_cli(disk_t *disk_car, list_part_t *list_part, char **current_cmd);
int recover_i386_logical(disk_t *disk, const unsigned char *buffer, partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
