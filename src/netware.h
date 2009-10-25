/*

    File: netware.h

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

struct disk_netware
{
  char unknown;
  char magic[12];
  char unknown2[3];
  char unknown3[3]; /* 0x10 */
  int32_t nbr_sectors;
};

int check_netware(disk_t *disk_car, partition_t *partition);
int recover_netware(disk_t *disk_car, const struct disk_netware *netware_block, partition_t *partition);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
