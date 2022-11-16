/*

    File: partxbox.c

    Copyright (C) 2005 Christophe GRENIER <grenier@cgsecurity.org>
    Some information has been found in xbox-fdisk software
  
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
#ifndef _PARTXBOX_H
#define _PARTXBOX_H
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(SINGLE_PARTITION_TYPE) || defined(SINGLE_PARTITION_XBOX)

struct xbox_partition
{
	char unk1[0x600];
	char magic[4];
	uint32_t bootnbr;
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires valid_disk(disk_car);
  @ requires \valid_read(disk_car);
  @ requires valid_list_part(list_part);
  @ requires \valid(current_cmd);
  @ requires separation: \separated(disk_car, list_part, current_cmd, *current_cmd);
  @ requires valid_read_string(*current_cmd);
  @*/
// ensures  valid_list_part(\result);
// ensures  valid_read_string(*current_cmd);
list_part_t *add_partition_xbox_cli(const disk_t *disk_car,list_part_t *list_part, char **current_cmd);

#endif
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
