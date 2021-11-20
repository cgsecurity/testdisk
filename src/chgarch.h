
/*

    File: chgarch.h

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _CHGARCH_H
#define _CHGARCH_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(current_cmd);
  @ requires \valid(disk);
  @ requires \separated(disk, current_cmd);
  @ requires valid_disk(disk);
  @ requires current_cmd == \null || valid_read_string(*current_cmd);
  @ ensures  current_cmd == \null || valid_read_string(*current_cmd);
  @ ensures  valid_disk(disk);
  @*/
int change_arch_type_cli(disk_t *disk, const int verbose, char**current_cmd);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
