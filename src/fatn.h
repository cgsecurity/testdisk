
/*

    File: fatn.h

    Copyright (C) 1998-2004,2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifndef _FATN_H
#define _FATN_H
#ifdef __cplusplus
extern "C" {
#endif

int dump_fat_info_ncurses(const struct fat_boot_sector*fh1, const upart_type_t upart_type, const unsigned int sector_size);
int dump_2fat_info_ncurses(const struct fat_boot_sector*fh1, const struct fat_boot_sector*fh2, const upart_type_t upart_type, const unsigned int sector_size);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
