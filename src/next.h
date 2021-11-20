/*

    File: next.h

    Copyright (C) 2020 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifndef _NEXT_H
#define _NEXT_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @*/
void search_location_init(const disk_t *disk_car, const unsigned int location_boundary, const int fast_mode);
uint64_t search_location_update(const uint64_t location);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
