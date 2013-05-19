/*

    File: hdaccess.h

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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


void hd_update_geometry(disk_t *disk_car, const int verbose);
void hd_update_all_geometry(const list_disk_t * list_disk, const int verbose);
list_disk_t *hd_parse(list_disk_t *list_disk, const int verbose, const int testdisk_mode);
disk_t *file_test_availability(const char *device, const int verbose, const int testdisk_mode);
void update_disk_car_fields(disk_t *disk_car);
void init_disk(disk_t *disk);
void generic_clean(disk_t *disk);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
