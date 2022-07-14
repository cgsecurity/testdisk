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
#ifndef _HDACCESS_H
#define _HDACCESS_H
#ifdef __cplusplus
extern "C" {
#endif
/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires disk_car->sector_size > 0;
  @ requires disk_car->geom.heads_per_cylinder > 0;
  @ requires \valid_function(disk_car->pread);
  @ decreases 0;
  @ ensures  valid_disk(disk_car);
  @*/
void hd_update_geometry(disk_t *disk_car, const int verbose);

/*@
  @ requires valid_list_disk(list_disk);
  @*/
void hd_update_all_geometry(const list_disk_t * list_disk, const int verbose);

/*@
  @ requires valid_list_disk(list_disk);
  @ ensures  valid_list_disk(\result);
  @*/
list_disk_t *hd_parse(list_disk_t *list_disk, const int verbose, const int testdisk_mode);

/*@
  @ requires valid_read_string(device);
  @ ensures  \result!=\null ==> (0 < \result->geom.cylinders < 0x2000000000000);
  @ ensures  \result!=\null ==> (0 < \result->geom.heads_per_cylinder <= 255);
  @ ensures  \result!=\null ==> (0 < \result->geom.sectors_per_head <= 63);
  @ ensures  \result==\null || valid_disk(\result);
  @*/
disk_t *file_test_availability(const char *device, const int verbose, const int testdisk_mode);

/*@
  @ requires \valid(disk_car);
  @ requires valid_disk(disk_car);
  @ requires 0 < disk_car->geom.heads_per_cylinder;
  @ requires 0 < disk_car->geom.sectors_per_head;
  @ requires 0 < disk_car->sector_size;
  @ ensures 0 < disk_car->geom.cylinders < 0x2000000000000;
  @ ensures  valid_disk(disk_car);
  @ assigns disk_car->disk_real_size, disk_car->geom.cylinders, disk_car->disk_size;
  @*/
void update_disk_car_fields(disk_t *disk_car);

/*@
  @ requires \valid(disk);
  @ ensures disk->autodetect == 0;
  @ ensures disk->disk_size == 0;
  @ ensures disk->user_max == 0;
  @ ensures disk->native_max == 0;
  @ ensures disk->dco == 0;
  @ ensures disk->offset == 0;
  @ ensures disk->rbuffer == NULL;
  @ ensures disk->wbuffer == NULL;
  @ ensures disk->rbuffer_size == 0;
  @ ensures disk->wbuffer_size == 0;
  @ ensures disk->model == NULL;
  @ ensures disk->serial_no == NULL;
  @ ensures disk->fw_rev == NULL;
  @ ensures disk->write_used == 0;
  @ ensures disk->description_txt[0] == '\0';
  @ ensures disk->unit == UNIT_CHS;
  @ assigns disk->autodetect, disk->disk_size, disk->user_max, disk->native_max, disk->dco, disk->offset;
  @ assigns disk->rbuffer, disk->wbuffer, disk->rbuffer_size, disk->wbuffer_size;
  @ assigns disk->model, disk->serial_no, disk->fw_rev, disk->write_used;
  @ assigns disk->description_txt[0], disk->unit;
  @*/
void init_disk(disk_t *disk);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \freeable(disk);
  @ requires valid_disk(disk);
  @*/
void generic_clean(disk_t *disk);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
