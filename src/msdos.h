/*

    File: msdos.h

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

struct info_disk_struct
{
  unsigned int disk;
  CHSgeometry_t geo_phys;	/* CHS low level */
  int mode_enh;
  int bad_geometry;
};

disk_t *hd_identify(const int verbose, const unsigned int disk, const int testdisk_mode);
const char *disk_description(disk_t *disk_car);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
