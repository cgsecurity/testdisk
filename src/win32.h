/*

    File: win32.h

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _WIN32_H
#define _WIN32_H
#ifdef __cplusplus
extern "C" {
#endif
#if defined(__CYGWIN__) || defined(__MINGW32__)
disk_t *file_test_availability_win32(const char *device, const int verbose, const int testdisk_mode);
unsigned int disk_get_sector_size_win32(HANDLE handle, const char *device, const int verbose);
uint64_t disk_get_size_win32(HANDLE handle, const char *device, const int verbose);
void disk_get_geometry_win32(CHSgeometry_t *geom, HANDLE handle, const char *device, const int verbose);
#endif
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
