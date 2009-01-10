/*

    File: hdwin32.h

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
#ifndef _HDWIN32_H
#define _HDWIN32_H
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__CYGWIN__) || defined(__MINGW32__)
void file_win32_disk_get_model(HANDLE handle, disk_t *dev, const int verbose);
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
