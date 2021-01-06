/*

    File: hiddenn.h

    Copyright (C) 2008-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _HIDDENN_H
#define _HIDDENN_H
#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NCURSES
/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @*/
int interface_check_hidden_ncurses(disk_t *disk, const int hpa_dco);
#endif

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
