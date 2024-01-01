/*

    File: utfsize.h

    Copyright (C) 2009-2021 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _UTFSIZE_H
#define _UTFSIZE_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires buf_len> 0;
  @ requires \valid_read(buffer+(0..buf_len-1));
  @ terminates \true;
  @ ensures 0 <= \result <= buf_len;
  @ assigns \nothing;
  @*/
int UTFsize(const unsigned char *buffer, const unsigned int buf_len);
#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
