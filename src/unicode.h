/*

    File: unicode.h

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _UNICODE_H
#define _UNICODE_H
#ifdef __cplusplus
extern "C" {
#endif

/*@
  @ requires \valid(to + ( 0 .. len-1));
  @ requires \valid_read(from + ( 0 .. len-1));
  @ requires \separated(to + (..), from + (..));
  @ terminates \true;
  @ assigns to[0 .. len-1];
  @*/
unsigned int UCSle2str(char *to, const uint16_t *from, const unsigned int len);

/*@
  @ requires \valid(to + ( 0 .. len-1));
  @ requires \valid_read(from + ( 0 .. len-1));
  @ requires \separated(to + (..), from + (..));
  @ terminates \true;
  @ assigns to[0 .. len-1];
  @*/
unsigned int str2UCSle(uint16_t *to, const char *from, const unsigned int len);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
