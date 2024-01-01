/*

    File: crc.h

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

#ifndef _CRC_H
#define _CRC_H
#ifdef __cplusplus
extern "C" {
#endif

#if 0
uint32_t* make_crc32_table(uint32_t poly);
unsigned int get_crc32_gen(const unsigned char *s, const unsigned int len, const uint32_t seed, const uint32_t *crctab);
#endif
/*@
  @ requires \valid_read((const char *)s + (0 .. len-1));
  @ requires \initialized((const char *)s + (0 .. len-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
unsigned int get_crc32(const void *s, const unsigned int len, const uint32_t seed);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
