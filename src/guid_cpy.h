/*

    File: guid_cpy.c

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

#ifndef _GUID_CPY_H
#define _GUID_CPY_H
/*@ requires \valid(dst);
  @ requires \valid_read(src);
  @ requires separation:
  @   \separated(((char *)dst)+(0..sizeof(efi_guid_t)-1),((char *)src)+(0..sizeof(efi_guid_t)-1));
  @ assigns ((char*)dst)[0..sizeof(efi_guid_t) - 1];
  @*/
// assigns ((char*)dst)[0..sizeof(efi_guid_t) - 1] \from ((char*)src)[0..sizeof(efi_guid_t)-1];
// ensures copied_contents: memcmp{Post,Pre}((char*)dst,(char*)src,sizeof(efi_guid_t)) == 0;
static inline void guid_cpy (efi_guid_t *dst, const efi_guid_t *src)
{
  memcpy(dst, src, sizeof(efi_guid_t));
}
#endif
