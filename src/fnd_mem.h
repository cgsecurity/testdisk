/*

    File: fnd_mem.h

    Copyright (C) 2005-2007 Christophe GRENIER <grenier@cgsecurity.org>

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

static inline const unsigned char *find_in_mem(const unsigned char *haystack, const unsigned int haystack_size,
    const unsigned char *needle, const unsigned int needle_length)
{
  const unsigned char *haystack_end=haystack+haystack_size;
  while(haystack_end-haystack>=needle_length)
  {
    haystack=memchr(haystack,needle[0],haystack_end-haystack);
    if(haystack==NULL)
      return NULL;
    if(memcmp(haystack,needle,needle_length)==0)
      return haystack;
    haystack++;
  };
  return NULL;
}
