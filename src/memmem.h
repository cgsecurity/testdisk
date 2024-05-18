/*

    File: memmem.h

    Copyright (C) 2005-2007 Christophe GRENIER <grenier@cgsecurity.org>
    Copyright (C) 1991,92,93,94,96,97,98,2000,2004 Free Software Foundation, Inc.
    The function has been copied from glibc 2.7

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
#ifndef _MEMMEM_H
#define _MEMMEM_H

/*@
  @ requires \valid_read((const char *)haystack+(0..haystack_len-1));
  @ requires \valid_read((const char *)needle+(0..needle_len-1));
  @ assigns  \nothing;
  @ ensures result_null_or_in_haystack:
  @   \result == \null
  @   || (\subset((char *)\result, (char *)haystack+(0..haystack_len-needle_len)) && \valid_read((char *)\result));
  @*/
static inline const void *td_memmem(const void *haystack, const unsigned int haystack_len, const void *needle, const unsigned int needle_len)
{
  const char *begin;
  const char *const last_possible = (const char *) haystack + haystack_len - needle_len;

  if (needle_len == 0)
    /* The first occurrence of the empty string is deemed to occur at
       the beginning of the string.  */
    /*@ assert (\subset((char *)haystack, (char *)haystack+(0..haystack_len-needle_len)) && \valid_read((char *)haystack)); */
    return (const void *) haystack;

  /* Sanity check, otherwise the loop might search through the whole
     memory.  */
  if (haystack_len < needle_len)
    return NULL;

  /*@
    @ loop invariant \valid_read(begin);
    @ loop invariant \subset(begin, (char *)haystack+(0..haystack_len-needle_len+1));
    @ loop assigns begin;
    @ loop variant last_possible - begin;
    @*/
  for (begin = (const char *) haystack; begin <= last_possible; ++begin)
  {
    if (begin[0] == ((const char *) needle)[0] &&
        !memcmp ((const void *) &begin[1],
                 (const void *) ((const char *) needle + 1),
                 needle_len - 1))
    {
      /*@ assert (\subset(begin, (char *)haystack+(0..haystack_len-needle_len)) && \valid_read(begin)); */
      return (const void *) begin;
    }
  }
  return NULL;
}
#endif
