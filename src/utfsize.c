/*

    File: utfsize.c

    Copyright (C) 2021 Christophe GRENIER <grenier@cgsecurity.org>

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_txt) || defined(SINGLE_FORMAT_win)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "log.h"
#include "utfsize.h"

int UTFsize(const unsigned char *buffer, const unsigned int buf_len)
{
  const unsigned char *p=buffer;	/* pointers to actual position in source buffer */
  unsigned int i=0;
  /*@
    @ loop invariant 0 <= i < buf_len + 3;
    @ loop invariant p == buffer + i;
    @ loop assigns i, p;
    @ loop variant buf_len - 1 - i;
    @*/
  while(i<buf_len)
  {
    /*@ assert i < buf_len; */
    /*@ assert p == buffer + i; */
    const unsigned char c=*p;
    if(c=='\0')
      return i;
    /* Reject some invalid UTF-8 sequences */
    if(c==0xc0 || c==0xc1 || c==0xf7 || c>=0xfd)
      return i;
    /*@ assert i + 1 >= buf_len || \valid_read(p+1); */
    /*@ assert i + 2 >= buf_len || \valid_read(p+2); */
    if((c & 0xf0)==0xe0 &&
	(i+1 >= buf_len || (*(p+1) & 0xc0)==0x80) &&
	(i+2 >= buf_len || (*(p+2) & 0xc0)==0x80))
    { /* UTF8 l=3 */
#ifdef DEBUG_TXT
      log_info("UTFsize i=%u l=3\n", i);
#endif
      p+=3;
      i+=3;
    }
    else if((c & 0xe0)==0xc0 &&
	(i+1 >= buf_len || (*(p+1) & 0xc0)==0x80))
    { /* UTF8 l=2 */
#ifdef DEBUG_TXT
      log_info("UTFsize i=%u l=2\n", i);
#endif
      p+=2;
      i+=2;
    }
    else
    { /* Ascii UCS */
#ifdef DEBUG_TXT
      log_info("UTFsize i=%u l=1 ? *p=%c\n", i, c);
#endif
      switch(c)
      {
	case 0x00:
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x0b:
	case 0x0c:
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1a:
	case 0x1b:
	case 0x1c:
	case 0x1d:
	case 0x1e:
	case 0x1f:
	case 0x7f:
	  return i;
      }
      p++;
      i++;
    }
  }
  return (i<buf_len?i:buf_len);
}
#endif
