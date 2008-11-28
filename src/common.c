/*

    File: common.c

    Copyright (C) 1998-2006 Christophe GRENIER <grenier@cgsecurity.org>
  
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdarg.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include <ctype.h>      /* tolower */
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef __MINGW32__
#ifdef HAVE_IO_H
#include <io.h>
#endif
#endif
#include "intrf.h"
#include "log.h"

static unsigned int up2power_aux(const unsigned int number);

void *MALLOC(size_t size)
{
  void *res;
  if(size<=0)
  {
    log_critical("Try to allocate 0 byte of memory\n");
    log_close();
    exit(EXIT_FAILURE);
  }
#if defined(HAVE_POSIX_MEMALIGN)
  if(size>=512)
  {
    /* Warning, memory leak checker must be posix_memalign aware, otherwise  *
     * reports may look strange. Aligned memory is required if the buffer is *
     * used for read/write operation with a file opened with O_DIRECT        */
    if(posix_memalign(&res,4096,size)==0)
    {
      memset(res,0,size);
      return res;
    }
  }
#endif
  if((res=malloc(size))==NULL)
  {
    log_critical("\nCan't allocate %lu bytes of memory.\n", (long unsigned)size);
    log_close();
    exit(EXIT_FAILURE);
  }
  memset(res,0,size);
  return res;
}

#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t size, const char *format, ...)
{
  int res;
  va_list ap;
  va_start(ap,format);
  res=vsnprintf(str, size, format, ap);
  va_end(ap);
  return res;
}
#endif

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
  return vsprintf(str,format,ap);
}
#endif

#ifndef HAVE_STRNCASECMP
/** Case-insensitive, size-constrained, lexical comparison. 
 *
 * Compares a specified maximum number of characters of two strings for 
 * lexical equivalence in a case-insensitive manner.
 *
 * @param[in] s1 - The first string to be compared.
 * @param[in] s2 - The second string to be compared.
 * @param[in] len - The maximum number of characters to compare.
 * 
 * @return Zero if at least @p len characters of @p s1 are the same as
 *    the corresponding characters in @p s2 within the ASCII printable 
 *    range; a value less than zero if @p s1 is lexically less than
 *    @p s2; or a value greater than zero if @p s1 is lexically greater
 *    than @p s2.
 *
 * @internal
 */
int strncasecmp(const char * s1, const char * s2, size_t len)
{
  while (*s1 && (*s1 == *s2 || tolower(*s1) == tolower(*s2)))
  {
    len--;
    if (len == 0) 
      return 0;
    s1++;
    s2++;
  }
  return (int)*(const unsigned char *)s1 - (int)*(const unsigned char *)s2;
}
#endif

unsigned int up2power(const unsigned int number)
{
  /* log_trace("up2power(%u)=>%u\n",number, (1<<up2power_aux(number-1))); */
  if(number==0)
    return 1;
  return (1<<up2power_aux(number-1));
}

static unsigned int up2power_aux(const unsigned int number)
{
  if(number==0)
	return 0;
  else
	return(1+up2power_aux(number/2));
}

void set_part_name(partition_t *partition,const char *src,const int max_size)
{
  int i;
  for(i=0;(i<max_size) && (src[i]!=(char)0);i++)
    partition->fsname[i]=src[i];
  partition->fsname[i--]='\0';
}


