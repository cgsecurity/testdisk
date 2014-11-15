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
#include <ctype.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef __MINGW32__
#ifdef HAVE_IO_H
#include <io.h>
#endif
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <assert.h>
#include "types.h"
#include "common.h"
#include "log.h"

static int32_t secwest=0;

static unsigned int up2power_aux(const unsigned int number);

/* coverity[+alloc] */
void *MALLOC(size_t size)
{
  void *res;
  assert(size>0);
  /* Warning, memory leak checker must be posix_memalign/memalign aware, otherwise  *
   * reports may look strange. Aligned memory is required if the buffer is *
   * used for read/write operation with a file opened with O_DIRECT        */
#if defined(HAVE_POSIX_MEMALIGN)
  if(size>=512)
  {
    if(posix_memalign(&res,4096,size)==0)
    {
      memset(res,0,size);
      return res;
    }
  }
#elif defined(HAVE_MEMALIGN)
  if(size>=512)
  {
    if((res=memalign(4096, size))!=NULL)
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

#ifndef HAVE_STRCASESTR
char * strcasestr (const char *haystack, const char *needle)
{
  const char *p, *startn = NULL, *np = NULL;
  for (p = haystack; *p; p++)
  {
    if (np)
    {
      if (toupper(*p) == toupper(*np))
      {
	if (!*++np)
	  return startn;
      }
      else
	np = NULL;
    }
    else if (toupper(*p) == toupper(*needle))
    {
      np = needle + 1;
      startn = p;
    }
  }
  return NULL;
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

void set_part_name(partition_t *partition, const char *src, const unsigned int max_size)
{
  unsigned int i;
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  partition->fsname[i]='\0';
}

void set_part_name_chomp(partition_t *partition, const unsigned char *src, const unsigned int max_size)
{
  unsigned int i;
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  while(i>0 && src[i-1]==' ')
    i--;
  partition->fsname[i]='\0';
}

char* strip_dup(char* str)
{
  unsigned int i;
  char *end;
  while(isspace(*str))
    str++;
  end=str;
  for (i = 0; str[i] != 0; i++)
    if (!isspace (str[i]))
      end=&str[i];
  if(str == end)
    return NULL;
  *(end+1) = 0;
  return strdup (str);
}

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since 1 1 70). */

int date_dos2unix(const unsigned short f_time, const unsigned short f_date)
{
  static const int day_n[] = { 0,31,59,90,120,151,181,212,243,273,304,334,0,0,0,0 };
  /* JanFebMarApr May Jun Jul Aug Sep Oct Nov Dec */

  int month,year,secs;

  /* first subtract and mask after that... Otherwise, if
     f_date == 0, bad things happen */
  month = ((f_date >> 5) - 1) & 15;
  year = f_date >> 9;
  secs = (f_time & 31)*2+60*((f_time >> 5) & 63)+(f_time >> 11)*3600+86400*
    ((f_date & 31)-1+day_n[month]+(year/4)+year*365-((year & 3) == 0 &&
      month < 2 ? 1 : 0)+3653);
  /* days since 1.1.70 plus 80's leap day */
  return secs+secwest;
}

void set_secwest(void)
{
  const time_t t = time(NULL);
  const struct  tm *tmptr = localtime(&t);
#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  if(tmptr)
    secwest = -1 * tmptr->tm_gmtoff;
  else
    secwest = 0;
#elif defined (DJGPP) || defined(__ANDROID__)
  secwest = 0;
#else
#if defined (__CYGWIN__)
  secwest = _timezone;
#else
  secwest = timezone;
#endif
  /* account for daylight savings */
  if (tmptr && tmptr->tm_isdst)
    secwest -= 3600;
#endif
}

/**
 * td_ntfs2utc - Convert an NTFS time to Unix time
 * @time:  An NTFS time in 100ns units since 1601
 *
 * NTFS stores times as the number of 100ns intervals since January 1st 1601 at
 * 00:00 UTC.  This system will not suffer from Y2K problems until ~57000AD.
 *
 * Return:  n  A Unix time (number of seconds since 1970)
 */
#define NTFS_TIME_OFFSET ((int64_t)(369 * 365 + 89) * 24 * 3600 * 10000000)
time_t td_ntfs2utc (int64_t ntfstime)
{
  return (ntfstime - (NTFS_TIME_OFFSET)) / 10000000;
}
