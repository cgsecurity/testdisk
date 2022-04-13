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

#ifdef DISABLED_FOR_FRAMAC
#undef HAVE_POSIX_MEMALIGN
#undef HAVE_MEMALIGN
#undef HAVE_NCURSES
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
#ifdef DISABLED_FOR_FRAMAC
  if((res=calloc(1,size))==NULL)
  {
    exit(EXIT_FAILURE);
  }
#else
  if((res=malloc(size))==NULL)
  {
#ifndef DISABLED_FOR_FRAMAC
    log_critical("\nCan't allocate %lu bytes of memory.\n", (long unsigned)size);
    log_close();
#endif
    exit(EXIT_FAILURE);
  }
  memset(res,0,size);
#endif
  /*@ assert \valid((char *)res + (0 .. size - 1)); */
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

#if ! defined(HAVE_LOCALTIME_R) && ! defined(__MINGW32__) && !defined(DISABLED_FOR_FRAMAC)
struct tm *localtime_r(const time_t *timep, struct tm *result)
{
  return localtime(timep);
}
#endif

/*@
  @ decreases number;
  @ assigns \nothing;
  @*/
static unsigned int up2power_aux(const unsigned int number)
{
  if(number==0)
	return 0;
  else
	return(1+up2power_aux(number/2));
}

unsigned int up2power(const unsigned int number)
{
  if(number==0)
    return 1;
  return (1<<up2power_aux(number-1));
}

void set_part_name(partition_t *partition, const char *src, const unsigned int max_size)
{
  unsigned int i;
  /*@
    @ loop assigns i, partition->fsname[i];
    @*/
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  partition->fsname[i]='\0';
}

void set_part_name_chomp(partition_t *partition, const unsigned char *src, const unsigned int max_size)
{
  unsigned int i;
  /*@
    @ loop assigns i, partition->fsname[i];
    @*/
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  /*@
    @ loop assigns i;
    @*/
  while(i>0 && src[i-1]==' ')
    i--;
  partition->fsname[i]='\0';
}

char* strip_dup(char* str)
{
  unsigned int i;
  char *end;
  /*@
    @ loop assigns str;
    @*/
  while(isspace(*str))
    str++;
  end=str;
  /*@
    @ loop assigns i, end;
    @*/
  for (i = 0; str[i] != 0; i++)
    if (!isspace (str[i]))
      end=&str[i];
  if(str == end)
    return NULL;
  *(end+1) = 0;
  return strdup (str);
}

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since 1 1 70). */
/*
 * The epoch of FAT timestamp is 1980.
 *     :  bits :     value
 * date:  0 -  4: day	(1 -  31)
 * date:  5 -  8: month	(1 -  12)
 * date:  9 - 15: year	(0 - 127) from 1980
 * time:  0 -  4: sec	(0 -  29) 2sec counts
 * time:  5 - 10: min	(0 -  59)
 * time: 11 - 15: hour	(0 -  23)
 */
#define SECS_PER_MIN	60
#define SECS_PER_HOUR	(60 * 60)
#define SECS_PER_DAY	(SECS_PER_HOUR * 24)
/* days between 1.1.70 and 1.1.80 (2 leap days) */
#define DAYS_DELTA	(365 * 10 + 2)
/* 120 (2100 - 1980) isn't leap year */
#define YEAR_2100	120
#define IS_LEAP_YEAR(y)	(!((y) & 3) && (y) != YEAR_2100)

time_t date_dos2unix(const unsigned short f_time, const unsigned short f_date)
{
  static const unsigned int days_in_year[] = { 0, 0,31,59,90,120,151,181,212,243,273,304,334,0,0,0 };
  /* JanFebMarApr May Jun Jul Aug Sep Oct Nov Dec */

  unsigned long int day,leap_day,month,year,days;
  unsigned long int secs;
  year  = f_date >> 9;
  /*@ assert 0 <= year <= 127; */
  month = td_max(1, (f_date >> 5) & 0xf);
  /*@ assert 1 <= month <= 15; */
  day   = td_max(1, f_date & 0x1f) - 1;
  /*@ assert 0 <= day <= 30; */

  if (year > YEAR_2100)		/* 2100 isn't leap year */
  {
    /*@ assert year > YEAR_2100; */
    leap_day = (year + 3) / 4;
    /*@ assert (YEAR_2100 + 3)/4 < leap_day <= 32; */
    leap_day--;
    /*@ assert (YEAR_2100 + 3)/4 <= leap_day < 32; */
  }
  else
  {
    /*@ assert year <= YEAR_2100; */
    leap_day = (year + 3) / 4;
    /*@ assert 0 <= leap_day <= (YEAR_2100 + 3)/4; */
  }
  /*@ assert 0 <= leap_day < 32; */
  if (IS_LEAP_YEAR(year) && month > 2)
    leap_day++;
  /*@ assert 0 <= leap_day <= 32; */
  days = days_in_year[month];
  /*@ assert days <= 334; */
  days += year * 365 + leap_day + day + DAYS_DELTA;

  secs = (f_time & 0x1f)<<1;
  secs += ((f_time >> 5) & 0x3f) * SECS_PER_MIN;
  secs += (f_time >> 11)* SECS_PER_HOUR;
  secs += days * SECS_PER_DAY;

  return secs+secwest;
}

void set_secwest(void)
{
  const time_t t = time(NULL);
#if defined(__MINGW32__) || defined(DISABLED_FOR_FRAMAC)
  const struct  tm *tmptr = localtime(&t);
#else
  struct  tm tmp;
  const struct  tm *tmptr = localtime_r(&t,&tmp);
#endif
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
  if(ntfstime < NTFS_TIME_OFFSET)
    return 0;
  return (ntfstime - NTFS_TIME_OFFSET) / 10000000;
}

int check_command(char **current_cmd, const char *cmd, const size_t n)
{
  const int res=strncmp(*current_cmd, cmd, n);
  if(res==0)
  {
#ifdef DISABLED_FOR_FRAMAC
    const char *src=*current_cmd;
    unsigned int i;
    /*@
      @ loop invariant valid_read_string(src);
      @ loop assigns i, src;
      @*/
    for(i=0; i<n && src[0]!='\0'; i++)
    {
      /*@ assert valid_read_string(src); */
      /*@ assert src[0]!= '\0'; */
      src++;
      /*@ assert valid_read_string(src); */
    }
    *current_cmd=src;
#else
    (*current_cmd)+=n;
#endif
    /*@ assert valid_read_string(*current_cmd); */
    return 0;
  }
  /*@ assert valid_read_string(*current_cmd); */
  return res;
}

void skip_comma_in_command(char **current_cmd)
{
  /*@
    loop invariant valid_read_string(*current_cmd);
    loop assigns *current_cmd;
    */
  while(*current_cmd[0]==',')
  {
    (*current_cmd)++;
  }
  /*@ assert valid_read_string(*current_cmd); */
}

uint64_t get_int_from_command(char **current_cmd)
{
  uint64_t tmp=0;
  /*@
    loop invariant valid_read_string(*current_cmd);
    loop assigns *current_cmd, tmp;
    */
  while(*current_cmd[0] >='0' && *current_cmd[0] <= '9')
  {
    tmp = tmp * 10 + *current_cmd[0] - '0';
    (*current_cmd)++;
  }
  return tmp;
}
