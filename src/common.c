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

static long secwest=0;

/* coverity[+alloc] */
void *MALLOC(size_t size)
{
  void *res;
  /*@ assert size > 0; */
#ifdef DISABLED_FOR_FRAMAC
  assert(size>0);
#endif
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
    log_critical("\nCan't allocate %lu bytes of memory.\n", (long unsigned)size);
    log_close();
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

void set_part_name(partition_t *partition, const char *src, const unsigned int max_size)
{
  unsigned int i;
  /*@
    @ loop invariant \separated(partition, src + (..));
    @ loop invariant 0 <= i < sizeof(partition->fsname);
    @ loop invariant 0 <= i <= max_size;
    @ loop invariant \initialized(partition->fsname+(0 .. i-1));
    @ loop assigns i, partition->fsname[0 .. i];
    @ loop variant sizeof(partition->fsname)-1 - i;
    @*/
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  partition->fsname[i]='\0';
  /*@ assert valid_string((char *)&partition->fsname); */
}

void set_part_name_chomp(partition_t *partition, const char *src, const unsigned int max_size)
{
  unsigned int i;
  /*@
    @ loop invariant \separated(partition, src + (..));
    @ loop invariant 0 <= i < sizeof(partition->fsname);
    @ loop invariant 0 <= i <= max_size;
    @ loop invariant \initialized(partition->fsname+(0 .. i-1));
    @ loop assigns i, partition->fsname[0 .. i];
    @ loop variant sizeof(partition->fsname)-1 - i;
    @*/
  for(i=0; i<sizeof(partition->fsname)-1 && i<max_size && src[i]!='\0'; i++)
    partition->fsname[i]=src[i];
  /*@
    @ loop invariant 0 <= i < sizeof(partition->fsname);
    @ loop invariant \initialized(partition->fsname+(0 .. i-1));
    @ loop assigns i;
    @ loop variant i;
    @*/
  while(i>0 && partition->fsname[i-1]==' ')
    i--;
  partition->fsname[i]='\0';
  /*@ assert valid_string((char *)&partition->fsname); */
}

char* strip_dup(char* str)
{
  char *end;
  char *tmp;
  /*@
    @ loop invariant valid_string(str);
    @ loop assigns str;
    @ loop variant strlen(\at(str, Pre)) - strlen(str);
    @*/
  while(isspace(*str))
    str++;
  end=str;
  /*@ assert valid_string(end); */
  /*@
    @ loop invariant valid_string(tmp);
    @ loop invariant valid_string(end);
    @ loop invariant end == str || *end != '\0';
    @ loop assigns tmp, end;
    @ loop variant strlen(str) - strlen(tmp);
    @*/
  for(tmp = str; *tmp != 0; tmp++)
    if(!isspace(*tmp))
      end=tmp;
  /*@ assert valid_string(end); */
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

/*@
  @ requires 0 <= year <= 127;
  @ terminates \true;
  @ ensures 0 <= \result <= 32;
  @ assigns \nothing;
  @*/
static unsigned int _date_get_leap_day(const unsigned long int year, const unsigned long int month)
{
  unsigned long int leap_day;
  if (year > YEAR_2100)         /* 2100 isn't leap year */
  {
    /*@ assert YEAR_2100 < year <= 127; */
    leap_day = (year + 3) / 4;
    /*@ assert leap_day <= 32; */
    leap_day--;
    /*@ assert leap_day < 32; */
  }
  else
  {
    /*@ assert year <= YEAR_2100; */
    leap_day = (year + 3) / 4;
    /*@ assert leap_day <= (YEAR_2100 + 3)/4; */
  }
  /*@ assert 0 <= leap_day < 32; */
  if (IS_LEAP_YEAR(year) && month > 2)
    leap_day++;
  /*@ assert 0 <= leap_day <= 32; */
  return leap_day;
}

/*@
  @ requires 0 <= days <= 334;
  @ requires 0 <= year <= 127;
  @ requires 0 <= leap_day <= 32;
  @ requires 0 <= day <= 30;
  @ terminates \true;
  @ ensures 0 <= \result <= 334 + 127 * 365 + 32 + 30 + DAYS_DELTA;
  @ assigns \nothing;
  @*/
static unsigned long int _date_get_days(const unsigned long int days, const unsigned long int year, const unsigned long int leap_day, const unsigned long int day)
{
  return days + year * 365 + leap_day + day + DAYS_DELTA;
}
/*@
  @ requires 0 <= seconds2 <= 31;
  @ terminates \true;
  @ ensures 0 <= \result <= 62;
  @ assigns \nothing;
  @*/
static unsigned long int _date_get_seconds(const unsigned long int seconds2)
{
  return seconds2 << 1;
}

/*@
  @ requires 0 <= m <= 0x3f;
  @ terminates \true;
  @ ensures 0 <= \result <= 0x3f * SECS_PER_MIN;
  @ assigns \nothing;
  @*/
static unsigned long int _date_min_to_seconds(const unsigned long int m)
{
  return m * SECS_PER_MIN;
}

/*@
  @ requires 0 <= h <= 0x3f;
  @ terminates \true;
  @ ensures 0 <= \result <= 0x3f * SECS_PER_HOUR;
  @ assigns \nothing;
  @*/
static unsigned long int _date_hours_to_seconds(const unsigned long int h)
{
  return h * SECS_PER_HOUR;
}

/*@
  @ requires -14*3600 <= secwest <= 12*3600;
  @ requires f_time <= 0xffffffff;
  @ requires f_date <= 0xffffffff;
  @ terminates \true;
  @ assigns \nothing;
  @*/
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
  leap_day = _date_get_leap_day(year, month);
  /*@ assert 0 <= leap_day <= 32; */
  days = days_in_year[month];
  /*@ assert 0 <= days <= 334; */
  days = _date_get_days(days, year, leap_day, day);
  /*@ assert 0 <= days <= 334 + 127 * 365 + 32 + 30 + DAYS_DELTA; */
  secs = _date_get_seconds(f_time &0x1f);
  /*@ assert secs <= 62; */
  secs += _date_min_to_seconds((f_time >> 5) & 0x3f);
  /*@ assert secs <= 0x3f * SECS_PER_MIN + 62; */
  secs += _date_hours_to_seconds(f_time >> 11);
  /*@ assert secs <= 0x3f * SECS_PER_HOUR + 0x3f * SECS_PER_MIN + 62; */
  secs += days * SECS_PER_DAY;
  /*@ assert secs <= (334 + 127 * 365 + 32 + 30 + DAYS_DELTA)* SECS_PER_DAY + 0x3f * SECS_PER_HOUR + 0x3f * SECS_PER_MIN + 62; */
#if defined(__FRAMAC__)
  return secs;
#else
  return secs+secwest;
#endif
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
#ifdef __FRAMAC__
  if(secwest < -48*3600)
  {
    secwest=0;
    return;
  }
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
    (*current_cmd)+=n;
    /*@ assert valid_read_string(*current_cmd); */
    return 0;
  }
  /*@ assert valid_read_string(*current_cmd); */
  return res;
}

void skip_comma_in_command(char **current_cmd)
{
  /*@
    @ loop invariant valid_read_string(*current_cmd);
    @ loop assigns *current_cmd;
    @ loop variant strlen(*current_cmd);
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
    @ loop invariant valid_read_string(*current_cmd);
    @ loop assigns *current_cmd, tmp;
    @ loop variant strlen(*current_cmd);
    @*/
  while(*current_cmd[0] >='0' && *current_cmd[0] <= '9')
  {
#ifdef __FRAMAC__
    const unsigned int v=*current_cmd[0] - '0';
    /*@ assert 0 <= v <= 9; */
    if(tmp >= UINT64_MAX / 10)
      return tmp;
    /** assert tmp < UINT64_MAX / 10; */
    tmp *= 10;
    /** assert tmp <= UINT64_MAX - 10; */
    tmp += v;
#else
    tmp = tmp * 10 + (*current_cmd[0] - '0');
#endif
    (*current_cmd)++;
  }
  return tmp;
}
