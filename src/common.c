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

#ifdef DJGPP
static inline unsigned char convert_char_dos(unsigned char car)
{
  if(car<0x20)
    return '_';
  switch(car)
  {
    /* Forbidden */
    case '<':
    case '>':
    case ':':
    case '"':
    /* case '/': subdirectory */
    case '\\':
    case '|':
    case '?':
    case '*':
    /* Not recommanded */
    case '[':
    case ']':
    case ';':
    case ',':
    case '+':
    case '=':
      return '_';
  }
  /* 'a' */
  if(car>=224 && car<=230)      
    return 'a';
  /* 'c' */
  if(car==231)
    return 'c';
  /* 'e' */
  if(car>=232 && car<=235)
    return 'e';
  /* 'i' */
  if(car>=236 && car<=239)
    return 'n';
  /* n */
  if(car==241)
    return 'n';
  /* 'o' */
  if((car>=242 && car<=246) || car==248)
    return 'o';
  /* 'u' */
  if(car>=249 && car<=252)
    return 'u';
  /* 'y' */
  if(car>=253)
    return 'y';
  return car;
}

static unsigned int filename_convert_dos(char *dst, const char*src, const unsigned int n)
{
  unsigned int i;
  for(i=0;i<n-1 && src[i]!='\0';i++)
    dst[i]=convert_char_dos(src[i]);
  while(i>0 && (dst[i-1]==' '||dst[i-1]=='.'))
    i--;
  if(i==0 && (dst[i]==' '||dst[i]=='.'))
    dst[i++]='_';
  dst[i]='\0';
  return i;
}
#endif

#if defined(__CYGWIN__) || defined(__MINGW32__)
static inline unsigned char convert_char_win(unsigned char car)
{
  if(car<0x20)
    return '_';
  switch(car)
  {
    /* Forbidden */
    case '<':
    case '>':
    case ':':
    case '"':
    /* case '/': subdirectory */
    case '\\':
    case '|':
    case '?':
    case '*':
    /* Not recommanded */
    case '[':
    case ']':
    case ';':
    case ',':
    case '+':
    case '=':
      return '_';
  }
  return car;
}

static unsigned int filename_convert_win(char *dst, const char*src, const unsigned int n)
{
  unsigned int i;
  for(i=0;i<n-1 && src[i]!='\0';i++)
    dst[i]=convert_char_win(src[i]);
  while(i>0 && (dst[i-1]==' '||dst[i-1]=='.'))
    i--;
  if(i==0 && (dst[i]==' '||dst[i]=='.'))
    dst[i++]='_';
  dst[i]='\0';
  return i;
}
#endif

#if defined(__APPLE__)
static unsigned int filename_convert_mac(char *dst, const char*src, const unsigned int n)
{
  unsigned int i,j;
  const unsigned char *p; 	/* pointers to actual position in source buffer */
  unsigned char *q;	/* pointers to actual position in destination buffer */
  p=(const unsigned char *)src;
  q=(unsigned char *)dst;
  for(i=0,j=0; (*p)!='\0' && i<n; i++)
  {
    if((*p & 0x80)==0x00)
    {
      *q++=*p++;
      j++;
    }
    else if((*p & 0xe0)==0xc0 && (*(p+1) & 0xc0)==0x80)
    {
      *q++=*p++;
      *q++=*p++;
      j+=2;
    }
    else if((*p & 0xf0)==0xe0 && (*(p+1) & 0xc0)==0x80 && (*(p+2) & 0xc0)==0x80)
    {
      *q++=*p++;
      *q++=*p++;
      *q++=*p++;
      j+=3;
    }
    else
    {
      *q++='_';
      p++;
      j++;
    }
  }
  *q='\0';
  return j;
}
#endif

char *gen_local_filename(const char *dir, const char*src)
{
  int l1=strlen(dir);
  int l2=(src==NULL?0:strlen(src));
  char *dst=(char *)MALLOC(l1+l2+1);
#if defined(DJGPP)
  l1=filename_convert_dos(dst, dir, l1+1);
  if(src!=NULL)
    filename_convert_dos(dst+l1, src, l2+1);
  if(dir[0]!='\0' && dir[1]==':')
    dst[1]=':';
#elif defined(__CYGWIN__) || defined(__MINGW32__)
  l1=filename_convert_win(dst, dir, l1+1);
  if(src!=NULL)
    filename_convert_win(dst+l1, src, l2+1);
  if(dir[0]!='\0' && dir[1]==':')
    dst[1]=':';
#elif defined(__APPLE__)
  l1=filename_convert_mac(dst, dir, l1+1);
  if(src!=NULL)
    filename_convert_mac(dst+l1, src, l2+1);
#else
  memcpy(dst, dir, l1);
  if(src!=NULL)
    memcpy(dst+l1, src,l2+1);
#endif
  return dst;
}

void create_dir(const char *dir_name, const unsigned int is_dir_name)
{
  /* create all sub-directories */
  char *pos;
  char *path=strdup(dir_name);
  if(path==NULL)
    return;
  pos=path+1;
  do
  {
    strcpy(path,dir_name);
    pos=strchr(pos+1,'/');
    if(pos!=NULL)
      *pos='\0';
    if(pos!=NULL || is_dir_name!=0)
    {
#ifdef __CYGWIN__
      if(memcmp(&path[1],":/cygdrive",10)!=0)
#endif
#ifdef HAVE_MKDIR
#ifdef __MINGW32__
      mkdir(path);
#else
      mkdir(path, 0775);
#endif
#else
#warning You need a mkdir function!
#endif
    }
  } while(pos!=NULL);
  free(path);
}
