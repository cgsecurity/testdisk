/*

    File: file_pdf.c

    Copyright (C) 1998-2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_pdf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* free */
#endif
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "memmem.h"
#include "common.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_pdf(file_stat_t *file_stat);

const file_hint_t file_hint_pdf= {
  .extension="pdf",
  .description="Portable Document Format, Adobe Illustrator",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pdf
};

/*@
  @ terminates \true;
  @ assigns \nothing;
  @*/
static int is_hexa(const int c)
{
  return ((c>='0' && c<='9') || (c>='A' && c<='F') || (c>='a' && c<='f'));
}

/*@
  @ terminates \true;
  @ assigns \nothing;
  @ ensures 0 <= \result <= 15;
  @*/
static unsigned int hex(const int c)
{
  if(c>='0' && c<='9')
    return c-'0';
  if(c>='A' && c<='F')
    return c-'A'+10;
  if(c>='a' && c<='f')
    return c-'a'+10;
  return 0;
}

/*@
  @ requires file_recovery->file_rename==&file_rename_pdf;
  @ requires valid_file_rename_param(file_recovery);
  @ ensures  valid_file_rename_result(file_recovery);
  @*/
static void file_rename_pdf(file_recovery_t *file_recovery)
{
  char title[512];
  const unsigned char pattern[6]={ '/', 'T', 'i', 't', 'l', 'e' };
  off_t offset;
  uint64_t tmp;
  FILE *handle;
  unsigned char*buffer;
  unsigned int i;
  unsigned int l;
  size_t bsize;
  const unsigned char utf16[3]= { 0xfe, 0xff, 0x00};
  if((handle=fopen(file_recovery->filename, "rb"))==NULL)
    return;
  if(my_fseek(handle, 0, SEEK_END)<0)
  {
    fclose(handle);
    return;
  }
#ifdef HAVE_FTELLO
  offset=ftello(handle);
#else
  offset=ftell(handle);
#endif
  if(offset <= 0)
  {
    fclose(handle);
    return;
  }
  if(offset > PHOTOREC_MAX_FILE_SIZE)
    offset = PHOTOREC_MAX_FILE_SIZE;
  tmp=file_rsearch(handle, offset, pattern, sizeof(pattern));
  if(tmp==0 || tmp > PHOTOREC_MAX_FILE_SIZE)
  {
    fclose(handle);
    return;
  }
  offset=tmp+sizeof(pattern);
  if(my_fseek(handle, offset, SEEK_SET)<0)
  {
    fclose(handle);
    return ;
  }
  buffer=(unsigned char*)MALLOC(512);
  if((bsize=fread(buffer, 1, 512, handle)) <= 2)
  {
    free(buffer);
    fclose(handle);
    return ;
  }
  /*@ assert 2 < bsize; */
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, 512);
#endif
  /*@ assert \initialized(buffer + (0 .. 512-1)); */
  fclose(handle);
  /* Skip spaces after /Title */
  /*@
    @ loop invariant 0 <= i <= bsize;
    @ loop assigns i;
    @ loop variant bsize - i;
    @ */
  for(i=0; i<bsize && buffer[i]==' '; i++);
  if(i + 2 >= bsize)
  {
    /* Too much spaces */
    free(buffer);
    return ;
  }
  /*@ assert i + 2 < bsize; */
  if(buffer[i]=='<')
  {
    unsigned int j;
    unsigned int s;
    /* hexa to ascii */
    buffer[i]='(';
    /*@ assert \valid(buffer + (0 .. bsize -1)); */
    /*@
      @ loop invariant s <= bsize;
      @ loop invariant j <= s;
      @ loop invariant j <  bsize;
      @ loop assigns s, j, buffer[0 .. 512-1];
      @ loop variant bsize - (s+1);
      @ */
    for(s=i+1, j=i+1;
	s+1<bsize && is_hexa(buffer[s]) && is_hexa(buffer[s+1]);
	s+=2, j++)
      buffer[j]=(hex(buffer[s])<<4) | hex(buffer[s+1]);
    buffer[j]=')';
  }
  l=0;
  if(buffer[i]=='(')
  {
    const char *sbuffer=(const char *)buffer;
    /*@ assert \valid_read(sbuffer + (0 .. 512-1)); */
    /*@ assert \initialized(sbuffer + (0 .. 512-1)); */
    i++;	/* Skip '(' */
    if(i+8<bsize && memcmp(&buffer[i], "\\376\\377", 8)==0)
    {
      /* escape utf-16 title */
      i+=8;
      /*@
        @ loop invariant l < i;
        @ loop invariant \initialized(title + (0 .. l-1));
        @ loop assigns i, l, title[0 .. 512-1];
	@ loop variant bsize - i;
	@*/
      while(i<bsize)
      {
	if(buffer[i]==')')
	  break;
	if(i+4<bsize && buffer[i]=='\\' && isdigit(buffer[i+1]) &&
	    isdigit(buffer[i+2]) && isdigit(buffer[i+3]))
	  i+=4;
	else
	  title[l++]=sbuffer[i++];
      }
      /*@ assert \initialized(title + (0 .. l-1)); */
    }
    else if(i+3<bsize && memcmp(&buffer[i], &utf16, 3)==0)
    {
      /* utf-16 title */
      i+=2;
      /*@
        @ loop invariant l < i;
        @ loop invariant \initialized(title + (0 .. l-1));
        @ loop assigns i, l, title[0 .. 512-1];
	@ loop variant bsize - (i+1);
	@*/
      while(i+1 < bsize)
      {
	if(buffer[i]==')')
	  break;
	title[l++]=sbuffer[i+1];
	i+=2;
      }
      /*@ assert \initialized(title + (0 .. l-1)); */
    }
    else
    {
      /* ascii title */
      /*@
        @ loop invariant l < i;
        @ loop invariant \initialized(title + (0 .. l-1));
        @ loop assigns i, l, title[0 .. 512-1];
	@ loop variant bsize - i;
	@*/
      while(i<bsize && buffer[i]!=')')
	title[l++]=sbuffer[i++];
      /*@ assert \initialized(title + (0 .. l-1)); */
    }
  }
  else
  {
    free(buffer);
    return ;
  }
  /*@ assert \initialized(title + (0 .. l-1)); */
  /* Try to avoid some double-extensions */
  if(l>4 &&
      (memcmp(&title[l-4], ".doc", 4)==0 ||
       memcmp(&title[l-4], ".xls", 4)==0))
    l-=4;
  else if(l>5 &&
      (memcmp(&title[l-5], ".docx", 5)==0 ||
       memcmp(&title[l-5], ".xlsx", 5)==0))
    l-=5;
  file_rename(file_recovery, title, l, 0, NULL, 1);
  free(buffer);
}

/*@
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, &Frama_C_entropy_source);
  @ assigns *file_recovery->handle, file_recovery->time;
  @ assigns errno;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_date_pdf(file_recovery_t *file_recovery)
{
  const unsigned char pattern[14]={'x', 'a', 'p', ':', 'C', 'r', 'e', 'a', 't', 'e', 'D', 'a', 't', 'e'};
  uint64_t offset=0;
  unsigned int j=0;
  char buffer[4096];
  if(file_recovery->file_size > PHOTOREC_MAX_FILE_SIZE)
    return ;
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  if(my_fseek(file_recovery->handle, 0, SEEK_SET)<0)
  {
    return ;
  }
  /*@
    @ loop invariant \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, buffer + (..));
    @ loop assigns offset, j, *file_recovery->handle, file_recovery->time, buffer[0..4095];
    @ loop assigns errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant file_recovery->file_size - offset;
    @*/
  while(offset < file_recovery->file_size)
  {
    int i;
    const int bsize=fread(buffer, 1, 4096, file_recovery->handle);
    if(bsize<=0)
    {
      return ;
    }
#if defined(__FRAMAC__)
    Frama_C_make_unknown(buffer, bsize);
#endif
    /*@
      @ loop invariant \initialized(buffer + (0 .. bsize-1));
      @ loop invariant \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, buffer + (..));
      @ loop invariant 0 <= i <= bsize;
      @ loop assigns i, j, *file_recovery->handle, file_recovery->time, buffer[0..21];
      @ loop assigns errno;
      @ loop variant bsize - i;
      @*/
    for(i=0; i<bsize; i++)
    {
      if(buffer[i]==pattern[j])
      {
	if(++j==sizeof(pattern))
	{
	  if(my_fseek(file_recovery->handle, offset+i+1, SEEK_SET)>=0 &&
	      fread(buffer, 1, 22, file_recovery->handle) == 22)
	  {
	    /*@ assert \initialized( buffer+ (0 .. 22-1)); */
	    if(buffer[0]=='=' && (buffer[1]=='\'' || buffer[1]=='"'))
	    {
	      file_recovery->time=get_time_from_YYYY_MM_DD_HH_MM_SS((const unsigned char *)&buffer[2]);
	    }
	    else if(buffer[0]=='>')
	    {
	      file_recovery->time=get_time_from_YYYY_MM_DD_HH_MM_SS((const unsigned char *)&buffer[1]);
	    }
	  }
	  return ;
	}
      }
      else
	j=0;
    }
    offset+=bsize;
  }
}


#define PDF_READ_SIZE 20

/*@
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns *file_recovery->handle, file_recovery->time, file_recovery->file_size;
  @ assigns errno;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_pdf_and_size(file_recovery_t *file_recovery)
{
  char buffer[PDF_READ_SIZE + 3];
  int i;
  int taille;
  if( file_recovery->file_size < file_recovery->calculated_file_size ||
      file_recovery->calculated_file_size < PDF_READ_SIZE)
  {
    file_recovery->file_size=0;
    return;
  }
  /*@ assert file_recovery->calculated_file_size >= PDF_READ_SIZE; */
  file_recovery->file_size=file_recovery->calculated_file_size;
  /*@ assert file_recovery->file_size >= PDF_READ_SIZE; */
  if(my_fseek(file_recovery->handle,file_recovery->file_size-PDF_READ_SIZE,SEEK_SET)<0)
  {
    file_recovery->file_size=0;
    return ;
  }
  taille=fread(buffer, 1, PDF_READ_SIZE, file_recovery->handle);
#if defined(__FRAMAC__)
  Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
  /*@
    @ loop assigns i;
    @ loop assigns *file_recovery->handle, file_recovery->time;
    @ loop assigns errno;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant i;
    @*/
  for(i=taille-4;i>=0;i--)
  {
    if(buffer[i]=='%' && buffer[i+1]=='E' && buffer[i+2]=='O' && buffer[i+3]=='F')
    {
      file_date_pdf(file_recovery);
      return ;
    }
  }
  file_recovery->file_size=0;
}

/*@
  @ requires valid_file_check_param(file_recovery);
  @ ensures  valid_file_check_result(file_recovery);
  @ assigns  *file_recovery->handle, file_recovery->time, file_recovery->file_size;
  @ assigns errno;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_pdf(file_recovery_t *file_recovery)
{
  const unsigned char pdf_footer[4]= { '%', 'E', 'O', 'F'};
  file_search_footer(file_recovery, pdf_footer, sizeof(pdf_footer), 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
  file_date_pdf(file_recovery);
}

/*@
  @ requires \valid_read(buffer+(0..512-1));
  @ assigns \nothing;
  @*/
static uint64_t read_pdf_file_aux(const unsigned char *buffer, unsigned int i)
{
  uint64_t file_size=0;
  /*@
    @ loop assigns i;
    @ loop variant 512 - i;
    @*/
  while(i < 512 &&
      (buffer[i] ==' ' || buffer[i]=='\t' || buffer[i]=='\n' || buffer[i]=='\r'))
    i++;
  /*@
    @ loop invariant file_size <= PHOTOREC_MAX_FILE_SIZE;
    @ loop assigns i, file_size;
    @ loop variant 512 - i;
    @ */
  for(;i<512 && buffer[i]>='0' && buffer[i]<='9'; i++)
  {
    file_size*=10;
    file_size+=buffer[i]-'0';
    if(file_size > PHOTOREC_MAX_FILE_SIZE)
    {
      return PHOTOREC_MAX_FILE_SIZE + 1;
    }
    /*@ assert file_size <= PHOTOREC_MAX_FILE_SIZE; */
  }
  return file_size;
}

/*@
  @ requires \valid_read(buffer+(0..512-1));
  @ assigns  \nothing;
  @*/
static uint64_t read_pdf_file(const unsigned char *buffer)
{
  const unsigned char sig_linearized[10]={'L','i','n','e','a','r','i','z','e','d'};
  const char *src;
  unsigned int i;
  const char *sbuffer=(const char *)buffer;
  src=(const char *)td_memmem(sbuffer, 512, sig_linearized, sizeof(sig_linearized));
  if(src == NULL)
    return 0;
  i = src - sbuffer;
  i+=sizeof(sig_linearized);
  if( i >= 512 -1)
    return 0;
  /*@ assert i < 512-1; */
  /*@
    @ loop assigns i;
    @ loop variant 512 - 1 - i;
    @ */
  for(; i < 512-1 && buffer[i]!='>'; i++)
  {
    if(buffer[i]=='/' && buffer[i+1]=='L')
      return read_pdf_file_aux(buffer, i+2);
  }
  return 0;
}

/*@
  @ requires buffer_size >= 512;
  @ requires separation: \separated(&file_hint_pdf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_pdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint64_t file_size;
  if(!isprint(buffer[6]))
    return 0;
  file_size=read_pdf_file(buffer);
  if(file_size > PHOTOREC_MAX_FILE_SIZE)
    return 0;
  reset_file_recovery(file_recovery_new);
  if(td_memmem(buffer, buffer_size, "<</Illustrator ", 15) != NULL)
    file_recovery_new->extension="ai";
  else
  {
    file_recovery_new->extension=file_hint_pdf.extension;
    file_recovery_new->file_rename=&file_rename_pdf;
  }
  if(file_size == 0)
  {
    file_recovery_new->file_check=&file_check_pdf;
    return 1;
  }
  file_recovery_new->calculated_file_size=file_size;
  file_recovery_new->data_check=&data_check_size;
  file_recovery_new->file_check=&file_check_pdf_and_size;
  return 1;
}

static void register_header_check_pdf(file_stat_t *file_stat)
{
  static const unsigned char pdf_header[]  = { '%','P','D','F','-','1'};
  register_header_check(0, pdf_header,sizeof(pdf_header), &header_check_pdf, file_stat);
}
#endif
