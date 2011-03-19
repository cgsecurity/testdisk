/*

    File: file_pdf.c

    Copyright (C) 1998-2007 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "types.h"
#include "filegen.h"
#include "memmem.h"
#include "common.h"

static void register_header_check_pdf(file_stat_t *file_stat);
static int header_check_pdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_pdf(file_recovery_t *file_recovery);
static void file_check_pdf_and_size(file_recovery_t *file_recovery);
static void file_date_pdf(file_recovery_t *file_recovery);

const file_hint_t file_hint_pdf= {
  .extension="pdf",
  .description="Portable Document Format, Adobe Illustrator",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_pdf
};

static const unsigned char pdf_header[]  = { '%','P','D','F','-','1'};

static void register_header_check_pdf(file_stat_t *file_stat)
{
  register_header_check(0, pdf_header,sizeof(pdf_header), &header_check_pdf, file_stat);
}

static int header_check_pdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer,pdf_header,sizeof(pdf_header))==0)
  {
    const unsigned char sig_linearized[10]={'L','i','n','e','a','r','i','z','e','d'};
    const unsigned char *src;
    reset_file_recovery(file_recovery_new);
    if(td_memmem(buffer, 512, "<</Illustrator ", 15) != NULL)
      file_recovery_new->extension="ai";
    else
      file_recovery_new->extension=file_hint_pdf.extension;
    if((src=(const unsigned char *)td_memmem(buffer, 512, sig_linearized, sizeof(sig_linearized))) != NULL)
    {
      src+=sizeof(sig_linearized);
      for(; src<=buffer+512 && *src!='>'; src++)
      {
	if(*src=='/' && *(src+1)=='L')
	{
	  src+=2;
	  while(src<buffer+512 &&
	      (*src==' ' || *src=='\t' || *src=='\n' || *src=='\r'))
	    src++;
	  file_recovery_new->calculated_file_size=0;
	  while(src<buffer+512 &&
	      *src>='0' && *src<='9')
	  {
	    file_recovery_new->calculated_file_size=file_recovery_new->calculated_file_size*10+(*src)-'0';
	    src++;
	  }
	  file_recovery_new->data_check=&data_check_size;
	  file_recovery_new->file_check=&file_check_pdf_and_size;
	  return 1;
	}
      }
    }
    file_recovery_new->file_check=&file_check_pdf;
    return 1;
  }
  return 0;
}

static void file_check_pdf_and_size(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size>=file_recovery->calculated_file_size)
  {
    const unsigned int read_size=20;
    unsigned char buffer[20+3];	/* read_size+3 */
    int i;
    int taille;
    file_recovery->file_size=file_recovery->calculated_file_size;
    if(fseek(file_recovery->handle,file_recovery->file_size-read_size,SEEK_SET)<0)
    {
      file_recovery->file_size=0;
      return ;
    }
    taille=fread(buffer,1,read_size,file_recovery->handle);
    for(i=taille-4;i>=0;i--)
    {
      if(buffer[i]=='%' && buffer[i+1]=='E' && buffer[i+2]=='O' && buffer[i+3]=='F')
      {
	file_date_pdf(file_recovery);
	return ;
      }
    }
  }
  file_recovery->file_size=0;
}

static void file_check_pdf(file_recovery_t *file_recovery)
{
  const unsigned char pdf_footer[4]= { '%', 'E', 'O', 'F'};
  file_search_footer(file_recovery, pdf_footer, sizeof(pdf_footer), 0);
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
  file_date_pdf(file_recovery);
}

static void file_date_pdf(file_recovery_t *file_recovery)
{
  const unsigned char pattern[14]={'x', 'a', 'p', ':', 'C', 'r', 'e', 'a', 't', 'e', 'D', 'a', 't', 'e'};
  uint64_t offset=0;
  unsigned int j=0;
  unsigned char*buffer=(unsigned char*)MALLOC(4096);
  fseek(file_recovery->handle, 0, SEEK_SET);
  while(offset < file_recovery->file_size)
  {
    int i;
    int bsize;
    if((bsize=fread(buffer, 1, 4096, file_recovery->handle))<=0)
    {
      free(buffer);
      return ;
    }
    for(i=0; i<bsize; i++)
    {
      if(buffer[i]==pattern[j])
      {
	if(++j==sizeof(pattern))
	{
	  const unsigned char *date_asc;
	  struct tm tm_time;
	  fseek(file_recovery->handle, offset+i+1, SEEK_SET);
	  if(fread(buffer, 1, 22, file_recovery->handle) < 22)
	  {
	    free(buffer);
	    return ;
	  }
	  if(buffer[0]=='=' && (buffer[1]=='\'' || buffer[1]=='"'))
	    date_asc=&buffer[2];
	  else if(buffer[i]=='>')
	    date_asc=&buffer[1];
	  else
	  {
	    free(buffer);
	    return ;
	  }
	  /* */
	  memset(&tm_time, 0, sizeof(tm_time));
	  tm_time.tm_sec=(date_asc[17]-'0')*10+(date_asc[18]-'0');      /* seconds 0-59 */
	  tm_time.tm_min=(date_asc[14]-'0')*10+(date_asc[15]-'0');      /* minutes 0-59 */
	  tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
	  tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
	  tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
	  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
	    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
	  tm_time.tm_isdst = -1;		/* unknown daylight saving time */
	  file_recovery->time=mktime(&tm_time);
	  free(buffer);
	  return ;
	}
      }
      else
	j=0;
    }
    offset+=bsize;
  }
  free(buffer);
}
