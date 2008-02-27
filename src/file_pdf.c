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
#include "types.h"
#include "filegen.h"
#include "memmem.h"

static void register_header_check_pdf(file_stat_t *file_stat);
static int header_check_pdf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static void file_check_pdf(file_recovery_t *file_recovery);
static void file_check_pdf_and_size(file_recovery_t *file_recovery);

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
    const unsigned char sig_illustrator[11]={'I','l','l','u','s','t','r','a','t','o','r'};
    const unsigned char sig_linearized[10]={'L','i','n','e','a','r','i','z','e','d'};
    const unsigned char *linearized;
    reset_file_recovery(file_recovery_new);
    if(td_memmem(buffer, 512, sig_illustrator,sizeof(sig_illustrator)) != NULL)
      file_recovery_new->extension="ai";
    else
      file_recovery_new->extension=file_hint_pdf.extension;
    if((linearized=td_memmem(buffer, 512, sig_linearized,sizeof(sig_linearized))) != NULL)
    {
      linearized+=sizeof(sig_linearized);
      while(*linearized!='>' && linearized<=buffer+512)
      {
	if(*linearized=='/' && *(linearized+1)=='L')
	{
	  linearized+=2;
	  while(*linearized==' ' || *linearized=='\t' || *linearized=='\n' || *linearized=='\r')
	    linearized++;
	  file_recovery_new->calculated_file_size=0;
	  while(*linearized>='0' && *linearized<='9' && linearized<=buffer+512)
	  {
	    file_recovery_new->calculated_file_size=file_recovery_new->calculated_file_size*10+(*linearized)-'0';
	    linearized++;
	  }
	  file_recovery_new->data_check=&data_check_size;
	  file_recovery_new->file_check=&file_check_pdf_and_size;
	  return 1;
	}
	linearized++;
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
	return ;
    }
  }
  file_recovery->file_size=0;
}

static void file_check_pdf(file_recovery_t *file_recovery)
{
  const unsigned char pdf_footer[4]= { '%', 'E', 'O', 'F'};
  file_search_footer(file_recovery, pdf_footer, sizeof(pdf_footer));
  file_allow_nl(file_recovery, NL_BARENL|NL_CRLF|NL_BARECR);
}
