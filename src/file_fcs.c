/*

    File: file_fcs.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "log.h"

static void register_header_check_fcs(file_stat_t *file_stat);
static int header_check_fcs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_fcs= {
  .extension="fcs",
  .description="Flow Cytometry Standard 3.0",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fcs
};

static const unsigned char fcs_signature[6]= {'F','C','S','3','.','0'};

static void register_header_check_fcs(file_stat_t *file_stat)
{
  register_header_check(0, fcs_signature, sizeof(fcs_signature), &header_check_fcs, file_stat);
}

struct fcs_header
{
  unsigned char magic[6];
  unsigned char reserved[4];
  unsigned char text_start[8];		/* 10 */
  unsigned char text_end[8];		/* 18 */
  unsigned char data_start[8];		/* 26 */
  unsigned char data_end[8];		/* 34 */
  unsigned char analysis_start[8];	/* 34 */
  unsigned char analysis_end[8];	/* 50 */
} __attribute__ ((__packed__));

static uint64_t ascii2int(const unsigned char *string, const unsigned int max_length)
{
  uint64_t res=0;
  unsigned int i;
  for(i=0;i<max_length;i++)
  {
    if(string[i]>='0' && string[i]<='9')
      res=res*10+(string[i]-'0');
    else if(!(string[i]==' ' && res==0))
      return 0;
  }
  return res;
}

static uint64_t ascii2int2(const unsigned char *string, const unsigned int max_length, const unsigned int delimiter)
{
  uint64_t res=0;
  unsigned int i;
  for(i=0;i<max_length;i++)
    if(string[i]>='0' && string[i]<='9')
      res=res*10+(string[i]-'0');
    else if(string[i]==delimiter)
      return res;
    else if(string[i]==' ' && res>0)
      return res;
    else if(string[i]!=' ')
      return 0;
  return res;
}

static int header_check_fcs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if(memcmp(buffer, fcs_signature, sizeof(fcs_signature))==0)
  {
    const struct fcs_header *fcs=(const struct fcs_header*)buffer;
    uint64_t text_start;
    uint64_t text_end;
    uint64_t data_start;
    uint64_t data_end;
    uint64_t analysis_start;
    uint64_t analysis_end;
    uint64_t stext_end=0;
    text_start=ascii2int(fcs->text_start, 8);
    text_end=ascii2int(fcs->text_end, 8);
    data_start=ascii2int(fcs->data_start, 8);
    data_end=ascii2int(fcs->data_end, 8);
    analysis_start=ascii2int(fcs->analysis_start, 8);
    analysis_end=ascii2int(fcs->analysis_end, 8);
    if(!(text_start<=text_end && data_start<=data_end && analysis_start<=analysis_end))
      return 0;
    if(data_end==0 || analysis_end==0)
    { /* Explore TEXT segment */
      unsigned int i;
      const char delimiter=buffer[text_start];
      for(i=0;i<text_end && i<buffer_size;i++)
      {
	if(buffer[i]==delimiter)
	{
	  if(i+1+8+1<text_end &&
	      memcmp(buffer+i+1,"$ENDDATA",8)==0 && buffer[i+1+8]==delimiter)
	    data_end=ascii2int2(&buffer[i+1+8+1], text_end-(i+1+8+1), delimiter);
	  else if(i+1+9+1<text_end && 
	      memcmp(buffer+i+1,"$ENDSTEXT",9)==0 && buffer[i+1+9]==delimiter)
	    stext_end=ascii2int2(&buffer[i+1+9+1], text_end-(i+1+9+1), delimiter);
	  else if(i+1+12+1<text_end && 
	      memcmp(buffer+i+1,"$ENDANALYSIS",12)==0 && buffer[i+1+12]==delimiter)
	    analysis_end=ascii2int2(&buffer[i+1+12+1], text_end-(i+1+12+1), delimiter);
	}
      }
    }
#ifdef DEBUG_FCS
    log_info("$ENDDATA %llu\n", (long long unsigned) data_end);
    log_info("$ENDSTEXT %llu\n", (long long unsigned) stext_end);
    log_info("$ENDANALYSIS %llu\n", (long long unsigned) analysis_end);
#endif
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_fcs.extension;
    file_recovery_new->min_filesize=58;
    file_recovery_new->calculated_file_size=data_end+9;
    if(file_recovery_new->calculated_file_size < analysis_end+9)
      file_recovery_new->calculated_file_size=analysis_end+9;
    if(file_recovery_new->calculated_file_size < stext_end+9)
      file_recovery_new->calculated_file_size=stext_end+9;
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
