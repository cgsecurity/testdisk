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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_fcs)
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

/*@
  @ requires valid_register_header_check(file_stat);
  @*/
static void register_header_check_fcs(file_stat_t *file_stat);

const file_hint_t file_hint_fcs= {
  .extension="fcs",
  .description="Flow Cytometry Standard 3.0",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fcs
};

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
} __attribute__ ((gcc_struct, __packed__));

/*@
  @ requires \valid_read(string + (0 .. max_length-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static uint64_t ascii2int(const unsigned char *string, const unsigned int max_length)
{
  uint64_t res=0;
  unsigned int i;
  /*@
    @ loop invariant res <= 0x1999999999999998;
    @ loop assigns res,i;
    @ loop variant max_length - i;
    @*/
  for(i=0;i<max_length;i++)
  {
    if(string[i]>='0' && string[i]<='9')
    {
      res=res*10+(string[i]-'0');
      if(res > 0x1999999999999998)
	return 0xffffffffffffffff;
    }
    else if(!(string[i]==' ' && res==0))
      return 0;
  }
  return res;
}

/*@
  @ requires \valid_read(string + (0 .. max_length-1));
  @ terminates \true;
  @ assigns \nothing;
  @*/
static uint64_t ascii2int2(const unsigned char *string, const unsigned int max_length, const unsigned int delimiter)
{
  uint64_t res=0;
  unsigned int i;
  /*@
    @ loop invariant res <= 0x1999999999999998;
    @ loop assigns res,i;
    @ loop variant max_length - i;
    @*/
  for(i=0;i<max_length;i++)
  {
    if(string[i]>='0' && string[i]<='9')
    {
      res=res*10+(string[i]-'0');
      if(res > 0x1999999999999998)
	return res;
    }
    else if(string[i]==delimiter)
      return res;
    else if(string[i]==' ' && res>0)
      return res;
    else if(string[i]!=' ')
      return 0;
  }
  return res;
}

/*@
  @ requires buffer_size >= sizeof(struct fcs_header);
  @ requires separation: \separated(&file_hint_fcs, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ ensures (\result == 1) ==> file_recovery_new->file_size == 0;
  @ ensures (\result != 0) ==> file_recovery_new->extension != \null;
  @ ensures (\result == 1) ==> (file_recovery_new->time == 0);
  @ ensures (\result == 1) ==> (file_recovery_new->min_filesize == 58);
  @ ensures (\result == 1) ==> (file_recovery_new->calculated_file_size > 0);
  @ ensures (\result == 1) ==> (file_recovery_new->extension == file_hint_fcs.extension);
  @ ensures (\result == 1) ==> (file_recovery_new->data_check == &data_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_check == &file_check_size);
  @ ensures (\result == 1) ==> (file_recovery_new->file_rename == \null);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_fcs(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
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
  if((data_end==0 || analysis_end==0) && text_start < buffer_size)
  { /* Explore TEXT segment */
    unsigned int i;
    const unsigned char delimiter=buffer[text_start];
    const unsigned int smallest=(buffer_size < text_end ? buffer_size : text_end);
    /*@
      @ loop assigns i, data_end, stext_end, analysis_end;
      @ loop variant smallest - i;
      @*/
    for(i=0; i<smallest; i++)
    {
      if(buffer[i]==delimiter)
      {
	if(i+1+8+1 < smallest &&
	    memcmp(buffer+i+1,"$ENDDATA",8)==0 && buffer[i+1+8]==delimiter)
	  data_end=ascii2int2(&buffer[i+1+8+1], smallest-(i+1+8+1), delimiter);
	else if(i+1+9+1 < smallest &&
	    memcmp(buffer+i+1,"$ENDSTEXT",9)==0 && buffer[i+1+9]==delimiter)
	  stext_end=ascii2int2(&buffer[i+1+9+1], smallest-(i+1+9+1), delimiter);
	else if(i+1+12+1 < smallest &&
	    memcmp(buffer+i+1,"$ENDANALYSIS",12)==0 && buffer[i+1+12]==delimiter)
	  analysis_end=ascii2int2(&buffer[i+1+12+1], smallest-(i+1+12+1), delimiter);
      }
    }
  }
#ifdef DEBUG_FCS
  log_info("$ENDDATA %llu\n", (long long unsigned) data_end);
  log_info("$ENDSTEXT %llu\n", (long long unsigned) stext_end);
  log_info("$ENDANALYSIS %llu\n", (long long unsigned) analysis_end);
#endif
  if( data_end >= 0x8000000000000000 - 9 ||
      analysis_end >= 0x8000000000000000 - 9 ||
      stext_end >= 0x8000000000000000 - 9)
    return 0;
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

static void register_header_check_fcs(file_stat_t *file_stat)
{
  static const unsigned char fcs_signature[6]= {'F','C','S','3','.','0'};
  register_header_check(0, fcs_signature, sizeof(fcs_signature), &header_check_fcs, file_stat);
}
#endif
