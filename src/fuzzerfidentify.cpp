/*

    File: fuzzerfidentify.cpp

    Copyright (C) 2018 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include <sys/types.h>
#include <unistd.h>
extern file_enable_t list_file_enable[];
extern file_check_list_t file_check_list;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  const size_t blocksize=65536;
  static unsigned char *buffer_start=NULL;
  static file_stat_t *file_stats=NULL;
  static char *filename=NULL;
  uint8_t *buffer;
  if(Size == 0)
    return 0;
  if(filename==NULL)
  {
    pid_t pid=getpid();
    filename=(char *)MALLOC(64);
    sprintf(filename, "sample%u", pid);
  }
  if(file_stats==NULL)
  {
    /* Enable all file formats */
    file_enable_t *file_enable;
    for(file_enable=list_file_enable;file_enable->file_hint!=NULL;file_enable++)
      file_enable->enable=1;
    file_stats=init_file_stats(list_file_enable);
  }
  if(buffer_start==NULL)
  {
    buffer_start=(unsigned char *)MALLOC(2*blocksize);
  }
  buffer=buffer_start+blocksize;
  memcpy(buffer, Data, (Size < blocksize ? Size : blocksize));
  {
    struct td_list_head *tmpl;
    file_recovery_t file_recovery_new;
    file_recovery_t file_recovery;
    reset_file_recovery(&file_recovery);
    file_recovery.blocksize=blocksize;
    file_recovery_new.blocksize=blocksize;
    file_recovery_new.file_stat=NULL;
    td_list_for_each(tmpl, &file_check_list.list)
    {
      struct td_list_head *tmp;
      const file_check_list_t *pos=td_list_entry_const(tmpl, const file_check_list_t, list);
      if(pos->offset <= blocksize)
      {
	td_list_for_each(tmp, &pos->file_checks[buffer[pos->offset]].list)
	{
	  const file_check_t *file_check=td_list_entry_const(tmp, const file_check_t, list);
	  if((file_check->length==0 ||
		(file_check->offset+file_check->length <=blocksize &&
		 memcmp(buffer + file_check->offset, file_check->value, file_check->length)==0)) &&
	      file_check->header_check(buffer, blocksize, 0, &file_recovery, &file_recovery_new)!=0)
	  {
	    file_recovery_new.file_stat=file_check->file_stat;
	    break;
	  }
	}
      }
      if(file_recovery_new.file_stat!=NULL)
	break;
    }
#if 0
    if( file_recovery_new.file_stat!=NULL && file_recovery_new.file_stat->file_hint!=NULL &&
	file_recovery_new.file_check!=NULL)
    {
      FILE *out;
      file_recovery_new.file_size=Size;
      file_recovery_new.calculated_file_size=Size;
      out=fopen(filename, "wb");
      fwrite(Data, Size, 1, out);
      file_recovery_new.handle=out;
      (file_recovery_new.file_check)(&file_recovery_new);
      fclose(out);
//      unlink(filename);
    }
#endif
  }
  return 0;  // Non-zero return values are reserved for future use.
}
