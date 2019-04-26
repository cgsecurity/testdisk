/*

    File: filegen.c

    Copyright (C) 2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "log.h"

static  file_check_t file_check_plist={
  .list = TD_LIST_HEAD_INIT(file_check_plist.list)
};

file_check_list_t file_check_list={
    .list = TD_LIST_HEAD_INIT(file_check_list.list)
};

static unsigned int index_header_check(void);

static int file_check_cmp(const struct td_list_head *a, const struct td_list_head *b)
{
  const file_check_t *fc_a=td_list_entry_const(a, const file_check_t, list);
  const file_check_t *fc_b=td_list_entry_const(b, const file_check_t, list);
  int res;
  if(fc_a->length==0 && fc_b->length!=0)
    return -1;
  if(fc_a->length!=0 && fc_b->length==0)
    return 1;
  res=fc_a->offset-fc_b->offset;
  if(res!=0)
    return res;
  res=memcmp(fc_a->value,fc_b->value, (fc_a->length<=fc_b->length?fc_a->length:fc_b->length));
  if(res!=0)
    return res;
  return fc_b->length-fc_a->length;
}

static void file_check_add_tail(file_check_t *file_check_new, file_check_list_t *pos)
{
  unsigned int i;
  file_check_list_t *newe=(file_check_list_t *)MALLOC(sizeof(*newe));
  newe->offset=file_check_new->offset;
  for(i=0;i<256;i++)
  {
    newe->file_checks[i].list.prev=&newe->file_checks[i].list;
    newe->file_checks[i].list.next=&newe->file_checks[i].list;
  }
  td_list_add_tail(&file_check_new->list, &newe->file_checks[file_check_new->length==0?0:((const unsigned char *)file_check_new->value)[0]].list);
  td_list_add_tail(&newe->list, &pos->list);
}

void register_header_check(const unsigned int offset, const void *value, const unsigned int length, int (*header_check)(const unsigned char *buffer, const unsigned int buffer_size,
      const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new),
  file_stat_t *file_stat)
{
  file_check_t *file_check_new=(file_check_t *)MALLOC(sizeof(*file_check_new));
  file_check_new->value=value;
  file_check_new->length=length;
  file_check_new->offset=offset;
  file_check_new->header_check=header_check;
  file_check_new->file_stat=file_stat;
  td_list_add_sorted(&file_check_new->list, &file_check_plist.list, file_check_cmp);
}

static void index_header_check_aux(file_check_t *file_check_new)
{
  struct td_list_head *tmp;
  td_list_for_each(tmp, &file_check_list.list)
  {
    file_check_list_t *pos=td_list_entry(tmp, file_check_list_t, list);
    if(file_check_new->length>0)
    {
      if(pos->offset >= file_check_new->offset &&
	  pos->offset < file_check_new->offset+file_check_new->length)
      {
	td_list_add_sorted(&file_check_new->list,
	    &pos->file_checks[((const unsigned char *)file_check_new->value)[pos->offset-file_check_new->offset]].list,
	    file_check_cmp);
	return ;
      }
      if(pos->offset>file_check_new->offset)
      {
	file_check_add_tail(file_check_new, pos);
	return ;
      }
    }
  }
  file_check_add_tail(file_check_new, &file_check_list);
}

static unsigned int index_header_check(void)
{
  struct td_list_head *tmp;
  struct td_list_head *next;
  unsigned int nbr=0;
 /* Initialize file_check_list from file_check_plist */
  td_list_for_each_prev_safe(tmp, next, &file_check_plist.list)
  {
    file_check_t *current_check;
    current_check=td_list_entry(tmp, file_check_t, list);
    td_list_del(tmp);
    index_header_check_aux(current_check);
    nbr++;
  }
  return nbr;
}

void free_header_check(void)
{
  struct td_list_head *tmpl;
  struct td_list_head *nextl;
  td_list_for_each_safe(tmpl, nextl, &file_check_list.list)
  {
    unsigned int i;
    file_check_list_t *pos=td_list_entry(tmpl, file_check_list_t, list);
    for(i=0;i<256;i++)
    {
      struct td_list_head *tmp;
      struct td_list_head *next;
      td_list_for_each_safe(tmp, next, &pos->file_checks[i].list)
      {
#ifdef DEBUG_HEADER_CHECK
	unsigned int j;
	const unsigned char *data;
#endif
	file_check_t *current_check;
	current_check=td_list_entry(tmp, file_check_t, list);
#ifdef DEBUG_HEADER_CHECK
	data=(const char *)current_check->value;
	log_info("[%u]=%02x length=%u offset=%u", pos->offset, i, current_check->length, current_check->offset);
	if(current_check->file_stat!=NULL && current_check->file_stat->file_hint!=NULL)
	  log_info(" %s", current_check->file_stat->file_hint->description);
	for(j=0; j<current_check->length; j++)
	  log_info(" %02x", data[j]);
	log_info("\n");
#endif
	td_list_del(tmp);
	free(current_check);
      }
    }
#ifdef DEBUG_HEADER_CHECK
    log_info("\n");
#endif
    td_list_del(tmpl);
    free(pos);
  }
}

void file_allow_nl(file_recovery_t *file_recovery, const unsigned int nl_mode)
{
  unsigned char buffer[4096];
  int taille;
  if(my_fseek(file_recovery->handle, file_recovery->file_size,SEEK_SET)<0)
    return;
  taille=fread(buffer,1, 4096,file_recovery->handle);
  if(taille > 0 && buffer[0]=='\n' && (nl_mode&NL_BARENL)==NL_BARENL)
    file_recovery->file_size++;
  else if(taille > 1 && buffer[0]=='\r' && buffer[1]=='\n' && (nl_mode&NL_CRLF)==NL_CRLF)
    file_recovery->file_size+=2;
  else if(taille > 0 && buffer[0]=='\r' && (nl_mode&NL_BARECR)==NL_BARECR)
    file_recovery->file_size++;
}

uint64_t file_rsearch(FILE *handle, uint64_t offset, const void*footer, const unsigned int footer_length)
{
  unsigned char*buffer;
  assert(footer_length < 4096);
  buffer=(unsigned char*)MALLOC(4096+footer_length-1);
  memset(buffer+4096,0,footer_length-1);
  do
  {
    int i;
    int taille;
    const unsigned int read_size=(offset%4096!=0 ? offset%4096 : 4096);
    offset-=read_size;
    if(my_fseek(handle,offset,SEEK_SET)<0)
    {
      free(buffer);
      return 0;
    }
    taille=fread(buffer, 1, read_size, handle);
    for(i=taille-1;i>=0;i--)
    {
      if(buffer[i]==*(const unsigned char *)footer && memcmp(buffer+i,footer,footer_length)==0)
      {
        free(buffer);
        return offset + i;
      }
    }
    memcpy(buffer+4096,buffer,footer_length-1);
  } while(offset>0);
  free(buffer);
  return 0;
}

void file_search_footer(file_recovery_t *file_recovery, const void*footer, const unsigned int footer_length, const unsigned int extra_length)
{
  if(footer_length==0 || file_recovery->file_size <= extra_length)
    return ;
  file_recovery->file_size=file_rsearch(file_recovery->handle, file_recovery->file_size-extra_length, footer, footer_length);
  if(file_recovery->file_size > 0)
    file_recovery->file_size+= footer_length + extra_length;
}

#if 0
void file_search_lc_footer(file_recovery_t *file_recovery, const unsigned char*footer, const unsigned int footer_length)
{
  const unsigned int read_size=4096;
  unsigned char*buffer;
  int64_t file_size;
  if(footer_length==0)
    return ;
  buffer=(unsigned char*)MALLOC(read_size+footer_length-1);
  file_size=file_recovery->file_size;
  memset(buffer+read_size,0,footer_length-1);
  do
  {
    int i;
    int taille;
    if(file_size%read_size!=0)
      file_size=file_size-(file_size%read_size);
    else
      file_size-=read_size;
    if(my_fseek(file_recovery->handle,file_size,SEEK_SET)<0)
    {
      free(buffer);
      return;
    }
    taille=fread(buffer,1,read_size,file_recovery->handle);
    for(i=0;i<taille;i++)
      buffer[i]=tolower(buffer[i]);
    for(i=taille-1;i>=0;i--)
    {
      if(buffer[i]==footer[0] && memcmp(buffer+i,footer,footer_length)==0)
      {
        file_recovery->file_size=file_size+i+footer_length;
        free(buffer);
        return;
      }
    }
    memcpy(buffer+read_size,buffer,footer_length-1);
  } while(file_size>0);
  file_recovery->file_size=0;
  free(buffer);
}
#endif

data_check_t data_check_size(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  if(file_recovery->file_size + buffer_size/2 >= file_recovery->calculated_file_size)
  {
    return DC_STOP;
  }
  return DC_CONTINUE;
}

void file_check_size(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size<file_recovery->calculated_file_size)
    file_recovery->file_size=0;
  else
    file_recovery->file_size=file_recovery->calculated_file_size;
}

void file_check_size_min(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size<file_recovery->calculated_file_size)
    file_recovery->file_size=0;
}

void file_check_size_max(file_recovery_t *file_recovery)
{
  if(file_recovery->file_size > file_recovery->calculated_file_size)
    file_recovery->file_size=file_recovery->calculated_file_size;
}

void reset_file_recovery(file_recovery_t *file_recovery)
{
  file_recovery->filename[0]='\0';
  file_recovery->time=0;
  file_recovery->file_stat=NULL;
  file_recovery->handle=NULL;
  file_recovery->file_size=0;
  file_recovery->location.list.prev=&file_recovery->location.list;
  file_recovery->location.list.next=&file_recovery->location.list;
  file_recovery->location.start=0;
  file_recovery->location.end=0;
  file_recovery->location.data=0;
  file_recovery->extension=NULL;
  file_recovery->min_filesize=0;
  file_recovery->calculated_file_size=0;
  file_recovery->data_check=NULL;
  file_recovery->file_check=NULL;
  file_recovery->file_rename=NULL;
  file_recovery->offset_error=0;
  file_recovery->offset_ok=0;
  file_recovery->checkpoint_status=0;
  file_recovery->checkpoint_offset=0;
//  file_recovery->blocksize=512;
  file_recovery->flags=0;
  file_recovery->extra=0;
}

file_stat_t * init_file_stats(file_enable_t *files_enable)
{
  file_stat_t *file_stats;
  file_enable_t *file_enable;
  unsigned int enable_count=1;	/* Lists are terminated by NULL */
  unsigned int sign_nbr;
  for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
  {
    if(file_enable->enable>0)
    {
      enable_count++;
    }
  }
  file_stats=(file_stat_t *)MALLOC(enable_count * sizeof(file_stat_t));
  enable_count=0;
  for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
  {
    if(file_enable->enable>0)
    {
      file_stats[enable_count].file_hint=file_enable->file_hint;
      file_stats[enable_count].not_recovered=0;
      file_stats[enable_count].recovered=0;
      if(file_enable->file_hint->register_header_check!=NULL)
	file_enable->file_hint->register_header_check(&file_stats[enable_count]);
      enable_count++;
    }
  }
  sign_nbr=index_header_check();
  file_stats[enable_count].file_hint=NULL;
  log_info("%u first-level signatures enabled\n", sign_nbr);
  return file_stats;
}

/* The original filename begins at offset in buffer and is null terminated */
int file_rename(file_recovery_t *file_recovery, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int append_original_ext)
{
  /* new_filename is large enough to avoid a buffer overflow */
  char *new_filename;
  const char *src=file_recovery->filename;
  const char *ext=NULL;
  char *dst;
  char *directory_sep;
  int len;
  if(buffer_size<0)
    return -1;
  len=strlen(src)+1;
  if(offset < buffer_size && buffer!=NULL)
    len+=buffer_size-offset+1;
  if(new_ext!=NULL)
    len+=strlen(new_ext);
  new_filename=(char*)MALLOC(len);
  dst=new_filename;
  directory_sep=new_filename;
  while(*src!='\0')
  {
    if(*src=='/')
    {
      directory_sep=dst;
      ext=NULL;
    }
    if(*src=='.')
      ext=src;
    *dst++ = *src++;
  }
  *dst='\0';
  dst=directory_sep;
  while(*dst!='.' && *dst!='\0')
    dst++;
  /* Add original filename */
  if(offset < buffer_size && buffer!=NULL)
  {
    char *dst_old=dst;
    int off;
    int ok=0;
    int bad=0;
    *dst++ = '_';
    src=&((const char *)buffer)[offset];
    for(off=offset; off<buffer_size && *src!='\0'; off++, src++)
    {
      switch(*src)
      {
	case '/':
	case '\\':
	case ':':
	case '*':
	case '<':
	case '>':
	case '|':
	case '\'':
	  if(*(dst-1) != '_')
	    *dst++ = '_';
	  bad++;
	  break;
	default:
	  if(isprint(*src) && !isspace(*src) && !ispunct(*src) && !iscntrl(*src))
	  {
	    *dst++ = *src;
	    ok++;
	  }
	  else
	  {
	    if(*(dst-1) != '_')
	      *dst++ = '_';
	    bad++;
	  }
	  break;
      }
    }
    if(ok <= bad)
      dst=dst_old;
    else
    {
      while(dst > dst_old && *(dst-1)=='_')
	dst--;
    }
  }
  /* Add extension */
  if(new_ext!=NULL)
  {
    src=new_ext;
    *dst++ = '.';
    while(*src!='\0')
      *dst++ = *src++;
  }
  else if(append_original_ext>0)
  {
    if(ext!=NULL)
    {
      while(*ext!='\0')
	*dst++ = *ext++;
    }
  }
  *dst='\0';
  if(rename(file_recovery->filename, new_filename)<0)
  {
    /* Rename has failed */
    free(new_filename);
    if(buffer==NULL)
      return -1;
    /* Try without the original filename */
    return file_rename(file_recovery, NULL, 0, 0, new_ext, append_original_ext);
  }
  if(strlen(new_filename)<sizeof(file_recovery->filename))
  {
    strcpy(file_recovery->filename, new_filename);
  }
  free(new_filename);
  return 0;
}

/* The original filename begins at offset in buffer and is null terminated */
int file_rename_unicode(file_recovery_t *file_recovery, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int append_original_ext)
{
  /* new_filename is large enough to avoid a buffer overflow */
  char *new_filename;
  const char *src=file_recovery->filename;
  const char *ext=src;
  char *dst;
  char *directory_sep;
  int len=strlen(src)+1;
  if(buffer_size<0)
    return -1;
  if(offset < buffer_size && buffer!=NULL)
    len+=buffer_size-offset;
  if(new_ext!=NULL)
    len+=strlen(new_ext);
  new_filename=(char*)MALLOC(len);
  dst=new_filename;
  directory_sep=dst;
  while(*src!='\0')
  {
    if(*src=='/')
      directory_sep=dst;
    if(*src=='.')
      ext=src;
    *dst++ = *src++;
  }
  *dst='\0';
  dst=directory_sep;
  while(*dst!='.' && *dst!='\0')
    dst++;
  /* Add original filename */
  if(offset < buffer_size && buffer!=NULL)
  {
    char *dst_old=dst;
    int off;
    int ok=0;
    int bad=0;
    *dst++ = '_';
    src=&((const char *)buffer)[offset];
    for(off=offset; off<buffer_size && *src!='\0'; off+=2, src+=2)
    {
      switch(*src)
      {
	case '/':
	case '\\':
	case ':':
	case '*':
	case '<':
	case '>':
	case '|':
	case '\'':
	  if(*(dst-1) != '_')
	    *dst++ = '_';
	  bad++;
	  break;
	default:
	  if(isprint(*src) && !isspace(*src) && !ispunct(*src) && !iscntrl(*src))
	  {
	    *dst++ = *src;
	    ok++;
	  }
	  else
	  {
	    if(*(dst-1) != '_')
	      *dst++ = '_';
	    bad++;
	  }
	  break;
      }
    }
    if(ok <= bad)
      dst=dst_old;
    else
    {
      while(dst > dst_old && *(dst-1)=='_')
	dst--;
    }
  }
  /* Add extension */
  if(new_ext!=NULL)
  {
    src=new_ext;
    *dst++ = '.';
    while(*src!='\0')
      *dst++ = *src++;
  }
  else if(append_original_ext>0)
  {
    while(*ext!='\0')
      *dst++ = *ext++;
  }
  *dst='\0';
  if(rename(file_recovery->filename, new_filename)<0)
  {
    /* Rename has failed */
    free(new_filename);
    if(buffer==NULL)
      return -1;
    /* Try without the original filename */
    return file_rename_unicode(file_recovery, NULL, 0, 0, new_ext, append_original_ext);
  }
  if(strlen(new_filename)<sizeof(file_recovery->filename))
  {
    strcpy(file_recovery->filename, new_filename);
  }
  free(new_filename);
  return 0;
}

static uint64_t offset_skipped_header=0;

void header_ignored_cond_reset(uint64_t start, uint64_t end)
{
  if(start <= offset_skipped_header && offset_skipped_header <= end)
    offset_skipped_header=0;
}

/* 0: file_recovery is bad *
 * 1: file_recovery is ok  */
int header_ignored_adv(const file_recovery_t *file_recovery, const file_recovery_t *file_recovery_new)
{
  file_recovery_t fr_test;
  off_t offset;
  assert(file_recovery!=NULL);
  assert(file_recovery_new!=NULL);
  if(file_recovery->file_check==NULL)
  {
    log_warning("header_ignored_adv: file_check==NULL\n");
    return 1;
  }
  if(file_recovery->handle==NULL)
  {
    if(file_recovery_new->location.start==0 || offset_skipped_header==0)
    {
      offset_skipped_header=file_recovery_new->location.start;
    }
    return 0;
  }

  memcpy(&fr_test, file_recovery, sizeof(fr_test));
#ifdef HAVE_FTELLO
  if((offset=ftello(file_recovery->handle)) < 0)
    offset=ftell(file_recovery->handle);
#else
  offset=ftell(file_recovery->handle);
#endif
  assert(offset >= 0);
  file_recovery->file_check(&fr_test);
  if(my_fseek(file_recovery->handle, offset, SEEK_SET) < 0)
  {
    log_error("BUG in header_ignored_adv: my_fseek() failed\n");
    return 1;
  }
  if(fr_test.file_size>0)
    return 1;
  if(file_recovery_new->location.start==0 || offset_skipped_header==0)
  {
    offset_skipped_header=file_recovery_new->location.start;
  }
  return 0;
}

void header_ignored(const file_recovery_t *file_recovery_new)
{
  if(file_recovery_new==NULL)
  {
    offset_skipped_header=0;
    return ;
  }
  if(file_recovery_new->location.start==0 || offset_skipped_header==0)
    offset_skipped_header=file_recovery_new->location.start;
}

void get_prev_location_smart(alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const uint64_t prev_location)
{
  alloc_data_t *file_space=*current_search_space;
  if(offset_skipped_header==0)
    return ;
  while(1)
  {
    file_space=td_list_prev_entry(file_space, list);
    if(file_space==list_search_space)
      break;
    if(file_space->start <= offset_skipped_header && offset_skipped_header < file_space->end)
    {
      *current_search_space=file_space;
      *offset=offset_skipped_header;
      offset_skipped_header=0;
      return ;
    }
    if(file_space->start < prev_location)
      break;
  }
#ifdef DEBUG_HEADER_CHECK
  log_info("get_prev_location_smart: reset offset_skipped_header=%llu, offset=%llu\n",
      (long long unsigned)(offset_skipped_header/512),
      (long long unsigned)(*offset/512));
#endif
  while(1)
  {
    file_space=td_list_prev_entry(file_space, list);
    if(file_space==list_search_space)
    {
      offset_skipped_header=0;
      return;
    }
    if(file_space->start < prev_location || file_space->start < offset_skipped_header)
    {
#ifdef DEBUG_HEADER_CHECK
      log_info("get_prev_location_smart: file_space->start < prev_location=%llu (in 512-bytes sectors), offset=%llu\n",
	  (long long unsigned)(prev_location/512),
	  (long long unsigned)(*offset/512));
#endif
      offset_skipped_header=0;
      return ;
    }
    *current_search_space=file_space;
    *offset=file_space->start;
  }
}

int my_fseek(FILE *stream, off_t offset, int whence)
{
#if defined(HAVE_FSEEKO) && !defined(__MINGW32__) && !defined(__ARM_EABI__)
  {
    int res;
    if((res=fseeko(stream, offset, whence))>=0)
      return res;
  }
#endif
 return fseek(stream, offset, whence);
}

time_t get_time_from_YYMMDDHHMMSS(const char *date_asc)
{
  struct tm tm_time;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[10]-'0')*10+(date_asc[11]-'0');	/* seconds 0-59 */
  tm_time.tm_min=(date_asc[8]-'0')*10+(date_asc[9]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[6]-'0')*10+(date_asc[7]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[4]-'0')*10+(date_asc[5]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[2]-'0')*10+(date_asc[3]-'0')-1;	/* month 1-12 */
  tm_time.tm_year=(date_asc[0]-'0')*10+(date_asc[1]-'0');        	/* year */
  if(tm_time.tm_year<80)
    tm_time.tm_year+=100;	/* year 2000 - 2079 */
  tm_time.tm_isdst = -1;	/* unknown daylight saving time */
  return mktime(&tm_time);
}

time_t get_time_from_YYYY_MM_DD_HH_MM_SS(const char *date_asc)
{
  struct tm tm_time;
  if(memcmp(date_asc, "0000", 4)==0)
    return (time_t)0;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[17]-'0')*10+(date_asc[18]-'0');      /* seconds 0-59 */
  tm_time.tm_min=(date_asc[14]-'0')*10+(date_asc[15]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
  tm_time.tm_isdst = -1;		/* unknown daylight saving time */
  return mktime(&tm_time);
}

time_t get_time_from_YYYY_MM_DD_HHMMSS(const char *date_asc)
{
  struct tm tm_time;
  if(memcmp(date_asc, "0000", 4)==0)
    return (time_t)0;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[15]-'0')*10+(date_asc[16]-'0');      /* seconds 0-59 */
  tm_time.tm_min=(date_asc[13]-'0')*10+(date_asc[14]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[11]-'0')*10+(date_asc[12]-'0');     /* hours   0-23*/
  tm_time.tm_mday=(date_asc[8]-'0')*10+(date_asc[9]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[5]-'0')*10+(date_asc[6]-'0')-1;	/* month 0-11 */
  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;        	/* year */
  tm_time.tm_isdst = -1;		/* unknown daylight saving time */
  return mktime(&tm_time);
}

time_t get_time_from_YYYYMMDD_HHMMSS(const char *date_asc)
{
  struct tm tm_time;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_sec=(date_asc[13]-'0')*10+(date_asc[14]-'0');      /* seconds 0-59 */
  tm_time.tm_min=(date_asc[11]-'0')*10+(date_asc[12]-'0');      /* minutes 0-59 */
  tm_time.tm_hour=(date_asc[9]-'0')*10+(date_asc[10]-'0');      /* hours   0-23*/
  tm_time.tm_mday=(date_asc[6]-'0')*10+(date_asc[7]-'0');	/* day of the month 1-31 */
  tm_time.tm_mon=(date_asc[4]-'0')*10+(date_asc[5]-'0')-1;	/* month 0-11 */
  tm_time.tm_year=(date_asc[0]-'0')*1000+(date_asc[1]-'0')*100+
    (date_asc[2]-'0')*10+(date_asc[3]-'0')-1900;		/* year */
  tm_time.tm_isdst = -1;		/* unknown daylight saving time */
  return mktime(&tm_time);
}
