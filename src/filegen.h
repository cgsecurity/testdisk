/*

    File: filegen.h

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _TESTDISK_FILEGEN_H
#define _TESTDISK_FILEGEN_H
#ifdef __cplusplus
extern "C" {
#endif
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif

#include "list.h"

#if defined(DJGPP)
#define PHOTOREC_MAX_FILE_SIZE (((uint64_t)1<<31)-1)
#else
#define PHOTOREC_MAX_FILE_SIZE (((uint64_t)1<<41)-1)
#endif
#define PHOTOREC_MAX_SIZE_16 (((uint64_t)1<<15)-1)
#define PHOTOREC_MAX_SIZE_32 (((uint64_t)1<<31)-1)

typedef enum { DC_SCAN=0, DC_CONTINUE=1, DC_STOP=2, DC_ERROR=3} data_check_t;
typedef struct file_hint_struct file_hint_t;
typedef struct file_recovery_struct file_recovery_t;
typedef struct file_enable_struct file_enable_t;
typedef struct file_stat_struct file_stat_t;
typedef struct
{
  struct td_list_head list;
  uint64_t start;
  uint64_t end;
  file_stat_t *file_stat;
  unsigned int data;
} alloc_data_t;

struct file_enable_struct
{
  const file_hint_t *file_hint;
  unsigned int enable;
};

struct file_stat_struct
{
  unsigned int not_recovered;
  unsigned int recovered;
  const file_hint_t *file_hint;
};

struct file_recovery_struct
{
  char filename[2048];
  alloc_list_t location;
  file_stat_t *file_stat;
  FILE *handle;
  time_t time;
  uint64_t file_size;
  const char *extension;
  uint64_t min_filesize;
  uint64_t offset_ok;
  uint64_t offset_error;
  uint64_t extra;	/* extra bytes between offset_ok and offset_error */
  uint64_t calculated_file_size;
  data_check_t (*data_check)(const unsigned char*buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
  /* data_check modifies file_recovery->calculated_file_size but not must alter file_recovery->file_size */
  void (*file_check)(file_recovery_t *file_recovery);
  void (*file_rename)(file_recovery_t *file_recovery);
  uint64_t checkpoint_offset;
  int checkpoint_status;	/* 0=suspend at offset_checkpoint if offset_checkpoint>0, 1=resume at offset_checkpoint */
  unsigned int blocksize;
  unsigned int flags;
};

struct file_hint_struct
{
  const char *extension;
  const char *description;
  const uint64_t max_filesize;
  const int recover;
  const unsigned int enable_by_default;
  void (*register_header_check)(file_stat_t *file_stat);
};

typedef struct
{
  struct td_list_head list;
  const void *value;
  unsigned int length;
  unsigned int offset;
  int (*header_check)(const unsigned char *buffer, const unsigned int buffer_size,
      const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
  file_stat_t *file_stat;
} file_check_t;

typedef struct
{
  file_check_t file_checks[256];
  struct td_list_head list;
  unsigned int offset;
} file_check_list_t;

#define NL_BARENL       (1 << 0)
#define NL_CRLF         (1 << 1)
#define NL_BARECR       (1 << 2)

void free_header_check(void);

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires \separated(file_recovery, file_recovery->handle);
  @ ensures file_recovery->handle == \old(file_recovery->handle);
  @*/
void file_allow_nl(file_recovery_t *file_recovery, const unsigned int nl_mode);

/*@
  @ requires \valid(handle);
  @ requires 0 < footer_length < 4096;
  @ requires \valid_read((char *)footer+(0..footer_length-1));
  @ requires \separated(handle, (char *)footer + (..), &errno, &Frama_C_entropy_source);
  @ assigns *handle, errno, Frama_C_entropy_source;
  @*/
uint64_t file_rsearch(FILE *handle, uint64_t offset, const void*footer, const unsigned int footer_length);

/*@
  @ requires \valid(file_recovery);
  @ requires \valid(file_recovery->handle);
  @ requires 0 < footer_length < 4096;
  @ requires \valid_read((char *)footer+(0..footer_length-1));
  @ requires \separated(file_recovery, file_recovery->handle, file_recovery->extension, &errno, &Frama_C_entropy_source);
  @ ensures \valid(file_recovery->handle);
  @ assigns *file_recovery->handle, errno, file_recovery->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
void file_search_footer(file_recovery_t *file_recovery, const void*footer, const unsigned int footer_length, const unsigned int extra_length);

/*@
  @ requires buffer_size >= 2;
  @ requires (buffer_size&1)==0;
  @ requires \valid_read((char *)buffer+(0..buffer_size-1));
  @ requires \valid(file_recovery);
  @ requires file_recovery->data_check == &data_check_size;
  @ ensures \result == DC_STOP || \result == DC_CONTINUE;
  @ ensures file_recovery->data_check == &data_check_size;
  @ assigns \nothing;
  @*/
data_check_t data_check_size(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);

/*@
  @ requires \valid(file_recovery);
  @ requires file_recovery->file_check == &file_check_size;
  @ assigns file_recovery->file_size;
  @*/
void file_check_size(file_recovery_t *file_recovery);

/*@
  @ requires \valid(file_recovery);
  @ requires file_recovery->file_check == &file_check_size_min;
  @ assigns file_recovery->file_size;
  @*/
void file_check_size_min(file_recovery_t *file_recovery);

/*@
  @ requires \valid(file_recovery);
  @ requires file_recovery->file_check == &file_check_size_max;
  @ assigns file_recovery->file_size;
  @*/
void file_check_size_max(file_recovery_t *file_recovery);

/*@
  requires \valid(file_recovery);
  ensures file_recovery->filename[0]=='\0';
  ensures file_recovery->time==0;
  ensures file_recovery->file_stat==\null;
  ensures file_recovery->handle==\null;
  ensures file_recovery->file_size==0;
  ensures file_recovery->location.list.prev==&file_recovery->location.list;
  ensures file_recovery->location.list.next==&file_recovery->location.list;
  ensures file_recovery->location.end==0;
  ensures file_recovery->location.data==0;
  ensures file_recovery->extension==\null;
  ensures file_recovery->min_filesize==0;
  ensures file_recovery->calculated_file_size==0;
  ensures file_recovery->data_check==\null;
  ensures file_recovery->file_check==\null;
  ensures file_recovery->file_rename==\null;
  ensures file_recovery->offset_error==0;
  ensures file_recovery->offset_ok==0;
  ensures file_recovery->checkpoint_status==0;
  ensures file_recovery->checkpoint_offset==0;
  ensures file_recovery->flags==0;
  ensures file_recovery->extra==0;
  assigns file_recovery->filename[0];
  assigns file_recovery->time;
  assigns file_recovery->file_stat;
  assigns file_recovery->handle;
  assigns file_recovery->file_size;
  assigns file_recovery->location.list.prev;
  assigns file_recovery->location.list.next;
  assigns file_recovery->location.end;
  assigns file_recovery->location.data;
  assigns file_recovery->extension;
  assigns file_recovery->min_filesize;
  assigns file_recovery->calculated_file_size;
  assigns file_recovery->data_check;
  assigns file_recovery->file_check;
  assigns file_recovery->file_rename;
  assigns file_recovery->offset_error;
  assigns file_recovery->offset_ok;
  assigns file_recovery->checkpoint_status;
  assigns file_recovery->checkpoint_offset;
  assigns file_recovery->flags;
  assigns file_recovery->extra;
*/
void reset_file_recovery(file_recovery_t *file_recovery);

/*@
  @ requires offset < 0x80000000;
  @ requires 0 < length <= 4096;
  @ requires \valid_read((char *)value+(0..length-1));
  @ requires \valid_function(header_check);
  @ requires \valid(file_stat);
  @*/
void register_header_check(const unsigned int offset, const void *value, const unsigned int length,
    int (*header_check)(const unsigned char *buffer, const unsigned int buffer_size,
      const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new),
    file_stat_t *file_stat);

/*@
  @ requires \valid(files_enable);
  @*/
file_stat_t * init_file_stats(file_enable_t *files_enable);

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires \valid_read((char *)buffer+(0..buffer_size-1));
  @ requires new_ext==\null || valid_read_string(new_ext);
  @ ensures valid_read_string((char*)&file_recovery->filename);
  @*/
int file_rename(file_recovery_t *file_recovery, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int force_ext);

/*@
  @ requires \valid(file_recovery);
  @ requires valid_read_string((char*)&file_recovery->filename);
  @ requires \valid_read((char *)buffer+(0..buffer_size-1));
  @ requires new_ext==\null || valid_read_string(new_ext);
  @ ensures valid_read_string((char*)&file_recovery->filename);
  @*/
int file_rename_unicode(file_recovery_t *file_recovery, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int force_ext);

void header_ignored_cond_reset(uint64_t start, uint64_t end);

/*@
  @ requires file_recovery_new==\null || \valid_read(file_recovery_new);
  @*/
void header_ignored(const file_recovery_t *file_recovery_new);

/*@
  @ requires separation: \separated(file_recovery, file_recovery_new, &errno);
  @ requires \valid_read(file_recovery);
  @ requires \valid_read(file_recovery_new);
  @ requires file_recovery->handle == \null || \valid(file_recovery->handle);
  @ requires \valid_function(file_recovery->file_check);
  @ requires \initialized(&file_recovery->file_check);
  @ requires \initialized(&file_recovery->handle);
  @ requires \separated(file_recovery, file_recovery->handle);
  @ ensures \result == 0 || \result == 1;
  @*/
int header_ignored_adv(const file_recovery_t *file_recovery, const file_recovery_t *file_recovery_new);

/*@
  requires valid_stream: \valid(stream);
  requires whence_enum: whence == SEEK_SET || whence == SEEK_CUR || whence == SEEK_END;
  requires \separated(&errno, stream);
  assigns *stream \from *stream, indirect:offset, indirect:whence;
  assigns \result, errno \from indirect:*stream, indirect:offset,
                                    indirect:whence;
*/
int my_fseek(FILE *stream, off_t offset, int whence);

/*@
  @ requires \valid_read(date_asc + (0 .. 11));
  @ assigns \nothing;
  @*/
time_t get_time_from_YYMMDDHHMMSS(const char *date_asc);

/*@
  @ requires \valid_read(date_asc + (0 .. 18));
  @ assigns \nothing;
  @*/
time_t get_time_from_YYYY_MM_DD_HH_MM_SS(const unsigned char *date_asc);

/*@
  @ requires \valid_read(date_asc + (0 .. 16));
  @ assigns \nothing;
  @*/
time_t get_time_from_YYYY_MM_DD_HHMMSS(const char *date_asc);

/*@
  @ requires \valid_read(date_asc + (0 .. 14));
  @ assigns \nothing;
  @*/
time_t get_time_from_YYYYMMDD_HHMMSS(const char *date_asc);

/*@
  @ requires \valid(list_search_space);
  @ requires \valid(current_search_space);
  @ requires \valid(offset);
  @*/
void get_prev_location_smart(const alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset, const uint64_t prev_location);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
