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
  void (*file_rename)(const char *old_filename);
  uint64_t checkpoint_offset;
  int checkpoint_status;	/* 0=suspend at offset_checkpoint if offset_checkpoint>0, 1=resume at offset_checkpoint */
  unsigned int blocksize;
  unsigned int flags;
};

struct file_hint_struct
{
  const char *extension;
  const char *description;
  const uint64_t min_header_distance;
  /* don't try head_check if min_header_distance >0 and previous_header_distance <= min_header_distance */
  /* needed by tar header */
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
void file_allow_nl(file_recovery_t *file_recovery, const unsigned int nl_mode);
uint64_t file_rsearch(FILE *handle, uint64_t offset, const void*footer, const unsigned int footer_length);
void file_search_footer(file_recovery_t *file_recovery, const void*footer, const unsigned int footer_length, const unsigned int extra_length);
void file_search_lc_footer(file_recovery_t *file_recovery, const unsigned char*footer, const unsigned int footer_length);
void del_search_space(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end);
data_check_t data_check_size(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
void file_check_size_lax(file_recovery_t *file_recovery);
void file_check_size(file_recovery_t *file_recovery);
void reset_file_recovery(file_recovery_t *file_recovery);
void register_header_check(const unsigned int offset, const void *value, const unsigned int length, int (*header_check)(const unsigned char *buffer, const unsigned int buffer_size,
      const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new),
  file_stat_t *file_stat);
file_stat_t * init_file_stats(file_enable_t *files_enable);
void file_rename(const char *old_filename, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int force_ext);
void file_rename_unicode(const char *old_filename, const void *buffer, const int buffer_size, const int offset, const char *new_ext, const int force_ext);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
