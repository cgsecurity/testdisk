/*

    File: photorec.h

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

#ifndef _TESTDISK_PHOTOREC_H
#define _TESTDISK_PHOTOREC_H
#define MAX_FILES_PER_DIR	500
#define DEFAULT_RECUP_DIR "recup_dir"
#ifdef __cplusplus
extern "C" {
#endif

enum photorec_status { STATUS_FIND_OFFSET, STATUS_UNFORMAT, STATUS_EXT2_ON, STATUS_EXT2_ON_BF, STATUS_EXT2_OFF, STATUS_EXT2_OFF_BF, STATUS_EXT2_ON_SAVE_EVERYTHING, STATUS_EXT2_OFF_SAVE_EVERYTHING, STATUS_QUIT };
typedef enum photorec_status photorec_status_t;

typedef enum { PSTATUS_OK=0, PSTATUS_STOP=1, PSTATUS_EACCES=2, PSTATUS_ENOSPC=3} pstatus_t;
typedef enum { PFSTATUS_BAD=0, PFSTATUS_OK=1, PFSTATUS_OK_TRUNCATED=2} pfstatus_t;

struct ph_options
{
  int paranoid;
  int keep_corrupted_file;
  unsigned int mode_ext2;
  unsigned int expert;
  unsigned int lowmem;
  int verbose;
  file_enable_t *list_file_format;
};

struct ph_param
{
  char *cmd_device;
  char *cmd_run;
  disk_t *disk;
  partition_t *partition;
  unsigned int carve_free_space_only;
  unsigned int blocksize;
  unsigned int pass;
  photorec_status_t status;
  time_t real_start_time;
  char *recup_dir;
  /* */
  unsigned int dir_num;
  unsigned int file_nbr;
  file_stat_t *file_stats;
  uint64_t offset;
};

/*@
   predicate valid_ph_param(struct ph_param *p) = (\valid_read(p) &&
	(p->recup_dir == \null || valid_read_string(p->recup_dir)) &&
	(p->disk == \null || valid_disk(p->disk)) &&
	(p->cmd_run == \null || valid_read_string(p->cmd_run))
	);
  @*/

#define PH_INVALID_OFFSET	0xffffffffffffffff

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(list_search_space, current_search_space, offset);
  @ requires current_search_space==\null || (\valid(*current_search_space) && valid_list_search_space(*current_search_space));
  @ ensures  \result==0 ==> (*current_search_space!=list_search_space && *offset == (*current_search_space)->start);
  @*/
// ensures  current_search_space==\null || (\valid(*current_search_space) && valid_list_search_space(*current_search_space));
int get_prev_file_header(const alloc_data_t *list_search_space, alloc_data_t **current_search_space, uint64_t *offset);

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, params, list_search_space);
  @ requires valid_disk(params->disk);
  @*/
int file_finish_bf(file_recovery_t *file_recovery, struct ph_param *params, 
    alloc_data_t *list_search_space);

/*@
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires valid_list_search_space(list_search_space);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \separated(file_recovery, params, list_search_space, &errno);
  @*/
void file_recovery_aborted(file_recovery_t *file_recovery, struct ph_param *params, alloc_data_t *list_search_space);

/*@
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, params, list_search_space);
  @ requires valid_disk(params->disk);
  @ ensures  \result == PFSTATUS_BAD || \result == PFSTATUS_OK || \result == PFSTATUS_OK_TRUNCATED;
  @*/
// ensures  valid_file_recovery(file_recovery);
pfstatus_t file_finish2(file_recovery_t *file_recovery, struct ph_param *params, const int paranoid, alloc_data_t *list_search_space);

/*@
  @ requires \valid_read(file_stats);
  @*/
void write_stats_log(const file_stat_t *file_stats);

/*@
  @ requires \valid(file_stats);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_stats, list_search_space);
  @*/
//ensures  valid_list_search_space(list_search_space);
void update_stats(file_stat_t *file_stats, alloc_data_t *list_search_space);
/*@
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @*/
// ensures  valid_partition(\result);
partition_t *new_whole_disk(const disk_t *disk_car);

/*@
  @ requires valid_list_search_space(list_file);
  @ requires \valid(offset);
  @ requires \separated(list_file, offset);
  @ requires default_blocksize > 0;
  @*/
// ensures  \result > 0;
unsigned int find_blocksize(const alloc_data_t *list_file, const unsigned int default_blocksize, uint64_t *offset);

/*@
  @ requires blocksize > 0;
  @ requires valid_list_search_space(list_search_space);
  @*/
void update_blocksize(const unsigned int blocksize, alloc_data_t *list_search_space, const uint64_t offset);

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires current_search_space==\null || valid_list_search_space(current_search_space);
  @*/
// ensures  current_search_space==\null || valid_list_search_space(current_search_space);
void forget(const alloc_data_t *list_search_space, alloc_data_t *current_search_space);

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires \valid_read(disk_car);
  @ requires valid_disk(disk_car);
  @ requires disk_car->disk_size > 0;
  @ requires disk_car->disk_real_size > 0;
  @ requires \valid_read(partition);
  @ requires separation: \separated(list_search_space, disk_car, partition);
  @*/
void init_search_space(alloc_data_t *list_search_space, const disk_t *disk_car, const partition_t *partition);

/*@
  @ requires valid_disk(disk_car);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(disk_car, partition, list_search_space);
  @ ensures  valid_list_search_space(list_search_space);
  @ ensures  valid_disk(disk_car);
  @ ensures  valid_list_search_space(list_search_space);
  @*/
unsigned int remove_used_space(disk_t *disk_car, const partition_t *partition, alloc_data_t *list_search_space);

/*@
  @ requires valid_list_search_space(list_search_space);
  @*/
void free_list_search_space(alloc_data_t *list_search_space);

/*@
  @ requires \valid_read((const file_stat_t *)p1);
  @ requires \valid_read((const file_stat_t *)p2);
  @ terminates \true;
  @ assigns \nothing;
  @*/
int sorfile_stat_ts(const void *p1, const void *p2);

/*@
  @ requires valid_read_string(recup_dir);
  @ requires \separated(recup_dir, &errno);
  @*/
unsigned int photorec_mkdir(const char *recup_dir, const unsigned int initial_dir_num);

/*@
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(list_search_space, current_search_space);
  @ ensures  valid_list_search_space(list_search_space);
  @*/
void info_list_search_space(const alloc_data_t *list_search_space, const alloc_data_t *current_search_space, const unsigned int sector_size, const int keep_corrupted_file, const int verbose);

/*@
  @ requires valid_list_search_space(list_search_space);
  @*/
void free_search_space(alloc_data_t *list_search_space);

/*@
  @ requires \valid(file_recovery);
  @ requires valid_file_recovery(file_recovery);
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \separated(file_recovery, params);
  @ requires valid_disk(params->disk);
  @*/
// ensures  valid_file_recovery(file_recovery);
void set_filename(file_recovery_t *file_recovery, struct ph_param *params);

/*@
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires valid_disk(params->disk);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(params, new_current_search_space, list_search_space);
  @ requires \valid(*new_current_search_space);
  @ requires valid_list_search_space(*new_current_search_space);
  @*/
// ensures  \valid(*new_current_search_space) && valid_list_search_space(*new_current_search_space);
// ensures  valid_list_search_space(list_search_space);
uint64_t set_search_start(struct ph_param *params, alloc_data_t **new_current_search_space, alloc_data_t *list_search_space);

/*@
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \valid_read(options);
  @ requires \separated(params, options);
  @ requires params->disk->sector_size > 0;
  @ requires valid_read_string(params->recup_dir);
  @ requires valid_file_enable_node(options->list_file_format);
  @ ensures  valid_ph_param(params);
  @ ensures  params->file_nbr == 0;
  @ ensures  params->status == STATUS_FIND_OFFSET;
  @ ensures  params->dir_num == 1;
  @ ensures  params->offset == PH_INVALID_OFFSET;
  @ ensures  params->blocksize > 0;
  @ ensures  valid_read_string(params->recup_dir);
  @*/
void params_reset(struct ph_param *params, const struct ph_options *options);

/*@
  @ assigns \nothing;
  @*/
const char *status_to_name(const photorec_status_t status);

/*@
  @ requires \valid(params);
  @ requires valid_ph_param(params);
  @ requires \valid_read(options);
  @ requires \separated(params, options);
  @ ensures  valid_ph_param(params);
  @ assigns  params->offset, params->status, params->file_nbr;
  @*/
void status_inc(struct ph_param *params, const struct ph_options *options);

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(&disk->arch);
  @ requires \valid_function(disk->arch->read_part);
  @ requires \valid_read(options);
  @ requires \separated(disk, options);
  @ decreases 0;
  @ ensures  valid_disk(disk);
  @*/
// ensures  valid_list_part(\result);
list_part_t *init_list_part(disk_t *disk, const struct ph_options *options);

/*@
  @ requires valid_file_recovery(file_recovery);
  @*/
// ensures  valid_file_recovery(file_recovery);
void file_block_log(const file_recovery_t *file_recovery, const unsigned int sector_size);

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, list_search_space, new_current_search_space, offset);
  @ requires new_current_search_space==\null || (\valid(*new_current_search_space) && valid_list_search_space(*new_current_search_space));
  @*/
// ensures  new_current_search_space==\null || (\valid(*new_current_search_space) && valid_list_search_space(*new_current_search_space));
// ensures  valid_file_recovery(file_recovery);
// ensures  valid_list_search_space(list_search_space);
void file_block_append(file_recovery_t *file_recovery, alloc_data_t *list_search_space, alloc_data_t **new_current_search_space, uint64_t *offset, const unsigned int blocksize, const unsigned int data);

/*@
  @ requires valid_file_recovery(file_recovery);
  @ requires valid_list_search_space(list_search_space);
  @ requires \separated(file_recovery, list_search_space, new_current_search_space, offset, buffer + (..));
  @ requires new_current_search_space==\null || (\valid(*new_current_search_space) && valid_list_search_space(*new_current_search_space));
  @ decreases 0;
  @*/
// ensures  new_current_search_space==\null || (\valid(*new_current_search_space) && valid_list_search_space(*new_current_search_space));
// ensures  valid_file_recovery(file_recovery);
// ensures  valid_list_search_space(list_search_space);
void file_block_truncate_and_move(file_recovery_t *file_recovery, alloc_data_t *list_search_space, const unsigned int blocksize,  alloc_data_t **new_current_search_space, uint64_t *offset, unsigned char *buffer);

/*@
  @ requires \valid(list_search_space);
  @ requires valid_list_search_space(list_search_space);
  @*/
void del_search_space(alloc_data_t *list_search_space, const uint64_t start, const uint64_t end);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif
#endif
