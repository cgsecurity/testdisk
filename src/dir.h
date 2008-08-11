/*

    File: dir.h

    Copyright (C) 2004-2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifndef _DIR_H
#define _DIR_H
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "list.h"
#define DIR_NAME_LEN 1024
#define FLAG_LIST_DELETED	1
#define FLAG_LIST_MASK12	2
#define FLAG_LIST_MASK16	4
/* capabilities */
#define CAPA_LIST_DELETED	1

typedef struct dir_data dir_data_t;
typedef struct file_data file_data_t;

struct dir_data
{
  void *display;
  char current_directory[DIR_NAME_LEN];
  unsigned long int current_inode;
  int verbose;
  unsigned int param;
  unsigned int capabilities;
  file_data_t *(*get_dir)(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int first_inode);
  int (*copy_file)(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const file_data_t *file);
  void (*close)(dir_data_t *dir_data);
  char *local_dir;
  void *private_dir_data;
};

#define	FILE_STATUS_DELETED	1

/* TODO: add status to file_info and migrate file_data to file_info */
struct file_data
{
  file_data_t *prev;
  file_data_t *next;
  char	name[DIR_NAME_LEN];
  struct stat stat;
  unsigned int status;
};

typedef struct 
{
  struct td_list_head list;
  char name[4096];
  struct stat stat;
  unsigned int status;
} file_info_t;

int dir_aff_log(const disk_t *disk_car, const partition_t *partition, const dir_data_t *dir_data, const file_data_t*dir_list);
int log_list_file(const disk_t *disk_car, const partition_t *partition, const dir_data_t *dir_data, const file_info_t*list);
void delete_list_file(file_data_t *file_list);
void delete_list_file_info(struct td_list_head *list);
int dir_partition_aff(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, char **current_cmd);
int dir_whole_partition_log(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode);
void mode_string (const unsigned int mode, char *str);
FILE *create_file(const char *filename);
int set_date(const char *pathname, time_t actime, time_t modtime);
int set_mode(const char *pathname, unsigned int mode);

#define LINUX_S_IFMT  00170000
#define LINUX_S_IFSOCK 0140000
#define LINUX_S_IFLNK    0120000
#define LINUX_S_IFREG  0100000
#define LINUX_S_IFBLK  0060000
#define LINUX_S_IFDIR  0040000
#define LINUX_S_IFCHR  0020000
#define LINUX_S_IFIFO  0010000
#define LINUX_S_ISUID  0004000
#define LINUX_S_ISGID  0002000
#define LINUX_S_ISVTX  0001000


#define LINUX_S_IRWXU 00700
#define LINUX_S_IRUSR 00400
#define LINUX_S_IWUSR 00200
#define LINUX_S_IXUSR 00100

#define LINUX_S_IRWXG 00070
#define LINUX_S_IRGRP 00040
#define LINUX_S_IWGRP 00020
#define LINUX_S_IXGRP 00010

#define LINUX_S_IRWXO 00007
#define LINUX_S_IROTH 00004
#define LINUX_S_IWOTH 00002
#define LINUX_S_IXOTH 00001

#define LINUX_S_IRWXUGO       (LINUX_S_IRWXU|LINUX_S_IRWXG|LINUX_S_IRWXO)
#define LINUX_S_IALLUGO       (LINUX_S_ISUID|LINUX_S_ISGID|LINUX_S_ISVTX|LINUX_S_IRWXUGO)
#define LINUX_S_IRUGO         (LINUX_S_IRUSR|LINUX_S_IRGRP|LINUX_S_IROTH)
#define LINUX_S_IWUGO         (LINUX_S_IWUSR|LINUX_S_IWGRP|LINUX_S_IWOTH)
#define LINUX_S_IXUGO         (LINUX_S_IXUSR|LINUX_S_IXGRP|LINUX_S_IXOTH)

#define LINUX_S_ISLNK(m)        (((m) & LINUX_S_IFMT) == LINUX_S_IFLNK)
#define LINUX_S_ISREG(m)        (((m) & LINUX_S_IFMT) == LINUX_S_IFREG)
#define LINUX_S_ISDIR(m)        (((m) & LINUX_S_IFMT) == LINUX_S_IFDIR)
#define LINUX_S_ISCHR(m)        (((m) & LINUX_S_IFMT) == LINUX_S_IFCHR)
#define LINUX_S_ISBLK(m)        (((m) & LINUX_S_IFMT) == LINUX_S_IFBLK)
#define LINUX_S_ISFIFO(m)       (((m) & LINUX_S_IFMT) == LINUX_S_IFIFO)
#define LINUX_S_ISSOCK(m)       (((m) & LINUX_S_IFMT) == LINUX_S_IFSOCK)

int filesort(const struct td_list_head *a, const struct td_list_head *b);
#endif
