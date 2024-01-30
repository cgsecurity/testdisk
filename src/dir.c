/*

    File: dir.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#ifdef DISABLED_FOR_FRAMAC
#undef HAVE_CHMOD
#endif
 
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include "types.h"
#include <errno.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "common.h"
#include "dir.h"
#include "log.h"
#include "log_part.h"
#define MAX_DIR_NBR 256

const char *monstr[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/*@
  @ terminates \true;
  @ assigns \result;
  @*/
static char ftypelet (unsigned int bits)
{
#ifdef LINUX_S_ISBLK
  if (LINUX_S_ISBLK (bits))
    return 'b';
#endif
  if (LINUX_S_ISCHR (bits))
    return 'c';
  if (LINUX_S_ISDIR (bits))
    return 'd';
  if (LINUX_S_ISREG (bits))
    return '-';
#ifdef LINUX_S_ISFIFO
  if (LINUX_S_ISFIFO (bits))
    return 'p';
#endif
#ifdef LINUX_S_ISLNK
  if (LINUX_S_ISLNK (bits))
    return 'l';
#endif
#ifdef LINUX_S_ISSOCK
  if (LINUX_S_ISSOCK (bits))
    return 's';
#endif
#ifdef LINUX_S_ISMPC
  if (LINUX_S_ISMPC (bits))
    return 'm';
#endif
#ifdef LINUX_S_ISNWK
  if (LINUX_S_ISNWK (bits))
    return 'n';
#endif
#ifdef LINUX_S_ISDOOR
  if (LINUX_S_ISDOOR (bits))
    return 'D';
#endif
#ifdef LINUX_S_ISCTG
  if (LINUX_S_ISCTG (bits))
    return 'C';
#endif
#ifdef LINUX_S_ISOFD
  if (LINUX_S_ISOFD (bits))
    /* off line, with data  */
    return 'M';
#endif
#ifdef LINUX_S_ISOFL
  /* off line, with no data  */
  if (LINUX_S_ISOFL (bits))
    return 'M';
#endif
  return '?';
}

void mode_string (const unsigned int mode, char *str)
{
#ifndef DISABLED_FOR_FRAMAC
  str[0] = ftypelet(mode);
  str[1] = (mode & LINUX_S_IRUSR) ? 'r' : '-';
  str[2] = (mode & LINUX_S_IWUSR) ? 'w' : '-';
  str[3] = (mode & LINUX_S_IXUSR) ? 'x' : '-';
  str[4] = (mode & LINUX_S_IRGRP) ? 'r' : '-';
  str[5] = (mode & LINUX_S_IWGRP) ? 'w' : '-';
  str[6] = (mode & LINUX_S_IXGRP) ? 'x' : '-';
  str[7] = (mode & LINUX_S_IROTH) ? 'r' : '-';
  str[8] = (mode & LINUX_S_IWOTH) ? 'w' : '-';
  str[9] = (mode & LINUX_S_IXOTH) ? 'x' : '-';
  str[10]='\0';
#ifdef LINUX_S_ISUID
  if (mode & LINUX_S_ISUID)
  {
    if (str[3] != 'x')
      /* Set-uid, but not executable by owner.  */
      str[3] = 'S';
    else
      str[3] = 's';
  }
#endif
#ifdef LINUX_S_ISGID
  if (mode & LINUX_S_ISGID)
  {
    if (str[6] != 'x')
      /* Set-gid, but not executable by group.  */
      str[6] = 'S';
    else
      str[6] = 's';
  }
#endif
#ifdef LINUX_S_ISVTX
  if (mode & LINUX_S_ISVTX)
  {
    if (str[9] != 'x')
      /* Sticky, but not executable by others.  */
      str[9] = 'T';
    else
      str[9] = 't';
  }
#endif
#endif
}

int set_datestr(char *datestr, size_t n, const time_t timev)
{
  const struct tm *tm_p;
#if ! defined(__MINGW32__)
  struct tm tmp;
#endif
  if(timev==0)
  {
    strncpy(datestr, "                 ", n);
    return 0;
  }
#if defined(__MINGW32__) || defined(DISABLED_FOR_FRAMAC)
  tm_p=localtime(&timev);
#else
  tm_p=localtime_r(&timev, &tmp);
#endif
  if(tm_p==NULL)
  {
    strncpy(datestr, "                 ", n);
    return 0;
  }
  snprintf(datestr, n,"%2d-%s-%4d %02d:%02d",
      tm_p->tm_mday, monstr[tm_p->tm_mon],
      1900 + tm_p->tm_year, tm_p->tm_hour,
      tm_p->tm_min);
  if(1900+tm_p->tm_year>=2000)
    return 1;
  return 0;
}

int dir_aff_log(const dir_data_t *dir_data, const file_info_t *dir_list)
{
  int test_date=0;
  struct td_list_head *file_walker = NULL;
  if(dir_data!=NULL)
  {
    log_info("Directory %s\n",dir_data->current_directory);
  }
#ifndef DISABLED_FOR_FRAMAC
  td_list_for_each(file_walker, &dir_list->list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    char		datestr[80];
    char str[11];
    test_date=set_datestr((char *)&datestr, sizeof(datestr), current_file->td_mtime);
    mode_string(current_file->st_mode, str);
    if((current_file->status&FILE_STATUS_DELETED)!=0)
      log_info("X");
    else
      log_info(" ");
    log_info("%7lu %s %5u  %5u %9llu %s ",
	(unsigned long int)current_file->st_ino,
	str,
	(unsigned int)current_file->st_uid,
	(unsigned int)current_file->st_gid,
	(long long unsigned int)current_file->st_size,
	datestr);
    if(dir_data!=NULL && (dir_data->param&FLAG_LIST_PATHNAME)!=0)
    {
      if(dir_data->current_directory[1]!='\0')
	log_info("%s/", dir_data->current_directory);
      else
	log_info("/");
    }
    log_info("%s\n", current_file->name);
  }
#endif
  return test_date;
}

void log_list_file(const disk_t *disk, const partition_t *partition, const dir_data_t *dir_data, const file_info_t*list)
{
#ifndef DISABLED_FOR_FRAMAC
  struct td_list_head *tmp;
  log_partition(disk, partition);
  if(dir_data!=NULL)
  {
    log_info("Directory %s\n",dir_data->current_directory);
  }
  td_list_for_each(tmp, &list->list)
  {
    char		datestr[80];
    char str[11];
    const file_info_t *current_file=td_list_entry_const(tmp, const file_info_t, list);
    if((current_file->status&FILE_STATUS_DELETED)!=0)
      log_info("X");
    else
      log_info(" ");
    set_datestr((char *)&datestr, sizeof(datestr), current_file->td_mtime);
    mode_string(current_file->st_mode, str);
    log_info("%7lu ",(unsigned long int)current_file->st_ino);
    log_info("%s %5u %5u ", 
	str, (unsigned int)current_file->st_uid, (unsigned int)current_file->st_gid);
    log_info("%9llu", (long long unsigned int)current_file->st_size);
    log_info(" %s %s\n", datestr, current_file->name);
  }
#endif
}

unsigned int delete_list_file(file_info_t *file_info)
{
  unsigned int nbr=0;
  struct td_list_head *file_walker = NULL;
  struct td_list_head *file_walker_next = NULL;
#ifndef DISABLED_FOR_FRAMAC
  td_list_for_each_safe(file_walker,file_walker_next, &file_info->list)
  {
    file_info_t *tmp;
    tmp=td_list_entry(file_walker, file_info_t, list);
    free(tmp->name);
    td_list_del(file_walker);
    free(tmp);
    nbr++;
  }
#endif
  return nbr;
}

/*@
  @ requires \valid_read(current_file);
  @ requires \valid_read(inode_known + (0 .. dir_nbr-1));
  @ assigns \nothing;
  @*/
static int is_inode_valid(const file_info_t *current_file, const unsigned int dir_nbr, const unsigned long int *inode_known)
{
  const unsigned long int new_inode=current_file->st_ino;
  unsigned int i;
  if(new_inode<2)
    return 0;
  if(strcmp(current_file->name, "..")==0)
    return 0;
  /*@
    @ loop assigns i;
    @ loop variant dir_nbr - i;
    @*/
  for(i=0; i<dir_nbr; i++)
    if(new_inode==inode_known[i]) /* Avoid loop */
      return 0;
  return 1;
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid(dir_data);
  @ requires \separated(disk, partition, dir_data);
  @ decreases 0;
  @*/
static int dir_whole_partition_log_aux(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode)
{
  struct td_list_head *file_walker = NULL;
  static unsigned int dir_nbr=0;
  static unsigned long int inode_known[MAX_DIR_NBR];
  const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
  file_info_t dir_list;
  TD_INIT_LIST_HEAD(&dir_list.list);
  if(dir_nbr==MAX_DIR_NBR)
    return 1;	/* subdirectories depth is too high => Back */
  if(dir_data->verbose>0)
    log_info("\ndir_partition inode=%lu\n",inode);
  dir_data->get_dir(disk, partition, dir_data, inode, &dir_list);
  dir_aff_log(dir_data, &dir_list);
  /* Not perfect for FAT32 root cluster */
  inode_known[dir_nbr++]=inode;
  td_list_for_each(file_walker, &dir_list.list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    if(LINUX_S_ISDIR(current_file->st_mode)!=0 &&
	is_inode_valid(current_file, dir_nbr, inode_known)>0 &&
	strlen(dir_data->current_directory)+1+strlen(current_file->name)<sizeof(dir_data->current_directory)-1)
    {
      if(strcmp(dir_data->current_directory,"/"))
	strcat(dir_data->current_directory,"/");
      strcat(dir_data->current_directory,current_file->name);
      dir_whole_partition_log_aux(disk, partition, dir_data, current_file->st_ino);
      /* restore current_directory name */
      dir_data->current_directory[current_directory_namelength]='\0';
    }
  }
  delete_list_file(&dir_list);
  dir_nbr--;
  return 0;
}

int dir_whole_partition_log(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode)
{
  log_partition(disk, partition);
  return dir_whole_partition_log_aux(disk, partition, dir_data, inode);
}

/*@
  @ requires \valid(disk);
  @ requires valid_disk(disk);
  @ requires \valid_read(partition);
  @ requires valid_partition(partition);
  @ requires \valid(dir_data);
  @ requires \valid(copy_ok);
  @ requires \valid(copy_bad);
  @ requires \separated(disk, partition, dir_data, copy_ok, copy_bad);
  @ decreases 0;
  @*/
static int dir_whole_partition_copy_aux(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode, unsigned int *copy_ok, unsigned int *copy_bad)
{
  struct td_list_head *file_walker = NULL;
  static unsigned int dir_nbr=0;
  static unsigned long int inode_known[MAX_DIR_NBR];
  const unsigned int current_directory_namelength=strlen(dir_data->current_directory);
  file_info_t dir_list;
  TD_INIT_LIST_HEAD(&dir_list.list);
  if(dir_nbr==MAX_DIR_NBR)
    return 1;	/* subdirectories depth is too high => Back */
  dir_data->get_dir(disk, partition, dir_data, inode, &dir_list);
  /* Not perfect for FAT32 root cluster */
  inode_known[dir_nbr++]=inode;
  td_list_for_each(file_walker, &dir_list.list)
  {
    const file_info_t *current_file=td_list_entry_const(file_walker, const file_info_t, list);
    if(strlen(dir_data->current_directory) + 1 + strlen(current_file->name) <
	sizeof(dir_data->current_directory)-1)
    {
      if(strcmp(dir_data->current_directory,"/"))
	strcat(dir_data->current_directory,"/");
      strcat(dir_data->current_directory,current_file->name);
      if(LINUX_S_ISDIR(current_file->st_mode)!=0)
      {
	if(is_inode_valid(current_file, dir_nbr, inode_known)>0)
	{
	  dir_whole_partition_copy_aux(disk, partition, dir_data, current_file->st_ino, copy_ok, copy_bad);
	}
      }
      else if(LINUX_S_ISREG(current_file->st_mode)!=0)
      {
	if(dir_data->copy_file(disk, partition, dir_data, current_file) == 0)
	  (*copy_ok)++;
	else
	  (*copy_bad)++;
      }
    }
    /* restore current_directory name */
    dir_data->current_directory[current_directory_namelength]='\0';
  }
  delete_list_file(&dir_list);
  dir_nbr--;
  return 0;
}

void dir_whole_partition_copy(disk_t *disk, const partition_t *partition, dir_data_t *dir_data, const unsigned long int inode)
{
  unsigned int copy_ok=0;
  unsigned int copy_bad=0;
  char *dst_directory=(char *)MALLOC(4096);
  dst_directory[0]='.';
  dst_directory[1]='\0';
#ifdef HAVE_GETCWD
  if(getcwd(dst_directory, 4096)==NULL)
  {
    free(dst_directory);
    return ;
  }
#endif
  dir_data->local_dir=dst_directory;
  dir_whole_partition_copy_aux(disk, partition, dir_data, inode, &copy_ok, &copy_bad);
  log_info("Copy done! %u ok, %u failed", copy_ok, copy_bad);
}

int filesort(const struct td_list_head *a, const struct td_list_head *b)
{
  const file_info_t *file_a=td_list_entry_const(a, const file_info_t, list);
  /*@ assert \valid_read(file_a); */
  const file_info_t *file_b=td_list_entry_const(b, const file_info_t, list);
  /*@ assert \valid_read(file_b); */
  /* Directories must be listed before files */
  const int res=((file_b->st_mode&LINUX_S_IFDIR)-(file_a->st_mode&LINUX_S_IFDIR));
  if(res)
    return res;
  /*@ assert valid_read_string(file_a->name); */
  /* . and .. must listed before the other directories */
  if((file_a->st_mode&LINUX_S_IFDIR) && strcmp(file_a->name, ".")==0)
    return -1;
  if((file_a->st_mode&LINUX_S_IFDIR) && strcmp(file_a->name, "..")==0 &&
      strcmp(file_b->name, ".")!=0)
    return -1;
  /*@ assert valid_read_string(file_b->name); */
  if((file_b->st_mode&LINUX_S_IFDIR) && strcmp(file_b->name, ".")==0)
    return 1;
  if((file_b->st_mode&LINUX_S_IFDIR) && strcmp(file_b->name, "..")==0 &&
      strcmp(file_a->name, ".")!=0)
    return 1;
  /* Files and directories are sorted by name */
  return strcmp(file_a->name, file_b->name);
}

/*
 * The mode_xlate function translates a linux mode into a native-OS mode_t.
 */

static struct {
  unsigned int lmask;
  mode_t mask;
} mode_table[] = {
#ifdef S_IRUSR
  { LINUX_S_IRUSR, S_IRUSR },
#endif
#ifdef S_IWUSR
  { LINUX_S_IWUSR, S_IWUSR },
#endif
#ifdef S_IXUSR
  { LINUX_S_IXUSR, S_IXUSR },
#endif
#ifdef S_IRGRP
  { LINUX_S_IRGRP, S_IRGRP },
#endif
#ifdef S_IWGRP
  { LINUX_S_IWGRP, S_IWGRP },
#endif
#ifdef S_IXGRP
  { LINUX_S_IXGRP, S_IXGRP },
#endif
#ifdef S_IROTH
  { LINUX_S_IROTH, S_IROTH },
#endif
#ifdef S_IWOTH
  { LINUX_S_IWOTH, S_IWOTH },
#endif
#ifdef S_IXOTH
  { LINUX_S_IXOTH, S_IXOTH },
#endif
  { 0, 0 }
};

/*@
  @ assigns \nothing;
  @*/
static mode_t mode_xlate(unsigned int lmode)
{
  unsigned int i;
  mode_t  mode = 0;
  /*@
    @ loop unroll 20;
    @ loop assigns i, mode;
    @*/
  for (i=0; mode_table[i].lmask; i++)
  {
    if (lmode & mode_table[i].lmask)
      mode |= mode_table[i].mask;
  }
  return mode;
}

/**
 * set_mode - Set the file's date and time
 * @pathname:  Path and name of the file to alter
 * @mode:    Mode using LINUX values
 *
 * Give a file a particular mode.
 *
 * Return:  0  Success, set the file's mode
 *	    -1  Error, failed to change the file's mode
 */
int set_mode(const char *pathname, unsigned int mode)
{
#if defined(HAVE_CHMOD) && ! ( defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP) || defined(__OS2__))
  return chmod(pathname, mode_xlate(mode));
#else
  return 0;
#endif
}

/*@
  @ requires valid_string(fn);
  @*/
static void strip_fn(char *fn)
{
  unsigned int i;
  /*@
    @ loop assigns i;
    @*/
  for(i=0;fn[i]!='\0';i++);
  /*@
    @ loop assigns i;
    @ loop invariant i;
    @*/
  while(i>0 && (fn[i-1]==' '||fn[i-1]=='.'))
    i--;
  if(i==0 && (fn[i]==' '||fn[i]=='.'))
    fn[i++]='_';
  fn[i]='\0';
}

#ifdef DJGPP
static inline unsigned char convert_char_dos(unsigned char car)
{
  if(car<0x20)
    return '_';
  switch(car)
  {
    /* Forbidden */
    case '<':
    case '>':
    case ':':
    case '"':
    /* case '/': subdirectory */
    case '\\':
    case '|':
    case '?':
    case '*':
    /* Not recommanded */
    case '[':
    case ']':
    case ';':
    case ',':
    case '+':
    case '=':
      return '_';
  }
  /* 'a' */
  if(car>=224 && car<=230)      
    return 'a';
  /* 'c' */
  if(car==231)
    return 'c';
  /* 'e' */
  if(car>=232 && car<=235)
    return 'e';
  /* 'i' */
  if(car>=236 && car<=239)
    return 'n';
  /* n */
  if(car==241)
    return 'n';
  /* 'o' */
  if((car>=242 && car<=246) || car==248)
    return 'o';
  /* 'u' */
  if(car>=249 && car<=252)
    return 'u';
  /* 'y' */
  if(car>=253)
    return 'y';
  return car;
}

/*
 * filename_convert reads a maximum of n and writes a maximum of n+1 bytes
 * dst string will be null-terminated
 */
static unsigned int filename_convert(char *dst, const char*src, const unsigned int n)
{
  unsigned int i;
  /*@
    @ loop assigns i, dst[0 .. i];
    @ loop variant n - i;
    @*/
  for(i=0;i<n && src[i]!='\0';i++)
    dst[i]=convert_char_dos(src[i]);
  /*@
    @ loop variant i;
    @*/
  while(i>0 && (dst[i-1]==' '||dst[i-1]=='.'))
    i--;
  if(i==0 && (dst[i]==' '||dst[i]=='.'))
    dst[i++]='_';
  dst[i]='\0';
  return i;
}
#elif defined(__CYGWIN__) || defined(__MINGW32__)
static inline unsigned char convert_char_win(unsigned char car)
{
  if(car<0x20)
    return '_';
  switch(car)
  {
    /* Forbidden */
    case '<':
    case '>':
    case ':':
    case '"':
    /* case '/': subdirectory */
    case '\\':
    case '|':
    case '?':
    case '*':
    /* Not recommanded, valid for NTFS, invalid for FAT */
    case '[':
    case ']':
    case '+':
    /* Not recommanded */
    case ';':
    case ',':
    case '=':
      return '_';
  }
  return car;
}

static unsigned int filename_convert(char *dst, const char*src, const unsigned int n)
{
  unsigned int i;
  for(i=0;i<n && src[i]!='\0';i++)
    dst[i]=convert_char_win(src[i]);
  while(i>0 && (dst[i-1]==' '||dst[i-1]=='.'))
    i--;
  if(i==0 && (dst[i]==' '||dst[i]=='.'))
    dst[i++]='_';
  dst[i]='\0';
  return i;
}
#elif defined(__APPLE__)
static unsigned int filename_convert(char *dst, const char*src, const unsigned int n)
{
  unsigned int i,j;
  const unsigned char *p; 	/* pointers to actual position in source buffer */
  unsigned char *q;	/* pointers to actual position in destination buffer */
  p=(const unsigned char *)src;
  q=(unsigned char *)dst;
  for(i=0,j=0; (*p)!='\0' && i<n; i++)
  {
    if((*p & 0x80)==0x00)
    {
      *q++=*p++;
      j++;
    }
    else if((*p & 0xe0)==0xc0 && (*(p+1) & 0xc0)==0x80)
    {
      *q++=*p++;
      *q++=*p++;
      j+=2;
    }
    else if((*p & 0xf0)==0xe0 && (*(p+1) & 0xc0)==0x80 && (*(p+2) & 0xc0)==0x80)
    {
      *q++=*p++;
      *q++=*p++;
      *q++=*p++;
      j+=3;
    }
    else
    {
      *q++='_';
      p++;
      j++;
    }
  }
  *q='\0';
  return j;
}
#else
/*@
  @ requires \valid(dst + (0 .. n));
  @ requires \valid_read(src + (0 .. n-1));
  @ requires \separated(dst + (..), src + (..));
  @*/
static unsigned int filename_convert(char *dst, const char*src, const unsigned int n)
{
  unsigned int i;
  /*@
    @ loop assigns i, dst[0 .. i];
    @ loop invariant n - i;
    @*/
  for(i=0;i<n && src[i]!='\0';i++)
    dst[i]=src[i];
  dst[i]='\0';
  return i;
}
#endif

char *gen_local_filename(const char *filename)
{
  const int l=strlen(filename);
  char *dst=(char *)MALLOC(l+1);
  filename_convert(dst, filename, l);
#if defined(DJGPP) || defined(__CYGWIN__) || defined(__MINGW32__)
  if(filename[0]!='\0' && filename[1]==':')
    dst[1]=':';
#endif
  return dst;
}

char *mkdir_local(const char *localroot, const char *pathname)
{
#ifdef DISABLED_FOR_FRAMAC
  return NULL;
#else
  const int l1=(localroot==NULL?0:strlen(localroot));
  const int l2=strlen(pathname);
  char *localdir=(char *)MALLOC(l1+l2+1);
  const char *src;
  char *dst;
  if(localroot!=NULL)
    memcpy(localdir, localroot, l1);
  memcpy(localdir+l1, pathname, l2+1);
#ifdef HAVE_MKDIR
#ifdef __MINGW32__
  if(mkdir(localdir)>=0 || errno==EEXIST)
    return localdir;
#else
  if(mkdir(localdir, 0775)>=0 || errno==EEXIST)
    return localdir;
#endif
  /* Need to create the parent and maybe convert the pathname */
  if(localroot!=NULL)
    memcpy(localdir, localroot, l1);
  localdir[l1]='\0';
  src=pathname;
  dst=localdir+l1;
  while(*src!='\0')
  {
    unsigned int n=0;
    const char *src_org=src;
    char *dst_org=dst;
    for(n=0;
	*src!='\0' && (n==0 || *src!='/');
	dst++, src++, n++)
      *dst=*src;
    *dst='\0';
#ifdef __MINGW32__
    if(mkdir(localdir)<0 && errno==EINVAL)
    {
      unsigned int l;
      l=filename_convert(dst_org, src_org, n);
      dst=dst_org+l;
      mkdir(localdir);
    }
#elif defined(__CYGWIN__)
    if(memcmp(&localdir[1],":/cygdrive",11)!=0 &&
	mkdir(localdir, 0775)<0 && errno==EINVAL)
    {
      unsigned int l;
      l=filename_convert(dst_org, src_org, n);
      dst=dst_org+l;
      mkdir(localdir, 0775);
    }
#else
    if(mkdir(localdir, 0775)<0 && errno==EINVAL)
    {
      unsigned int l;
      l=filename_convert(dst_org, src_org, n);
      dst=dst_org+l;
      (void)mkdir(localdir, 0775);
    }
#endif
  }
#else
#warning "You need a mkdir function!"
#endif
  return localdir;
#endif
}

void mkdir_local_for_file(const char *filename)
{
  char *dir;
  char *sep;
  dir=strdup(filename);
  sep=strrchr(dir,'/');
  if(sep!=NULL)
  {
    *sep='\0';
    free(mkdir_local(NULL, dir));
  }
  free(dir);
}

FILE *fopen_local(char **localfilename, const char *localroot, const char *filename)
{
#ifdef DISABLED_FOR_FRAMAC
  return NULL;
#else
  const int l1=strlen(localroot);
  const int l2=strlen(filename);
  const char *src;
  char *dst=(char *)MALLOC(l1+l2+1);
  const char *src_org=filename;
  char *dst_org=dst;
  FILE *f_out;
  memcpy(dst, localroot, l1);
  memcpy(dst+l1, filename, l2+1);
  *localfilename=dst;
  strip_fn(dst);
  f_out=fopen(dst,"wb");
  if(f_out)
    return f_out;
  /* Need to create the parent and maybe convert the pathname */
  src=filename;
  memcpy(dst, localroot, l1+1);
  dst+=l1;
  while(*src!='\0')
  {
    unsigned int n;
    src_org=src;
    dst_org=dst;
    for(n=0;
	*src!='\0' && (n==0 || *src!='/');
	dst++, src++, n++)
      *dst=*src;
    *dst='\0';
    if(*src!='\0')
    {
#ifdef __MINGW32__
      if(mkdir(*localfilename)<0 && errno==EINVAL)
      {
	unsigned int l;
	l=filename_convert(dst_org, src_org, n);
	dst=dst_org+l;
	mkdir(*localfilename);
      }
#elif defined(__CYGWIN__)
      if(memcmp(&localfilename[1],":/cygdrive",11)!=0 &&
	  mkdir(*localfilename, 0775)<0 &&
	  (errno==EINVAL || errno==ENOENT))
      {
	unsigned int l;
	l=filename_convert(dst_org, src_org, n);
	dst=dst_org+l;
	mkdir(*localfilename, 0775);
      }
#else
      if(mkdir(*localfilename, 0775)<0 && errno==EINVAL)
      {
	unsigned int l;
	l=filename_convert(dst_org, src_org, n);
	dst=dst_org+l;
	(void)mkdir(*localfilename, 0775);
      }
#endif
    }
  }
  f_out=fopen(*localfilename,"wb");
  if(f_out)
    return f_out;
  filename_convert(dst_org, src_org, l2);
  return fopen(*localfilename,"wb");
#endif
}
