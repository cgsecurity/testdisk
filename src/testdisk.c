/*

    File: testdisk.c

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
#ifdef HAVE_LOCALE_H
#include <locale.h>	/* setlocale */
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include "intrface.h"
#include "fnctdsk.h"
#include "dir.h"
#include "ext2_dir.h"
#include "rfs_dir.h"
#include "ntfs_dir.h"
#include "hdcache.h"
#include "ewf.h"
#include "log.h"
#include "hdaccess.h"
#include "sudo.h"
#include "partauto.h"
#include "misc.h"
#include "tdisksel.h"
#include "tlog.h"
#include "autoset.h"
#include "hidden.h"

#ifdef HAVE_SIGACTION
static struct sigaction action;
static void sighup_hdlr(int sig);

static void sighup_hdlr(int sig)
{
  if(sig == SIGINT)
    log_critical("SIGINT detected! TestDisk has been killed.\n");
  else
    log_critical("SIGHUP detected! TestDisk has been killed.\n");
  log_flush();
  action.sa_handler=SIG_DFL;
  sigaction(sig,&action,NULL);
  kill(0, sig);
}
#endif

static void display_help(void)
{
  printf("\n" \
      "Usage: testdisk [/log] [/debug] [file.dd|file.e01|device]\n"\
      "       testdisk /list  [/log]   [file.dd|file.e01|device]\n" \
      "       testdisk /version\n" \
      "\n" \
      "/log          : create a testdisk.log file\n" \
      "/debug        : add debug information\n" \
      "/list         : display current partitions\n" \
      "\n" \
      "TestDisk checks and recovers lost partitions\n" \
      "It works with :\n" \
      "- BeFS (BeOS)                           - BSD disklabel (Free/Open/Net BSD)\n" \
      "- CramFS, Compressed File System        - DOS/Windows FAT12, FAT16 and FAT32\n" \
      "- XBox FATX                             - Windows exFAT\n" \
      "- HFS, HFS+, Hierarchical File System   - JFS, IBM's Journaled File System\n" \
      "- Linux btrfs                           - Linux ext2, ext3 and ext4\n" \
      "- Linux GFS2                            - Linux LUKS\n" \
      "- Linux Raid                            - Linux Swap\n" \
      "- LVM, LVM2, Logical Volume Manager     - Netware NSS\n" \
      "- Windows NTFS                          - ReiserFS 3.5, 3.6 and 4\n" \
      "- Sun Solaris i386 disklabel            - UFS and UFS2 (Sun/BSD/...)\n" \
      "- XFS, SGI's Journaled File System      - Wii WBFS\n" \
      "- Sun ZFS\n");
}

static void display_version(void)
{
  printf("\n");
  printf("Version: %s\n", VERSION);
  printf("Compiler: %s\n", get_compiler());
#ifdef RECORD_COMPILATION_DATE
  printf("Compilation date: %s\n", get_compilation_date());
#endif
  printf("ext2fs lib: %s, ntfs lib: %s, reiserfs lib: %s, ewf lib: %s, curses lib: %s\n",
      td_ext2fs_version(), td_ntfs_version(), td_reiserfs_version(), td_ewf_version(), td_curses_version());
  printf("OS: %s\n" , get_os());
}

static int display_disk_list(list_disk_t *list_disk, const int testdisk_mode, 
    const int create_backup, const int safe, const int saveheader, const int unit, const int verbose)
{
  list_disk_t *element_disk;
  printf("Please wait...\n");
  /* Scan for available device only if no device or image has been supplied in parameter */
  if(list_disk==NULL)
    list_disk=hd_parse(list_disk, verbose, testdisk_mode);
  if(list_disk==NULL)
  {
    printf("No disk detected.\n");
#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP)
#else
#ifdef HAVE_GETEUID
    if(geteuid()!=0)
    {
      printf("You need to be root to use TestDisk.\n");
    }
#endif
#endif
    return 1;
  }

  /* Activate the cache */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
  if(safe==0)
    hd_update_all_geometry(list_disk, verbose);
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    const int hpa_dco=is_hpa_or_dco(disk);
    printf("%s\n", disk->description(disk));
    printf("Sector size:%u\n", disk->sector_size);
    if(disk->model!=NULL)
      printf("Model: %s", disk->model);
    if(disk->serial_no!=NULL)
      printf(", S/N:%s", disk->serial_no);
    if(disk->fw_rev!=NULL)
      printf(", FW:%s", disk->fw_rev);
    printf("\n");
    if(hpa_dco!=0)
    {
      if(disk->sector_size!=0)
	printf("size       %llu sectors\n", (long long unsigned)(disk->disk_real_size/disk->sector_size));
      if(disk->user_max!=0)
	printf("user_max   %llu sectors\n", (long long unsigned)disk->user_max);
      if(disk->native_max!=0)
	printf("native_max %llu sectors\n", (long long unsigned)(disk->native_max+1));
      if(disk->dco!=0)
	printf("dco        %llu sectors\n", (long long unsigned)(disk->dco+1));
      if(hpa_dco&1)
	printf("Host Protected Area (HPA) present.\n");
      if(hpa_dco&2)
	printf("Device Configuration Overlay (DCO) present.\n");
    }
    printf("\n");
  }

  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    autodetect_arch(disk, NULL);
    if(unit==UNIT_DEFAULT)
      autoset_unit(disk);
    else
      disk->unit=unit;
    interface_list(disk, verbose, saveheader, create_backup);
    printf("\n");
  }
  delete_list_disk(list_disk);
  return 0;
}


int main( int argc, char **argv )
{
  int i;
#ifdef SUDO_BIN
  int use_sudo=0;
#endif
  int verbose=0, dump_ind=0;
  int create_log=TD_LOG_NONE;
  int do_list=0;
  int unit=UNIT_DEFAULT;
  int write_used;
  int saveheader=0;
  int create_backup=0;
  int run_setlocale=1;
  int done=0;
  int safe=0;
  int testdisk_mode=TESTDISK_O_RDWR|TESTDISK_O_READAHEAD_8K;
  list_disk_t *list_disk=NULL;
  list_disk_t *element_disk;
  const char *cmd_device=NULL;
  char *cmd_run=NULL;
  const char *logfile="testdisk.log";
  FILE *log_handle=NULL;
  int log_errno=0;
  /* srand needed for GPT creation (weak is ok) */
  srand(time(NULL));
#ifdef HAVE_SIGACTION
  /* set up the signal handler for SIGINT & SIGHUP */
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGINT);
  sigaddset(&action.sa_mask, SIGHUP);
  action.sa_handler  = &sighup_hdlr;
  action.sa_flags = 0;
  if(sigaction(SIGINT, &action, NULL)==-1)
  {
    printf("Error on SIGACTION call\n");
    return -1;
  }
  if(sigaction(SIGHUP, &action, NULL)==-1)
  {
    printf("Error on SIGACTION call\n");
    return -1;
  }
#endif
  printf("TestDisk %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttps://www.cgsecurity.org\n",VERSION,TESTDISKDATE);
  for(i=1;i<argc;i++)
  {
    if((strcmp(argv[i],"/dump")==0) || (strcmp(argv[i],"-dump")==0))
      dump_ind=1;
    else if((strcmp(argv[i],"/logname")==0) ||(strcmp(argv[i],"-logname")==0))
    {
      if(i+2>=argc)
      {
	display_help();
	log_close();
	return 1;
      }
      logfile=argv[++i];
    }
    else if((strcmp(argv[i],"/nolog")==0) ||(strcmp(argv[i],"-nolog")==0))
    {
      create_log=TD_LOG_NONE;
    }
    else if((strcmp(argv[i],"/log")==0) ||(strcmp(argv[i],"-log")==0))
    {
      if(create_log==TD_LOG_NONE)
        create_log=TD_LOG_APPEND;
      if(log_handle==NULL)
	log_handle=log_open(logfile, create_log, &log_errno);
    }
    else if((strcmp(argv[i],"/debug")==0) || (strcmp(argv[i],"-debug")==0))
    {
      verbose++;
      if(create_log==TD_LOG_NONE)
        create_log=TD_LOG_APPEND;
      if(log_handle==NULL)
	log_handle=log_open(logfile, create_log, &log_errno);
    }
    else if((strcmp(argv[i],"/all")==0) || (strcmp(argv[i],"-all")==0))
      testdisk_mode|=TESTDISK_O_ALL;
    else if((strcmp(argv[i],"/backup")==0) || (strcmp(argv[i],"-backup")==0))
      create_backup=1;
    else if((strcmp(argv[i],"/direct")==0) || (strcmp(argv[i],"-direct")==0))
      testdisk_mode|=TESTDISK_O_DIRECT;
    else if((strcmp(argv[i],"/help")==0) || (strcmp(argv[i],"-help")==0) || (strcmp(argv[i],"--help")==0) ||
      (strcmp(argv[i],"/h")==0) || (strcmp(argv[i],"-h")==0) ||
      (strcmp(argv[i],"/?")==0) || (strcmp(argv[i],"-?")==0))
    {
      display_help();
      log_close();
      return 0;
    }
    else if((strcmp(argv[i],"/version")==0) || (strcmp(argv[i],"-version")==0) || (strcmp(argv[i],"--version")==0) ||
      (strcmp(argv[i],"/v")==0) || (strcmp(argv[i],"-v")==0))
    {
      display_version();
      log_close();
      return 0;
    }
    else if(strcmp(argv[i],"/list")==0 || strcmp(argv[i],"-list")==0 || strcmp(argv[i],"-l")==0)
    {
      do_list=1;
    }
    else if(strcmp(argv[i],"-lu")==0)
    {
      do_list=1;
      unit=UNIT_SECTOR;
    }
    else if((strcmp(argv[i],"/nosetlocale")==0) || (strcmp(argv[i],"-nosetlocale")==0))
      run_setlocale=0;
    else if((strcmp(argv[i],"/safe")==0) || (strcmp(argv[i],"-safe")==0))
      safe=1;
    else if((strcmp(argv[i],"/saveheader")==0) || (strcmp(argv[i],"-saveheader")==0))
      saveheader=1;
    else if(strcmp(argv[i],"/cmd")==0)
    {
      if(i+2>=argc)
      {
	display_help();
	log_close();
	return 1;
      }
      {
	disk_t *disk_car;
	cmd_device=argv[++i];
	cmd_run=argv[++i];
	disk_car=file_test_availability(cmd_device, verbose, testdisk_mode);
	if(disk_car==NULL)
	{
	  printf("\nUnable to open file or device %s: %s\n", cmd_device, strerror(errno));
	  log_close();
	  return 1;
	}
	list_disk=insert_new_disk(list_disk,disk_car);
      }
    }
    else
    {
      disk_t *disk_car=file_test_availability(argv[i], verbose, testdisk_mode);
      if(disk_car==NULL)
      {
	printf("\nUnable to open file or device %s: %s\n", argv[i], strerror(errno));
	log_close();
	return 1;
      }
      list_disk=insert_new_disk(list_disk,disk_car);
    }
  }
  screen_buffer_reset();
  if(do_list!=0)
  {
    const int res=display_disk_list(list_disk, testdisk_mode, create_backup, safe, saveheader, unit, verbose);
    log_close();
    return res;
  }
#ifdef HAVE_SETLOCALE
  if(run_setlocale>0)
  {
    const char *locale;
    locale = setlocale (LC_ALL, "");
    if (locale==NULL) {
      locale = setlocale (LC_ALL, NULL);
      log_error("Failed to set locale, using default '%s'.\n", locale);
    } else {
      log_info("Using locale '%s'.\n", locale);
    }
  }
#endif
  if(create_log!=TD_LOG_NONE && log_handle==NULL)
    log_handle=log_open_default(logfile, create_log, &log_errno);
#ifdef HAVE_NCURSES
  /* ncurses need locale for correct unicode support */
  if(start_ncurses("TestDisk",argv[0]))
  {
    log_close();
    return 1;
  }
  if(argc==1 && create_log==TD_LOG_NONE)
  {
    verbose=1;
    create_log=ask_testdisk_log_creation();
    if(create_log==TD_LOG_CREATE || create_log==TD_LOG_APPEND)
      log_handle=log_open(logfile, create_log, &log_errno);
  }
  {
    const char*filename=logfile;
    while(create_log!=TD_LOG_NONE && log_handle==NULL)
    {
      filename=ask_log_location(filename, log_errno);
      if(filename!=NULL)
	log_handle=log_open(filename, create_log, &log_errno);
      else
	create_log=TD_LOG_NONE;
    }
  }
#endif
  if(log_handle!=NULL)
  {
    time_t my_time;
#ifdef HAVE_DUP2
    dup2(fileno(log_handle),2);
#endif
    my_time=time(NULL);
    log_info("\n\n%s",ctime(&my_time));
    log_info("Command line: TestDisk");
    for(i=1;i<argc;i++)
      log_info(" %s", argv[i]);
    log_info("\n\n");
  }
  log_info("TestDisk %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttps://www.cgsecurity.org\n", VERSION, TESTDISKDATE);
  log_info("OS: %s\n" , get_os());
  log_info("Compiler: %s\n", get_compiler());
#ifdef RECORD_COMPILATION_DATE
  log_info("Compilation date: %s\n", get_compilation_date());
#endif
  log_info("ext2fs lib: %s, ntfs lib: %s, reiserfs lib: %s, ewf lib: %s, curses lib: %s\n",
      td_ext2fs_version(), td_ntfs_version(), td_reiserfs_version(), td_ewf_version(), td_curses_version());
#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    log_warning("User is not root!\n");
  }
#endif
#endif
  log_flush();
#ifdef HAVE_NCURSES
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr, "Please wait...\n");
  wrefresh(stdscr);
#endif
  /* Scan for available device only if no device or image has been supplied in parameter */
  if(list_disk==NULL)
    list_disk=hd_parse(list_disk, verbose, testdisk_mode);
  /* Activate the cache */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
#ifdef HAVE_NCURSES
  wmove(stdscr,6,0);
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    wprintw(stdscr,"%s\n",element_disk->disk->description(element_disk->disk));
  }
  wrefresh(stdscr);
#endif
  if(safe==0)
    hd_update_all_geometry(list_disk, verbose);
  log_disk_list(list_disk);
#ifdef SUDO_BIN
  if(list_disk==NULL)
  {
#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP)
#else
#ifdef HAVE_GETEUID
    if(geteuid()!=0)
      use_sudo=2;
#endif
#endif
  }
  if(use_sudo==0)
    use_sudo=do_curses_testdisk(verbose,dump_ind,list_disk,saveheader,cmd_device,&cmd_run);
#else
  do_curses_testdisk(verbose,dump_ind,list_disk,saveheader,cmd_device,&cmd_run);
#endif
#ifdef HAVE_NCURSES
  end_ncurses();
#endif
  log_info("\n");
  while(done==0)
  {
    int command='Q';
    if(cmd_run!=NULL)
    {
      skip_comma_in_command(&cmd_run);
      if(check_command(&cmd_run,"list",4)==0)
      {
	command='L';
      }
      else if(cmd_run[0]!='\0')
      {
	log_critical("Syntax error in command line: %s\n",cmd_run);
	printf("Syntax error in command line: %s\n",cmd_run);
      }
    }
    switch(command)
    {
      case 'L':
	for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
	  interface_list(element_disk->disk, verbose, saveheader, create_backup);
	break;
      case 'q':
      case 'Q':
	done = 1;
	break;
    }
  }
  cmd_device=NULL;
  cmd_run=NULL;
  write_used=delete_list_disk(list_disk);
  log_info("TestDisk exited normally.\n");
  if(log_close()!=0)
  {
    printf("TestDisk: Log file corrupted!\n");
  }
  if(write_used!=0)
  {
    printf("You have to reboot for the change to take effect.\n");
  }
#ifdef SUDO_BIN
  if(use_sudo>0)
  {
    printf("\n");
    if(use_sudo>1)
      printf("No disk found.\n");
    printf("TestDisk will try to restart itself using the sudo command to get\n");
    printf("root (superuser) privileges.\n");
    printf("\n");
    run_sudo(argc, argv, create_log);
  }
#endif
  return 0;
}
