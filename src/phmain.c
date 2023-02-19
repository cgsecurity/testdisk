/*

    File: phmain.c

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

#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP) || !defined(HAVE_GETEUID)
#undef SUDO_BIN
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_LIBEWF
#undef HAVE_SIGACTION
#undef HAVE_NCURSES
#undef ENABLE_DFXML
#undef HAVE_SETLOCALE
#undef HAVE_GETEUID
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink, ftruncate */
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
#include <ctype.h>      /* tolower */
#ifdef HAVE_LOCALE_H
#include <locale.h>	/* setlocale */
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "fnctdsk.h"
#include "intrfn.h"
#include "dir.h"
#include "filegen.h"
#include "photorec.h"
#include "hdcache.h"
#include "ewf.h"
#include "log.h"
#include "hdaccess.h"
#include "sudo.h"
#include "phcfg.h"
#include "misc.h"
#include "ext2_dir.h"
#include "file_jpg.h"
#include "file_gz.h"
#include "ntfs_dir.h"
#include "pdiskseln.h"
#include "dfxml.h"

int need_to_stop=0;
extern file_enable_t array_file_enable[];
#ifndef DISABLED_FOR_FRAMAC
extern uint64_t gpfh_nbr;
extern uint64_t gpls_nbr;
#endif

#ifdef HAVE_SIGACTION
static struct sigaction action;
static void sighup_hdlr(int sig);

static void sighup_hdlr(int sig)
{
  if(sig == SIGINT)
    log_critical("SIGINT detected! PhotoRec has been killed.\n");
  else if(sig == SIGHUP)
    log_critical("SIGHUP detected! PhotoRec has been killed.\n");
  else
    log_critical("SIGTERM detected! PhotoRec has been killed.\n");
  log_flush();
  if(need_to_stop==1)
  {
    action.sa_handler=SIG_DFL;
    sigaction(sig,&action,NULL);
    kill(0, sig);
    return ;
  }
  need_to_stop=1;
}
#endif

static void display_help(void)
{
  printf("\nUsage: photorec [/log] [/debug] [/d recup_dir] [file.dd|file.e01|device]\n"\
      "       photorec /version\n" \
      "\n" \
      "/log          : create a photorec.log file\n" \
      "/debug        : add debug information\n" \
      "\n" \
      "PhotoRec searches for various file formats (JPEG, Office...). It stores files\n" \
      "in the recup_dir directory.\n");
}

#ifndef DISABLED_FOR_FRAMAC
static void display_version(void)
{
  printf("\n");
  printf("Version: %s\n", VERSION);
  printf("Compiler: %s\n", get_compiler());
#ifdef RECORD_COMPILATION_DATE
  printf("Compilation date: %s\n", get_compilation_date());
#endif
  printf("ext2fs lib: %s, ntfs lib: %s, ewf lib: %s, libjpeg: %s, curses lib: %s, zlib: %s\n",
      td_ext2fs_version(), td_ntfs_version(), td_ewf_version(), td_jpeg_version(), td_curses_version(), td_zlib_version());
#ifdef HAVE_ICONV
  printf("iconv support: yes\n");
#else
  printf("iconv support: no\n");
#endif
  printf("OS: %s\n" , get_os());
}
#endif

int main( int argc, char **argv )
{
  list_disk_t *list_disk=NULL;
  /*@ assert list_disk == \null; */
  /*@ assert valid_list_disk(list_disk); */
  int i;
#ifdef DISABLED_FOR_FRAMAC
  char *argv_framac[]={ "photorec", "/cmd", "file.dd", "search", NULL };
#endif
#ifdef SUDO_BIN
  int use_sudo=0;
#endif
  int create_log=TD_LOG_NONE;
  int run_setlocale=1;
  int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  list_disk_t *element_disk;
  const char *logfile="photorec.log";
  int log_opened=0;
  int log_errno=0;
  struct ph_options options={
    .paranoid=1,
    .keep_corrupted_file=0,
    .mode_ext2=0,
    .expert=0,
    .lowmem=0,
    .verbose=0,
    .list_file_format=array_file_enable
  };
  struct ph_param params;
  if(argc <= 0)
    return 1;
  /*@ assert valid_list_disk(list_disk); */ ;
  params.recup_dir=NULL;
  params.cmd_device=NULL;
  params.cmd_run=NULL;
  params.carve_free_space_only=0;
  params.disk=NULL;
  /*@ assert valid_ph_param(&params); */
  /* random (weak is ok) is needed for GPT */
  srand(time(NULL)& (long)0xffffffff);
  /*@ assert valid_list_disk(list_disk); */ ;
#ifdef HAVE_SIGACTION
  /* set up the signal handler for SIGINT & SIGHUP */
  sigemptyset(&action.sa_mask);
  sigaddset(&action.sa_mask, SIGINT);
  sigaddset(&action.sa_mask, SIGHUP);
  sigaddset(&action.sa_mask, SIGTERM);
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
  if(sigaction(SIGTERM, &action, NULL)==-1)
  {
    printf("Error on SIGACTION call\n");
    return -1;
  }
#endif
#ifndef DISABLED_FOR_FRAMAC
  printf("PhotoRec %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttps://www.cgsecurity.org\n",VERSION,TESTDISKDATE);
#endif
#if defined(DISABLED_FOR_FRAMAC)
  argc=4;
  argv=argv_framac;
#endif
  /*@ assert valid_list_disk(list_disk); */
  /*@
    @ loop unroll 256;
    @ loop invariant valid_list_disk(list_disk);
    @*/
  for(i=1;i<argc;i++)
  {
#ifndef DISABLED_FOR_FRAMAC
    if((strcmp(argv[i],"/logname")==0) ||(strcmp(argv[i],"-logname")==0))
    {
      if(i+2>=argc)
      {
	display_help();
	free(params.recup_dir);
	return 1;
      }
      /*@ assert valid_read_string(argv[i+1]); */
      logfile=argv[++i];
      /*@ assert valid_read_string(logfile); */
    }
    else if((strcmp(argv[i],"/nolog")==0) ||(strcmp(argv[i],"-nolog")==0))
    {
      create_log=TD_LOG_NONE;
    }
    else if((strcmp(argv[i],"/log")==0) ||(strcmp(argv[i],"-log")==0))
    {
      if(create_log==TD_LOG_NONE)
        create_log=TD_LOG_APPEND;
    }
    else if((strcmp(argv[i],"/debug")==0) || (strcmp(argv[i],"-debug")==0))
    {
      options.verbose++;
      if(create_log==TD_LOG_NONE)
        create_log=TD_LOG_APPEND;
    }
    else if(i+1<argc && ((strcmp(argv[i],"/d")==0)||(strcmp(argv[i],"-d")==0)))
    {
      const int len=strlen(argv[i+1]);
      if(argv[i+1][len-1]=='\\' || argv[i+1][len-1]=='/')
      {
        params.recup_dir=(char *)MALLOC(len + strlen(DEFAULT_RECUP_DIR) + 1);
        strcpy(params.recup_dir,argv[i+1]);
        strcat(params.recup_dir,DEFAULT_RECUP_DIR);
	/*@ assert \freeable(params.recup_dir); */
      }
      else
      {
        params.recup_dir=strdup(argv[i+1]);
	/*@ assert params.recup_dir==\null || \freeable(params.recup_dir); */
      }
      i++;
    }
    else if((strcmp(argv[i],"/all")==0) || (strcmp(argv[i],"-all")==0))
      testdisk_mode|=TESTDISK_O_ALL;
    else if((strcmp(argv[i],"/direct")==0) || (strcmp(argv[i],"-direct")==0))
      testdisk_mode|=TESTDISK_O_DIRECT;
    else if((strcmp(argv[i],"/help")==0) || (strcmp(argv[i],"-help")==0) || (strcmp(argv[i],"--help")==0) ||
      (strcmp(argv[i],"/h")==0) || (strcmp(argv[i],"-h")==0) ||
      (strcmp(argv[i],"/?")==0) || (strcmp(argv[i],"-?")==0))
    {
      display_help();
      free(params.recup_dir);
      return 0;
    }
    else if((strcmp(argv[i],"/version")==0) || (strcmp(argv[i],"-version")==0) || (strcmp(argv[i],"--version")==0) ||
      (strcmp(argv[i],"/v")==0) || (strcmp(argv[i],"-v")==0))
    {
      display_version();
      free(params.recup_dir);
      return 0;
    }
    else if((strcmp(argv[i],"/nosetlocale")==0) || (strcmp(argv[i],"-nosetlocale")==0))
      run_setlocale=0;
    else
#endif
    if(strcmp(argv[i],"/cmd")==0)
    {
      if(i+2>=argc)
      {
	display_help();
	free(params.recup_dir);
	return 1;
      }
#ifndef DISABLED_FOR_FRAMAC
      if(strcmp(argv[i+1],"resume")==0)
      {
	params.cmd_device=argv[++i];
      }
      else
#endif
      {
        disk_t *disk_car;
        params.cmd_device=argv[++i];
#ifdef DISABLED_FOR_FRAMAC
        params.cmd_device="disk.dd";
#endif
        params.cmd_run=argv[++i];
        /* There is no log currently */
        disk_car=file_test_availability(params.cmd_device, options.verbose, testdisk_mode);
	/*@ assert disk_car == \null || valid_disk(disk_car); */
        if(disk_car==NULL)
        {
          printf("\nUnable to open file or device %s: %s\n", params.cmd_device, strerror(errno));
	  free(params.recup_dir);
	  return 1;
        }
	/*@ assert  \valid(disk_car); */
	/*@ assert 0 < disk_car->geom.cylinders < 0x2000000000000 && 0 < disk_car->geom.heads_per_cylinder <= 255 && 0 < disk_car->geom.sectors_per_head <= 63; */
	/*@ assert valid_read_string(disk_car->device); */
	list_disk=insert_new_disk(list_disk,disk_car);
	/*@ assert list_disk ==\null || (\valid(list_disk) && valid_disk(list_disk->disk)); */
	/*@ assert valid_list_disk(list_disk); */
      }
    }
#ifndef DISABLED_FOR_FRAMAC
    else
    {
      disk_t *disk_car=file_test_availability(argv[i], options.verbose, testdisk_mode);
      /*@ assert  valid_disk(disk_car); */
      if(disk_car==NULL)
      {
        printf("\nUnable to open file or device %s: %s\n", argv[i], strerror(errno));
	free(params.recup_dir);
	return 1;
      }
      list_disk=insert_new_disk(list_disk,disk_car);
      /*@ assert list_disk ==\null || (\valid(list_disk) && valid_disk(list_disk->disk)); */
      /*@ assert valid_list_disk(list_disk); */
    }
#endif
  }
  /*@ assert valid_ph_param(&params); */
#if defined(ENABLE_DFXML)
  xml_set_command_line(argc, argv);
#endif
  /*@ assert valid_read_string(logfile); */
  if(create_log!=TD_LOG_NONE)
    log_opened=log_open(logfile, create_log, &log_errno);
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
  if(create_log!=TD_LOG_NONE && log_opened==0)
    log_opened=log_open_default(logfile, create_log, &log_errno);
#ifdef HAVE_NCURSES
  /* ncurses need locale for correct unicode support */
  if(start_ncurses("PhotoRec", argv[0]))
  {
    free(params.recup_dir);
    log_close();
    return 1;
  }
  {
    const char*filename=logfile;
    while(create_log!=TD_LOG_NONE && log_opened==0)
    {
      filename=ask_log_location(filename, log_errno);
      if(filename!=NULL)
	log_opened=log_open(filename, create_log, &log_errno);
      else
	create_log=TD_LOG_NONE;
    }
  }
  aff_copy(stdscr);
  wmove(stdscr,5,0);
  wprintw(stdscr, "Disk identification, please wait...\n");
  wrefresh(stdscr);
#endif
  {
    time_t my_time;
    my_time=time(NULL);
    log_info("\n\n%s",ctime(&my_time));
  }
  log_info("Command line: PhotoRec");
  for(i=1;i<argc;i++)
    log_info(" %s", argv[i]);
  log_info("\n\n");
  log_info("PhotoRec %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttps://www.cgsecurity.org\n", VERSION, TESTDISKDATE);
  log_info("OS: %s\n" , get_os());
  log_info("Compiler: %s\n", get_compiler());
#ifdef RECORD_COMPILATION_DATE
  log_info("Compilation date: %s\n", get_compilation_date());
#endif
  log_info("ext2fs lib: %s, ntfs lib: %s, ewf lib: %s, libjpeg: %s, curses lib: %s\n",
      td_ext2fs_version(), td_ntfs_version(), td_ewf_version(), td_jpeg_version(), td_curses_version());
#if defined(HAVE_GETEUID) && !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(DJGPP)
  if(geteuid()!=0)
  {
    log_warning("User is not root!\n");
  }
#endif
  log_flush();
  screen_buffer_reset();
#ifndef DISABLED_FOR_FRAMAC
  /* Scan for available device only if no device or image has been supplied in parameter */
  if(list_disk==NULL)
    list_disk=hd_parse(list_disk, options.verbose, testdisk_mode);
  hd_update_all_geometry(list_disk, options.verbose);
  /* Activate the cache, even if photorec has its own */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    element_disk->disk=new_diskcache(element_disk->disk, testdisk_mode);
  }
  log_disk_list(list_disk);
#endif
  reset_array_file_enable(options.list_file_format);
  file_options_load(options.list_file_format);
#ifdef SUDO_BIN
  if(list_disk==NULL && geteuid()!=0)
  {
      use_sudo=2;
  }
  if(use_sudo==0)
    use_sudo=do_curses_photorec(&params, &options, list_disk);
#else
  do_curses_photorec(&params, &options, list_disk);
#endif
#ifdef HAVE_NCURSES
  end_ncurses();
#endif
#ifndef DISABLED_FOR_FRAMAC
  if(options.verbose > 0)
  {
    log_info("perf: get_prev_file_header: %lu, get_prev_location_smart: %lu\n", (long unsigned)gpfh_nbr, (long unsigned)gpls_nbr);
  }
  log_info("PhotoRec exited normally.\n");
#endif
  if(log_close()!=0)
  {
#ifndef DISABLED_FOR_FRAMAC
    printf("PhotoRec: Log file corrupted!\n");
#endif
  }
  else if(params.cmd_run!=NULL && params.cmd_run[0]!='\0')
  {
    /*@ assert valid_read_string(params.cmd_run); */
#ifndef DISABLED_FOR_FRAMAC
    printf("PhotoRec syntax error: %s\n", params.cmd_run);
#endif
  }
#ifdef SUDO_BIN
  if(use_sudo>0)
  {
    printf("\n");
    if(use_sudo>1)
      printf("No disk found.\n");
    printf("PhotoRec will try to restart itself using the sudo command to get\n");
    printf("root (superuser) privileges.\n");
    printf("\n");
    run_sudo(argc, argv, create_log);
  }
#endif
#ifndef DISABLED_FOR_FRAMAC
  delete_list_disk(list_disk);
#endif
  free(params.recup_dir);
#ifdef ENABLE_DFXML
  xml_clear_command_line();
#endif
  return 0;
}
