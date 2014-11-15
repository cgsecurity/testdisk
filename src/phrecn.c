/*

    File: phrecn.c

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

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
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
#include <ctype.h>      /* tolower */
#include "types.h"
#include "common.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#endif
#include <errno.h>
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#ifdef HAVE_WINBASE_H
#include <stdarg.h>
#include <winbase.h>
#endif
#include "dir.h"
#include "fat.h"
#include "fat_dir.h"
#include "list.h"
#include "lang.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "phrecn.h"
#include "log.h"
#include "log_part.h"
#include "file_tar.h"
#include "phcfg.h"
#include "pblocksize.h"
#include "askloc.h"
#include "fat_unformat.h"
#include "pnext.h"
#include "phbf.h"
#include "phnc.h"
#include "phbs.h"
#include "file_found.h"
#include "dfxml.h"
#include "poptions.h"
#include "psearchn.h"

/* #define DEBUG */
/* #define DEBUG_BF */
#define DEFAULT_IMAGE_NAME "image_remaining.dd"

extern file_check_list_t file_check_list;

static int interface_cannot_create_file(void);

#ifdef HAVE_NCURSES
static void recovery_finished(disk_t *disk, const partition_t *partition, const unsigned int file_nbr, const char *recup_dir, const pstatus_t ind_stop)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"%s", disk->description_short(disk));
  mvwaddstr(stdscr,5,0,msg_PART_HEADER_LONG);
  wmove(stdscr,6,0);
  aff_part(stdscr,AFF_PART_ORDER|AFF_PART_STATUS, disk, partition);
  wmove(stdscr,9,0);
  wclrtoeol(stdscr);
  wprintw(stdscr,"%u files saved in %s directory.\n", file_nbr, recup_dir);
  wmove(stdscr,10,0);
  wclrtoeol(stdscr);
  switch(ind_stop)
  {
    case PSTATUS_OK:
      wprintw(stdscr,"Recovery completed.");
      if(file_nbr > 0)
      {
	wmove(stdscr, 12, 0);
	wprintw(stdscr, "You are welcome to donate to support further development and encouragement");
	wmove(stdscr, 13, 0);
	wprintw(stdscr, "http://www.cgsecurity.org/wiki/Donation");
      }
      break;
    case PSTATUS_STOP:
      wprintw(stdscr,"Recovery aborted by the user.");
      break;
    case PSTATUS_EACCES:
      wprintw(stdscr,"Cannot create file in current directory.");
      break;
    case PSTATUS_ENOSPC:
      wprintw(stdscr,"Cannot write file, no space left.");
      break;
  }
  wmove(stdscr,22,0);
  wclrtoeol(stdscr);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  log_flush();
  while(1)
  {
    switch(wgetch(stdscr))
    {
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
      case KEY_MOUSE:
	{
	  MEVENT event;
	  if(getmouse(&event) == OK)
	  {	/* When the user clicks left mouse button */
	    if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	    {
	      if(event.x < sizeof("[ Quit ]") && event.y==22)
		return ;
	    }
	  }
	}
	break;
#endif
      case KEY_ENTER:
#ifdef PADENTER
      case PADENTER:
#endif
      case '\n':
      case '\r':
      case 'q':
      case 'Q':
	return;
    }
  }
}
#endif

#if defined(HAVE_NCURSES) && (defined(__CYGWIN__) || defined(__MINGW32__))
static int interface_cannot_create_file(void)
{
  static const struct MenuItem menuMain[]=
  {
    { 'C', "Continue", "Continue the recovery."},
    { 'Q', "Quit", "Abort the recovery."},
    { 0,NULL,NULL}
  };
  unsigned int menu=0;
  int car;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"PhotoRec has been unable to create new file.");
  wmove(stdscr,5,0);
  wprintw(stdscr,"This problem may be due to antivirus blocking write access while scanning files created by PhotoRec.");
  wmove(stdscr,6,0);
  wprintw(stdscr,"If possible, temporary disable your antivirus live protection.");
  car= wmenuSelect_ext(stdscr, 23, INTER_MAIN_Y, INTER_MAIN_X, menuMain, 10,
      "CQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
  if(car=='c' || car=='C')
    return 0;
  return 1;
}
#else
static int interface_cannot_create_file(void)
{
  return 1;
}
#endif

static void gen_image(const char *filename, disk_t *disk, const alloc_data_t *list_search_space)
{
  struct td_list_head *search_walker = NULL;
  const unsigned int buffer_size=64*512;
  FILE *out;
  unsigned char *buffer;
  if(td_list_empty(&list_search_space->list))
    return ;
  if(!(out=fopen(filename,"w+b")))
    return ;
  buffer=(unsigned char *)MALLOC(buffer_size);
  td_list_for_each(search_walker, &list_search_space->list)
  {
    uint64_t offset;
    alloc_data_t *current_search_space;
    current_search_space=td_list_entry(search_walker, alloc_data_t, list);
    for(offset=current_search_space->start; offset <= current_search_space->end; offset+=buffer_size)
    {
      const unsigned int read_size=(current_search_space->end - offset + 1 < buffer_size ?
	  current_search_space->end - offset + 1 : buffer_size);
      disk->pread(disk, buffer, read_size, offset);
      if(fwrite(buffer, read_size, 1, out)<1)
      {
	log_critical("Cannot write to file %s: %s\n", filename, strerror(errno));
	free(buffer);
	fclose(out);
	return ;
      }
    }
  }
  free(buffer);
  fclose(out);
}

int photorec(struct ph_param *params, const struct ph_options *options, alloc_data_t *list_search_space)
{
  pstatus_t ind_stop=PSTATUS_OK;
  const unsigned int blocksize_is_known=params->blocksize;
  params_reset(params, options);
  if(params->cmd_run!=NULL && params->cmd_run[0]!='\0')
  {
    while(params->cmd_run[0]==',')
      params->cmd_run++;
    if(strncmp(params->cmd_run,"status=unformat",15)==0)
    {
      params->status=STATUS_UNFORMAT;
      params->cmd_run+=15;
    }
    else if(strncmp(params->cmd_run,"status=find_offset",18)==0)
    {
      params->status=STATUS_FIND_OFFSET;
      params->cmd_run+=18;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on_bf",17)==0)
    {
      params->status=STATUS_EXT2_ON_BF;
      params->cmd_run+=17;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on_save_everything",33)==0)
    {
      params->status=STATUS_EXT2_ON_SAVE_EVERYTHING;
      params->cmd_run+=33;
    }
    else if(strncmp(params->cmd_run,"status=ext2_on",14)==0)
    {
      params->status=STATUS_EXT2_ON;
      params->cmd_run+=14;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off_bf",18)==0)
    {
      params->status=STATUS_EXT2_OFF_BF;
      params->cmd_run+=18;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off_save_everything",34)==0)
    {
      params->status=STATUS_EXT2_OFF_SAVE_EVERYTHING;
      params->cmd_run+=34;
    }
    else if(strncmp(params->cmd_run,"status=ext2_off",15)==0)
    {
      params->status=STATUS_EXT2_OFF;
      params->cmd_run+=15;
    }
  }
  else
  {
#ifdef HAVE_NCURSES
    if(options->expert>0 &&
	ask_confirmation("Try to unformat a FAT filesystem (Y/N)")!=0)
      params->status=STATUS_UNFORMAT;
#endif
  }

  screen_buffer_reset();
  log_info("\nAnalyse\n");
  log_partition(params->disk, params->partition);

  /* make the first recup_dir */
  params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num);

#ifdef ENABLE_DFXML
  /* Open the XML output file */
  xml_open(params->recup_dir, params->dir_num);
  xml_setup(params->disk, params->partition);
#endif
  
  for(params->pass=0; params->status!=STATUS_QUIT; params->pass++)
  {
    const unsigned int old_file_nbr=params->file_nbr;
    log_info("Pass %u (blocksize=%u) ", params->pass, params->blocksize);
    log_info("%s\n", status_to_name(params->status));

#ifdef HAVE_NCURSES
    aff_copy(stdscr);
    wmove(stdscr, 4, 0);
    wprintw(stdscr, "%s", params->disk->description_short(params->disk));
    mvwaddstr(stdscr, 5, 0, msg_PART_HEADER_LONG);
    wmove(stdscr, 6, 0);
    aff_part(stdscr, AFF_PART_ORDER|AFF_PART_STATUS, params->disk, params->partition);
    wmove(stdscr, 22, 0);
    wattrset(stdscr, A_REVERSE);
    waddstr(stdscr, "  Stop  ");
    wattroff(stdscr, A_REVERSE);
    wrefresh(stdscr);
#endif
    switch(params->status)
    {
      case STATUS_UNFORMAT:
	ind_stop=fat_unformat(params, options, list_search_space);
	params->blocksize=blocksize_is_known;
	break;
      case STATUS_FIND_OFFSET:
	{
	  uint64_t start_offset=0;
	  if(blocksize_is_known>0)
	  {
	    ind_stop=PSTATUS_OK;
	    if(!td_list_empty(&list_search_space->list))
	      start_offset=(td_list_entry(list_search_space->list.next, alloc_data_t, list))->start % params->blocksize;
	  }
	  else
	  {
	    ind_stop=photorec_find_blocksize(params, options, list_search_space);
	    params->blocksize=find_blocksize(list_search_space, params->disk->sector_size, &start_offset);
	  }
#ifdef HAVE_NCURSES
	  if(options->expert>0)
	    params->blocksize=menu_choose_blocksize(params->blocksize, params->disk->sector_size, &start_offset);
#endif
	  update_blocksize(params->blocksize, list_search_space, start_offset);
	}
	break;
      case STATUS_EXT2_ON_BF:
      case STATUS_EXT2_OFF_BF:
	ind_stop=photorec_bf(params, options, list_search_space);
	break;
      default:
	ind_stop=photorec_aux(params, options, list_search_space);
	break;
    }
    session_save(list_search_space, params, options);

    switch(ind_stop)
    {
      case PSTATUS_ENOSPC:
	{ /* no more space */
#ifdef HAVE_NCURSES
	  char *dst;
	  char *res;
	  dst=strdup(params->recup_dir);
	  if(dst!=NULL)
	  {
	    res=strrchr(dst, '/');
	    if(res!=NULL)
	      *res='\0';
	  }
	  res=ask_location("Warning: no free space available. Please select a destination to save the recovered files.\nDo not choose to write the files to the same partition they were stored on.", "", dst);
	  free(dst);
	  if(res==NULL)
	    params->status=STATUS_QUIT;
	  else
	  {
	    free(params->recup_dir);
	    params->recup_dir=(char *)MALLOC(strlen(res)+1+strlen(DEFAULT_RECUP_DIR)+1);
	    strcpy(params->recup_dir,res);
	    strcat(params->recup_dir,"/");
	    strcat(params->recup_dir,DEFAULT_RECUP_DIR);
	    free(res);
	    /* Create the directory */
	    params->dir_num=photorec_mkdir(params->recup_dir,params->dir_num);
	  }
#else
	  params->status=STATUS_QUIT;
#endif
	}
	break;
      case PSTATUS_EACCES:
	if(interface_cannot_create_file()!=0)
	  params->status=STATUS_QUIT;
	break;
      case PSTATUS_STOP:
	if(session_save(list_search_space, params, options) < 0)
	{
	  /* Failed to save the session! */
#ifdef HAVE_NCURSES
	  if(ask_confirmation("PhotoRec has been unable to save its session status. Answer Y to really Quit, N to resume the recovery")!=0)
#endif
	    params->status=STATUS_QUIT;
	}
	else
	{
#ifdef HAVE_NCURSES
	  if(ask_confirmation("Answer Y to really Quit, N to resume the recovery")!=0)
#endif
	    params->status=STATUS_QUIT;
	}
	break;
      case PSTATUS_OK:
	status_inc(params, options);
	if(params->status==STATUS_QUIT)
	  unlink("photorec.ses");
	break;
    }
    {
      const time_t current_time=time(NULL);
      log_info("Elapsed time %uh%02um%02us\n",
          (unsigned)((current_time-params->real_start_time)/60/60),
          (unsigned)((current_time-params->real_start_time)/60%60),
          (unsigned)((current_time-params->real_start_time)%60));
    }
    update_stats(params->file_stats, list_search_space);
    if(params->pass>0)
    {
      log_info("Pass %u +%u file%s\n",params->pass,params->file_nbr-old_file_nbr,(params->file_nbr-old_file_nbr<=1?"":"s"));
      write_stats_log(params->file_stats);
    }
    log_flush();
  }
#ifdef HAVE_NCURSES
  if(options->expert>0 && !td_list_empty(&list_search_space->list))
  {
    char msg[256];
    uint64_t data_size=0;
    struct td_list_head *search_walker = NULL;
    td_list_for_each(search_walker, &list_search_space->list)
    {
      const alloc_data_t *current_search_space;
      current_search_space=td_list_entry(search_walker, alloc_data_t, list);
      data_size += current_search_space->end - current_search_space->start + 1;
    }
    snprintf(msg, sizeof(msg),
	"Create an image_remaining.dd (%u MB) file with the unknown data (Answer N if not sure) (Y/N)",
	(unsigned int)(data_size/1000/1000));
    if(ask_confirmation("%s", msg)!=0)
    {
      char *filename;
      char *res;
      char *dst_path=strdup(params->recup_dir);
      res=strrchr(dst_path, '/');
      if(res!=NULL)
	*res='\0';
      else
      {
	dst_path[0]='.';
	dst_path[1]='\0';
      }
      filename=(char *)MALLOC(strlen(dst_path) + 1 + strlen(DEFAULT_IMAGE_NAME) + 1);
      strcpy(filename, dst_path);
      strcat(filename, "/");
      strcat(filename, DEFAULT_IMAGE_NAME);
      gen_image(filename, params->disk, list_search_space);
      free(filename);
      free(dst_path);
    }
  }
#endif
  info_list_search_space(list_search_space, NULL, params->disk->sector_size, options->keep_corrupted_file, options->verbose);
  /* Free memory */
  free_search_space(list_search_space);
#ifdef HAVE_NCURSES
  if(params->cmd_run==NULL)
    recovery_finished(params->disk, params->partition, params->file_nbr, params->recup_dir, ind_stop);
#endif
  free(params->file_stats);
  params->file_stats=NULL;
  free_header_check();
#ifdef ENABLE_DFXML
  xml_shutdown();
  xml_close();
#endif
  return 0;
}

#ifdef HAVE_NCURSES
void interface_options_photorec_ncurses(struct ph_options *options)
{
  unsigned int menu = 5;
  struct MenuItem menuOptions[]=
  {
    { 'P', NULL, "Check JPG files" },
    { 'K',NULL,"Keep corrupted files"},
    { 'S',NULL,"Try to skip indirect block"},
    { 'E',NULL,"Provide additional controls"},
    { 'L',NULL,"Low memory"},
    { 'Q',"Quit","Return to main menu"},
    { 0, NULL, NULL }
  };
  while (1)
  {
    int car;
    int real_key;
    switch(options->paranoid)
    {
      case 0:
	menuOptions[0].name="Paranoid : No";
	break;
      case 1:
	menuOptions[0].name="Paranoid : Yes (Brute force disabled)";
	break;
      default:
	menuOptions[0].name="Paranoid : Yes (Brute force enabled)";
	break;
    }
    menuOptions[1].name=options->keep_corrupted_file?"Keep corrupted files : Yes":"Keep corrupted files : No";
    menuOptions[2].name=options->mode_ext2?"ext2/ext3 mode: Yes":"ext2/ext3 mode : No";
    menuOptions[3].name=options->expert?"Expert mode : Yes":"Expert mode : No";
    menuOptions[4].name=options->lowmem?"Low memory: Yes":"Low memory: No";
    aff_copy(stdscr);
    car=wmenuSelect_ext(stdscr, 23, INTER_OPTION_Y, INTER_OPTION_X, menuOptions, 0, "PKELQ", MENU_VERT|MENU_VERT_ARROW2VALID, &menu,&real_key);
    switch(car)
    {
      case 'p':
      case 'P':
	if(options->paranoid<2)
	  options->paranoid++;
	else
	  options->paranoid=0;
	break;
      case 'k':
      case 'K':
	options->keep_corrupted_file=!options->keep_corrupted_file;
	break;
      case 's':
      case 'S':
	options->mode_ext2=!options->mode_ext2;
	break;
      case 'e':
      case 'E':
	options->expert=!options->expert;
	break;
      case 'l':
      case 'L':
	options->lowmem=!options->lowmem;
	break;
      case key_ESC:
      case 'q':
      case 'Q':
	interface_options_photorec_log(options);
	return;
    }
  }
}

#define INTER_FSELECT_X	0
#define INTER_FSELECT_Y	(LINES-2)
#define INTER_FSELECT	(LINES-10)

void interface_file_select_ncurses(file_enable_t *files_enable)
{
  int current_element_num=0;
  int offset=0;
  int old_LINES=0;	/* Screen will be cleared */
  unsigned int menu=0;
  int enable_status=files_enable[0].enable;
  static const struct MenuItem menuAdv[]=
  {
    {'q',"Quit","Return to main menu"},
    {0,NULL,NULL}
  };
  log_info("\nInterface File Select\n");
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
  mousemask(ALL_MOUSE_EVENTS, NULL);
#endif
  while(1)
  {
    int i;
    int command;
    if(old_LINES!=LINES)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"PhotoRec will try to locate the following files");
      current_element_num=0;
      offset=0;
      old_LINES=LINES;
    }
    wmove(stdscr,5,0);
    wclrtoeol(stdscr);
    wmove(stdscr,5,4);
    if(offset>0)
      wprintw(stdscr,"Previous");
    for(i=offset;files_enable[i].file_hint!=NULL && i<offset+INTER_FSELECT;i++)
    {
      wmove(stdscr,6+i-offset,0);
      wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
      if(i==current_element_num)
      {
	wattrset(stdscr, A_REVERSE);
	wprintw(stdscr,">[%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
	wattroff(stdscr, A_REVERSE);
      }
      else
      {
	wprintw(stdscr," [%c] %-4s %s", (files_enable[i].enable==0?' ':'X'),
	    (files_enable[i].file_hint->extension!=NULL?
	     files_enable[i].file_hint->extension:""),
	    files_enable[i].file_hint->description);
      }
    }
    wmove(stdscr,6+INTER_FSELECT,4);
    wclrtoeol(stdscr);	/* before addstr for BSD compatibility */
    if(files_enable[i].file_hint!=NULL)
      wprintw(stdscr,"Next");
    wmove(stdscr,6+INTER_FSELECT+1,0);
    wclrtoeol(stdscr);
    wprintw(stdscr,"Press ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"s");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    if(enable_status==0)
      wprintw(stdscr," for default selection, ");
    else
      wprintw(stdscr," to disable all file families, ");
    if(has_colors())
      wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
    wprintw(stdscr,"b");
    if(has_colors())
      wbkgdset(stdscr,' ' | COLOR_PAIR(0));
    wprintw(stdscr," to save the settings");
    command = wmenuSelect(stdscr, LINES-1, INTER_FSELECT_Y, INTER_FSELECT_X, menuAdv, 8,
	"q", MENU_BUTTON | MENU_ACCEPT_OTHERS, menu);
#if defined(KEY_MOUSE) && defined(ENABLE_MOUSE)
    if(command == KEY_MOUSE)
    {
      MEVENT event;
      if(getmouse(&event) == OK)
      {	/* When the user clicks left mouse button */
	if((event.bstate & BUTTON1_CLICKED) || (event.bstate & BUTTON1_DOUBLE_CLICKED))
	{
	  if(event.y >=6 && event.y<6+INTER_FSELECT)
	  {
	    if(((event.bstate & BUTTON1_CLICKED) && current_element_num == event.y-6-offset) ||
	      (event.bstate & BUTTON1_DOUBLE_CLICKED))
	      command='+';
	    /* Disk selection */
	    while(current_element_num > event.y-(6-offset) && current_element_num>0)
	    {
		current_element_num--;
	    }
	    while(current_element_num < event.y-(6-offset) && files_enable[current_element_num+1].file_hint!=NULL)
	    {
		current_element_num++;
	    }
	  }
	  else if(event.y==5 && event.x>=4 && event.x<=4+sizeof("Previous") &&
	      offset>0)
	    command=KEY_PPAGE;
	  else if(event.y==6+INTER_FSELECT && event.x>=4 && event.x<=4+sizeof("Next") &&
	      files_enable[i].file_hint!=NULL)
	    command=KEY_NPAGE;
	  else
	    command = menu_to_command(LINES-1, INTER_FSELECT_Y, INTER_FSELECT_X, menuAdv, 8,
		"q", MENU_BUTTON | MENU_ACCEPT_OTHERS, event.y, event.x);
	}
      }
    }
#endif
    switch(command)
    {
      case KEY_UP:
      case '8':
	if(current_element_num>0)
	  current_element_num--;
	break;
      case KEY_PPAGE:
      case '9':
	for(i=0; i<INTER_FSELECT-1 && current_element_num>0; i++)
	  current_element_num--;
	break;
      case KEY_DOWN:
      case '2':
	if(files_enable[current_element_num+1].file_hint!=NULL)
	  current_element_num++;
	break;
      case KEY_NPAGE:
      case '3':
	for(i=0; i<INTER_FSELECT-1 && files_enable[current_element_num+1].file_hint!=NULL; i++)
	  current_element_num++;
	break;
      case KEY_RIGHT:
      case '+':
      case ' ':
      case KEY_LEFT:
      case '-':
      case 'x':
      case 'X':
      case '4':
      case '5':
      case '6':
	files_enable[current_element_num].enable=1-files_enable[current_element_num].enable;
	break;
      case 's':
      case 'S':
	{
	  enable_status=1-enable_status;
	  if(enable_status==0)
	  {
	    file_enable_t *file_enable;
	    for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
	      file_enable->enable=0;
	  }
	  else
	    reset_list_file_enable(files_enable);
	}
	break;
      case 'b':
      case 'B':
	if(file_options_save(files_enable)<0)
	{
	  display_message("Failed to save the settings.");
	}
	else
	{
	  display_message("Settings recorded successfully.");
	}
	break;
      case 'q':
      case 'Q':
	return;
    }
    if(current_element_num<offset)
      offset=current_element_num;
    if(current_element_num>=offset+INTER_FSELECT)
      offset=current_element_num-INTER_FSELECT+1;
  }
}
#endif
