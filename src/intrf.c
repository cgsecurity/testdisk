/*

    File: intrf.c

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
 
#include <stdarg.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_CYGWIN_H
#include <sys/cygwin.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <errno.h>
#include "types.h"
#include "common.h"
#include "lang.h"
#include "intrf.h"
#ifdef HAVE_NCURSES
#include "intrfn.h"
#else
#include <stdio.h>
#endif
#include "fnctdsk.h"
#include "list.h"
#include "dir.h"
#include "log.h"
#include "hdaccess.h"

/* Use COLS (actual number of columns) or COLUMNS (number of columns the program has been designed for) ? */

#define GS_DEFAULT -1
#define GS_key_ESCAPE -2
extern const arch_fnct_t arch_i386;
extern const arch_fnct_t arch_gpt;
extern const arch_fnct_t arch_mac;
extern const arch_fnct_t arch_none;
extern const arch_fnct_t arch_sun;
extern const arch_fnct_t arch_xbox;
extern const char *monstr[];

static char intr_buffer_screen[MAX_LINES][LINE_LENGTH+1];
static int intr_nbr_line=0;
#ifdef HAVE_NCURSES
static void set_parent_directory(char *dst_directory);
#endif

int screen_buffer_add(const char *_format, ...)
{
  char tmp_line[BUFFER_LINE_LENGTH+1];
  char *pos_in_tmp_line=tmp_line;
  va_list ap;
  va_start(ap,_format);
  memset(tmp_line,'\0',sizeof(tmp_line));
  vsnprintf(tmp_line,BUFFER_LINE_LENGTH,_format,ap);
  va_end(ap);
  while(pos_in_tmp_line!=NULL && (intr_nbr_line<MAX_LINES))
  {
    unsigned int len=strlen(intr_buffer_screen[intr_nbr_line]);
    unsigned int nbr=LINE_LENGTH-len;
    char *ret_ligne= strchr(pos_in_tmp_line,'\n');
    if(ret_ligne!=NULL && ret_ligne-pos_in_tmp_line < nbr)
      nbr=ret_ligne-pos_in_tmp_line;
    memcpy(&intr_buffer_screen[intr_nbr_line][len], pos_in_tmp_line, nbr);
    intr_buffer_screen[intr_nbr_line][len+nbr]='\0';
    if(ret_ligne!=NULL)
    {
      if(++intr_nbr_line<MAX_LINES)
	intr_buffer_screen[intr_nbr_line][0]='\0';
      ret_ligne++;
    }
    pos_in_tmp_line=ret_ligne;
  }
  /*	log_trace("aff_intr_buffer_screen %d =>%s<=\n",intr_nbr_line,tmp_line); */
  if(intr_nbr_line==MAX_LINES)
  {
    log_warning("Buffer can't store more than %u lines.\n", MAX_LINES);
    intr_nbr_line++;
  }
  return 0;
}

void screen_buffer_to_interface()
{
#ifdef HAVE_NCURSES
  {
    int i;
    int pos=intr_nbr_line-DUMP_MAX_LINES<0?0:intr_nbr_line-DUMP_MAX_LINES;
    if(intr_nbr_line<MAX_LINES && intr_buffer_screen[intr_nbr_line][0]!='\0')
      intr_nbr_line++;
    /* curses interface */
    for (i=pos; i<intr_nbr_line && i<MAX_LINES && (i-pos)<DUMP_MAX_LINES; i++)
    {
      wmove(stdscr,DUMP_Y+1+i-pos,DUMP_X);
      wclrtoeol(stdscr);
      wprintw(stdscr,"%s",intr_buffer_screen[i]);
    }
    wrefresh(stdscr);
  }
#endif
}

void screen_buffer_to_stdout()
{
  int i;
  if(intr_nbr_line<MAX_LINES && intr_buffer_screen[intr_nbr_line][0]!='\0')
    intr_nbr_line++;
  /* to log file and stdout */
  for(i=0;i<intr_nbr_line && i<MAX_LINES;i++)
  {
    printf("%s\n",intr_buffer_screen[i]);
    log_info("%s\n",intr_buffer_screen[i]);
  }
}

void screen_buffer_reset()
{
  int i;
  intr_nbr_line=0;
  for(i=0;i<MAX_LINES;i++)
    memset(intr_buffer_screen[i],0,LINE_LENGTH+1);
}

void screen_buffer_to_log()
{
  int i;
  if(intr_buffer_screen[intr_nbr_line][0]!='\0')
    intr_nbr_line++;
  /* to log file */
  for(i=0;i<intr_nbr_line;i++)
    log_info("%s\n",intr_buffer_screen[i]);
}

const char *aff_part_aux(const unsigned int newline, const disk_t *disk_car, const partition_t *partition)
{
  char status=' ';
  static char msg[200];
  unsigned int pos=0;
  const arch_fnct_t *arch=partition->arch;
  if(arch==NULL)
  {
    arch=disk_car->arch;
    log_error("BUG: No arch for a partition\n");
  }
  msg[sizeof(msg)-1]=0;
  if((newline&AFF_PART_ORDER)==AFF_PART_ORDER)
  {
    if((partition->status!=STATUS_EXT_IN_EXT) && (partition->order!=NO_ORDER))
      pos+=snprintf(&msg[pos],sizeof(msg)-pos-1,"%2d ", partition->order);
    else
      pos+=snprintf(&msg[pos],sizeof(msg)-pos-1,"   ");
  }
  if((newline&AFF_PART_STATUS)==AFF_PART_STATUS)
  {
    switch(partition->status)
    {
      case STATUS_PRIM:           status='P'; break;
      case STATUS_PRIM_BOOT:      status='*'; break;
      case STATUS_EXT:            status='E'; break;
      case STATUS_EXT_IN_EXT:     status='X'; break;
      case STATUS_LOG:            status='L'; break;
      case STATUS_DELETED:        status='D'; break;
      default:			  status=' '; break;
    }
  }
  pos+=snprintf(&msg[pos],sizeof(msg)-pos-1,"%c", status);
  if(arch->get_partition_typename(partition)!=NULL)
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " %-20s ",
        arch->get_partition_typename(partition));
  else if(arch->get_part_type)
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " Sys=%02X               ", arch->get_part_type(partition));
  else
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " Unknown              ");
  if(disk_car->unit==UNIT_SECTOR)
  {
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " %10lu %10lu ",
        (long unsigned)(partition->part_offset/disk_car->sector_size),
        (long unsigned)((partition->part_offset+partition->part_size-1)/disk_car->sector_size));
  }
  else
  {
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1,"%5u %3u %2u %5u %3u %2u ",
        offset2cylinder(disk_car,partition->part_offset),
        offset2head(    disk_car,partition->part_offset),
        offset2sector(  disk_car,partition->part_offset),
        offset2cylinder(disk_car,partition->part_offset+partition->part_size-1),
        offset2head(    disk_car,partition->part_offset+partition->part_size-1),
        offset2sector(  disk_car,partition->part_offset+partition->part_size-1));
  }
  pos+=snprintf(&msg[pos],sizeof(msg)-pos-1,"%10lu", (long unsigned)(partition->part_size/disk_car->sector_size));
  if(partition->partname[0]!='\0')
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " [%s]",partition->partname);
  if(partition->fsname[0]!='\0')
    pos+=snprintf(&msg[pos],sizeof(msg)-pos-1, " [%s]",partition->fsname);
  return msg;
}

#define PATH_SEP '/'
#define SPATH_SEP "/"
#if defined(__CYGWIN__)
/* /cygdrive/c/ => */
#define PATH_DRIVE_LENGTH 9
#endif

#ifdef HAVE_NCURSES
static void set_parent_directory(char *dst_directory)
{
  int i;
  int last_sep=-1;
  for(i=0;dst_directory[i]!='\0';i++)
    if(dst_directory[i]==PATH_SEP)
      last_sep=i;
#ifdef __CYGWIN__
  /* /cygdrive */
  if(last_sep>PATH_DRIVE_LENGTH)
    dst_directory[last_sep]='\0';
  else
    dst_directory[PATH_DRIVE_LENGTH]='\0';
#elif defined(DJGPP) || defined(__OS2__)
  if(last_sep > 2 )
    dst_directory[last_sep]='\0';	/* subdirectory */
  else if(last_sep == 2 && dst_directory[3]!='\0')
    dst_directory[3]='\0';	/* root directory */
  else
    dst_directory[0]='\0';	/* drive list */
#else
  if(last_sep>1)
    dst_directory[last_sep]='\0';
  else
    dst_directory[1]='\0';
#endif
}
#endif

static inline char *td_getcwd(char *buf, unsigned long size)
{
  /* buf must non-NULL*/
#ifdef HAVE_GETCWD
  if(getcwd(buf, size)!=NULL)
    return buf;
#endif
  buf[0]='.';
  buf[1]='\0';
  return buf;
}

#ifdef HAVE_NCURSES
#define INTER_DIR (LINES-25+16)
static int vaff_txt(int line, WINDOW *window, const char *_format, va_list ap) __attribute__((format(printf, 3, 0)));
static int wmenuUpdate(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, unsigned int current);
static void dir_aff_entry(WINDOW *window, file_info_t *file_info);
static int wgetch_nodelay(WINDOW *window);

int get_string(char *str, int len, char *def)
{
    int c;
    int i = 0;
    int x, y;
    int use_def = FALSE;
    curs_set(1);
    getyx(stdscr, y, x);
    wclrtoeol(stdscr);
    str[0] = 0;

    if (def != NULL) {
      mvwaddstr(stdscr,y, x, def);
      wmove(stdscr,y, x);
      use_def = TRUE;
    }

    wrefresh(stdscr);
    while ((c = wgetch(stdscr)) != '\n' && c != key_CR
#ifdef PADENTER
        && c!= PADENTER
#endif
        )
    {
      switch (c) {
        /* escape is generated by enter from keypad */
        /*
           case key_ESC:
           wmove(stdscr,y, x);
           wclrtoeol(stdscr);
           curs_set(0);
           wrefresh(stdscr);
           return GS_key_ESCAPE;
         */
        case KEY_DC:
        case KEY_BACKSPACE:
          if (i > 0) {
            str[--i] = 0;
            mvaddch(y, x+i, ' ');
            wmove(stdscr,y, x+i);
          } else if (use_def) {
            wclrtoeol(stdscr);
            use_def = FALSE;
          }
          break;
        default:
          if (i < len && isprint(c)) {
            mvaddch(y, x+i, c);
            if (use_def) {
              wclrtoeol(stdscr);
              use_def = FALSE;
            }
            str[i++] = c;
            str[i] = 0;
          }
      }
      wrefresh(stdscr);
    }
    curs_set(0);
    wrefresh(stdscr);
    if (use_def)
      return GS_DEFAULT;
    else
      return i;
}

static int wgetch_nodelay(WINDOW *window)
{
  int res;
  nodelay(window,TRUE);
  res=wgetch(window);
  nodelay(window,FALSE);
  return res;
}

/*
 * Actual function which prints the button bar and highlights the active button
 * Should not be called directly. Call function menuSelect instead.
 */

static int wmenuUpdate(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, const int menuType, unsigned int current)
{
  unsigned int i, lmargin = x, ymargin = y;
  unsigned int lenNameMax=0;
  for( i = 0; menuItems[i].key!=0; i++ )
    if(strchr(available, menuItems[i].key)!=NULL )
    {
      unsigned int lenName = strlen( menuItems[i].name );
      if(lenNameMax<lenName && lenName < itemLength)
        lenNameMax=lenName;
    }
  /* Print available buttons */
  for( i = 0; menuItems[i].key!=0; i++ )
  {
    char buff[80];
    unsigned int lenName;
    const char *mi;
    wmove(window, y, x );
    wclrtoeol(window);

    /* Search next available button */
    while( menuItems[i].key!=0 && strchr(available, menuItems[i].key)==NULL )
    {
      i++;
    }
    if( menuItems[i].key==0 ) break; /* No more menu items */

    /* If selected item is not available and we have bypassed it,
       make current item selected */
    if( current < i && menuItems[current].key < 0 ) current = i;

    mi = menuItems[i].name;
    lenName = strlen( mi );
    if(lenName>=sizeof(buff))
    {
      log_critical("\nBUG: %s\n",mi);
    }
    if(lenName >= itemLength)
    {
      if( menuType & MENU_BUTTON )
        snprintf(buff, sizeof(buff),"[%s]",mi);
      else
        snprintf(buff, sizeof(buff),"%s",mi);
    }
    else
    {
      if( menuType & MENU_BUTTON )
      {
        if(menuType & MENU_VERT)
          snprintf( buff, sizeof(buff),"[%*s%-*s]", (itemLength - lenNameMax) / 2, "",
              (itemLength - lenNameMax + 1) / 2 + lenNameMax, mi );
        else
          snprintf( buff, sizeof(buff),"[%*s%-*s]", (itemLength - lenName) / 2, "",
              (itemLength - lenName + 1) / 2 + lenName, mi );
      }
      else
        snprintf( buff, sizeof(buff),"%*s%-*s", (itemLength - lenName) / 2, "",
            (itemLength - lenName + 1) / 2 + lenName, mi );
    }
    /* If current item is selected, highlight it */
    if( current == i )
    {
      wattrset(window, A_REVERSE);
    }

    /* Print item */
    mvwaddstr(window, y, x, buff );

    /* Lowlight after selected item */
    if( current == i )
    {
      wattroff(window, A_REVERSE);
    }
    if(menuType & MENU_VERT_WARN)
      mvwaddstr(window, y, x+itemLength+4, menuItems[i].desc);

    /* Calculate position for the next item */
    if( menuType & MENU_VERT )
    {
      y += 1;
      if( y >= yinfo - 1)
      {
        y = ymargin;
        x += (lenName < itemLength?itemLength:lenName) + MENU_SPACING;
        if( menuType & MENU_BUTTON ) x += 2;
      }
    }
    else
    {
      x += (lenName < itemLength?itemLength:lenName) + MENU_SPACING;
      if( menuType & MENU_BUTTON ) x += 2;
      if( x > COLUMNS - lmargin - 12 )
      {
        x = lmargin;
        y ++ ;
      }
    }
  }
  /* Print the description of selected item */
  if(!(menuType & MENU_VERT_WARN))
  {
    const char *mcd = menuItems[current].desc;
    mvwaddstr(window, yinfo, (COLUMNS - strlen( mcd )) / 2, mcd );
  }
  return y;
}

/* This function takes a list of menu items, lets the user choose one *
 * and returns the value keyboard shortcut of the selected menu item  */

int wmenuSelect(WINDOW *window, int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, int menuType, unsigned int menuDefault)
{
  unsigned int current=menuDefault;
  return wmenuSelect_ext(window, yinfo, y, x, menuItems, itemLength, available, menuType, &current, NULL);
}

int wmenuSelect_ext(WINDOW *window, const int yinfo, int y, int x, const struct MenuItem *menuItems, const unsigned int itemLength, const char *available, int menuType, unsigned int *current, int *real_key)
{
  int i, ylast = y, key = 0;
  /*
     if( ( menuType & ( MENU_HORIZ | MENU_VERT ) )==0 )    
     {
     wprintw(window,"Menu without direction. Defaulting horizontal.");
     menuType |= MENU_HORIZ;
     }
   */
  /* Warning: current may be out of bound, not checked */
  /* Make sure that the current is one of the available items */
  while(strchr(available, menuItems[*current].key)==NULL)
  {
    (*current)++ ;
    if( menuItems[*current].key==0 )
    {
      *current = 0;
    }
  }
  /* Repeat until allowable choice has been made */
  while( key==0 )
  {
    /* Display the menu */
    ylast = wmenuUpdate( window, yinfo, y, x, menuItems, itemLength, available,
        menuType, *current );
    wrefresh(window);
    /* Don't put wgetch after the following wclrtoeol */
    key = wgetch(window);
    if(real_key!=NULL)
      *real_key=key;

    /* Clear out all prompts and such */
    for( i = y; i < ylast; i ++ )
    {
      wmove(window, i, x );
      wclrtoeol(window);
    }
    wmove(window, yinfo, 0 );
    wclrtoeol(window);
    if(strchr(available, key)==NULL)
    {
      if(key=='2')
	key=KEY_DOWN;
      else if(key=='4')
	key=KEY_LEFT;
      else if(key=='5')
	key=KEY_ENTER;
      else if(key=='6')
	key=KEY_RIGHT;
      else if(key=='8')
	key=KEY_UP;
    }
    /* Cursor keys */
    switch(key)
    {
      case KEY_UP:
        if( (menuType & MENU_VERT)!=0 )
        {
          do {
            if( (*current)-- == 0 )
            {
              while( menuItems[(*current)+1].key ) (*current) ++ ;
            }
          } while( strchr( available, menuItems[*current].key )==NULL );
          key = 0;
        }
        break;
      case KEY_DOWN:
        if( (menuType & MENU_VERT)!=0 )
        {
          do {
            (*current) ++ ;
            if( menuItems[*current].key==0 ) *current = 0 ;
          } while( strchr( available, menuItems[*current].key )==NULL );
          key = 0;
        }
        break;
      case KEY_RIGHT:
        if( (menuType & MENU_HORIZ)!=0 )
        {
          do {
            (*current) ++ ;
            if( menuItems[*current].key==0 ) 
            {
              *current = 0 ;
            }
          } while( strchr( available, menuItems[*current].key )==NULL );
          key = 0;
        }
        break;
      case KEY_LEFT:
        if( (menuType & MENU_HORIZ) !=0)
        {
          do {
            if( (*current)-- == 0 )
            {
              while( menuItems[(*current) + 1].key ) (*current) ++ ;
            }
          } while( strchr( available, menuItems[*current].key )==NULL );
          key = 0;
        }
        break;
    }
    /* Enter equals to the keyboard shortcut of current menu item */
    if((key==13) || (key==10) || (key==KEY_ENTER) ||
        (((menuType & MENU_VERT) != 0) && ((menuType & MENU_VERT_ARROW2VALID) != 0)
         && (key==KEY_RIGHT || key==KEY_LEFT)))
      key = menuItems[*current].key;
#ifdef PADENTER
    if(key==PADENTER)
      key = menuItems[*current].key;
#endif

    /* Is pressed key among acceptable ones */
    if( key!=0 && (strchr(available, toupper(key))!=NULL || strchr(available, key)!=NULL))
      break;
    /* Should all keys to be accepted? */
    if( key && (menuType & MENU_ACCEPT_OTHERS)!=0 ) break;
    /* The key has not been accepted so far -> let's reject it */
#ifdef DEBUG
    if( key )
    {
      wmove(window,5,0);
      wprintw(window,"key %03X",key);
      putchar( BELL );
    }
#endif
    key = 0;
  }
  /* Clear out prompts and such */
  for( i = y; i <= ylast; i ++ )
  {
    wmove(window, i, x );
    wclrtoeol(window);
  }
  wmove(window, yinfo, 0 );
  wclrtoeol(window);
  return key;
}

/* Function menuSelect takes way too many parameters  *
 * Luckily, most of time we can do with this function */

int wmenuSimple(WINDOW *window,const struct MenuItem *menuItems, unsigned int menuDefault)
{
    unsigned int i, j, itemLength = 0;
    char available[MENU_MAX_ITEMS];

    for(i = 0; menuItems[i].key; i++)
    {
      j = strlen(menuItems[i].name);
      if( j > itemLength ) itemLength = j;
      available[i] = menuItems[i].key;
    }
    available[i] = 0;
    return wmenuSelect(window, 24, 18, 0, menuItems, itemLength, available, MENU_HORIZ | MENU_BUTTON, menuDefault);
}

/* End of command menu support code */

unsigned long long int ask_number(const unsigned long long int val_cur, const unsigned long long int val_min, const unsigned long long int val_max, const char * _format, ...)
{
  char res[200];
  char res2[200];
  char response[LINE_LENGTH];
  char def[LINE_LENGTH];
  unsigned long int tmp_val;
  va_list ap;
  va_start(ap,_format);
  vsnprintf(res,sizeof(res),_format,ap);
  if(val_min!=val_max)
    snprintf(res2,sizeof(res2),"(%llu-%llu) :",val_min,val_max);
  else
    res2[0]='\0';
  va_end(ap);
  waddstr(stdscr, res);
  waddstr(stdscr, res2);
  sprintf(def, "%llu", val_cur);
  if (get_string(response, LINE_LENGTH, def) > 0)
  {
#ifdef HAVE_ATOLL
    tmp_val = atoll(response);
#else
    tmp_val = atol(response);
#endif
    if (val_min==val_max || (tmp_val >= val_min && tmp_val <= val_max))
      return tmp_val;
  }
  return val_cur;
}

void dump_ncurses(const void *nom_dump, unsigned int lng)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  keypad(window, TRUE); /* Need it to get arrow key */
  aff_copy(window);
  dump(window, nom_dump, lng);
  dump_log(nom_dump,lng);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}

void dump(WINDOW *window, const void *nom_dump,unsigned int lng)
{
  unsigned int i,j;
  unsigned int nbr_line;
  unsigned char car;
  unsigned int pos=0;
  int done=0;
  unsigned int menu=2;   /* default : quit */
  const char *options="PNQ";
  struct MenuItem menuDump[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q',"Quit","Quit dump section"},
    { 0, NULL, NULL }
  };
  nbr_line=(lng+0x10-1)/0x10;
  if(nbr_line<=DUMP_MAX_LINES)
  {
    options="Q";
  }
  /* ncurses interface */
  mvwaddstr(window,DUMP_Y,DUMP_X,msg_DUMP_HEXA);
  /* On pourrait utiliser wscrl */
  do
  {
    for (i=pos; (i<nbr_line)&&((i-pos)<DUMP_MAX_LINES); i++)
    {
      wmove(window,DUMP_Y+i-pos,DUMP_X);
      wclrtoeol(window);
      wprintw(window,"%04X ",i*0x10);
      for(j=0; j< 0x10;j++)
      {
        if(i*0x10+j<lng)
        {
          car=*((const unsigned char*)nom_dump+i*0x10+j);
          wprintw(window,"%02x", car);
        }
        else
          wprintw(window,"  ");
        if(j%4==(4-1))
          wprintw(window," ");
      }
      wprintw(window,"  ");
      for(j=0; j< 0x10;j++)
      {
        if(i*0x10+j<lng)
        {
          car=*((const unsigned char*)nom_dump+i*0x10+j);
          if ((car<32)||(car >= 127))
            wprintw(window,".");
          else
            wprintw(window,"%c",  car);
        }
        else
          wprintw(window," ");
      }
    }
    switch (wmenuSelect(window, 24, INTER_DUMP_Y, INTER_DUMP_X, menuDump, 8, options, MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
    {
      case 'p':
      case 'P':
      case KEY_UP:
        if(strchr(options,'N')!=NULL)
        {
          menu=0;
          if(pos>0)
            pos--;
        }
        break;
      case 'n':
      case 'N':
      case KEY_DOWN:
        if(strchr(options,'N')!=NULL)
        {
          menu=1;
          if(pos<nbr_line-DUMP_MAX_LINES)
            pos++;
        }
        break;
      case KEY_PPAGE:
        if(strchr(options,'N')!=NULL)
        {
          menu=0;
          if(pos>DUMP_MAX_LINES-1)
            pos-=DUMP_MAX_LINES-1;
          else
            pos=0;
        }
        break;
      case KEY_NPAGE:
        if(strchr(options,'N')!=NULL)
        {
          menu=1;
          if(pos<nbr_line-DUMP_MAX_LINES-(DUMP_MAX_LINES-1))
            pos+=DUMP_MAX_LINES-1;
          else
            pos=nbr_line-DUMP_MAX_LINES;
        }
        break;
      case key_ESC:
      case 'q':
      case 'Q':
        done = TRUE;
        break;
    }
  } while(done==FALSE);
}

void dump2(WINDOW *window, const void *dump_1, const void *dump_2, const unsigned int lng)
{
  unsigned int i,j;
  unsigned int nbr_line;
  unsigned int pos=0;
  int done=0;
  unsigned int menu=2;   /* default : quit */
  const char *options="PNQ";
  struct MenuItem menuDump[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q',"Quit","Quit dump section"},
    { 0, NULL, NULL }
  };
  /* ncurses interface */
  nbr_line=(lng+0x08-1)/0x08;
  if(nbr_line<=DUMP_MAX_LINES)
  {
    options="Q";
  }
  do
  {
    for (i=pos; (i<nbr_line)&&((i-pos)<DUMP_MAX_LINES); i++)
    {
      wmove(window,DUMP_Y+i-pos,DUMP_X);
      wclrtoeol(window);
      wprintw(window,"%04X ",i*0x08);
      for(j=0; j<0x08;j++)
      {
        if(i*0x08+j<lng)
        {
          unsigned char car1=*((const unsigned char*)dump_1+i*0x08+j);
          unsigned char car2=*((const unsigned char*)dump_2+i*0x08+j);
          if(car1!=car2)
            wattrset(window, A_REVERSE);
          wprintw(window,"%02x", car1);
          if(car1!=car2)
            wattroff(window, A_REVERSE);
        }
        else
          wprintw(window," ");
        if(j%4==(4-1))
          wprintw(window," ");
      }
      wprintw(window,"  ");
      for(j=0; j<0x08;j++)
      {
        if(i*0x08+j<lng)
        {
          unsigned char car1=*((const unsigned char*)dump_1+i*0x08+j);
          unsigned char car2=*((const unsigned char*)dump_2+i*0x08+j);
          if(car1!=car2)
            wattrset(window, A_REVERSE);
          if ((car1<32)||(car1 >= 127))
            wprintw(window,".");
          else
            wprintw(window,"%c",  car1);
          if(car1!=car2)
            wattroff(window, A_REVERSE);
        }
        else
          wprintw(window," ");
      }
      wprintw(window,"  ");
      for(j=0; j<0x08;j++)
      {
        if(i*0x08+j<lng)
        {
          unsigned char car1=*((const unsigned char*)dump_1+i*0x08+j);
          unsigned char car2=*((const unsigned char*)dump_2+i*0x08+j);
          if(car1!=car2)
            wattrset(window, A_REVERSE);
          wprintw(window,"%02x", car2);
          if(car1!=car2)
            wattroff(window, A_REVERSE);
          if(j%4==(4-1))
            wprintw(window," ");
        }
        else
          wprintw(window," ");
      }
      wprintw(window,"  ");
      for(j=0; j<0x08;j++)
      {
        if(i*0x08+j<lng)
        {
          unsigned char car1=*((const unsigned char*)dump_1+i*0x08+j);
          unsigned char car2=*((const unsigned char*)dump_2+i*0x08+j);
          if(car1!=car2)
            wattrset(window, A_REVERSE);
          if ((car2<32)||(car2 >= 127))
            wprintw(window,".");
          else
            wprintw(window,"%c",  car2);
          if(car1!=car2)
            wattroff(window, A_REVERSE);
        }
        else
          wprintw(window," ");
      }
    }
    switch (wmenuSelect(window, 24, INTER_DUMP_Y, INTER_DUMP_X, menuDump, 8, options, MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu))
    {
      case 'p':
      case 'P':
      case KEY_UP:
        if(strchr(options,'N')!=NULL)
        {
          menu=0;
          if(pos>0)
            pos--;
        }
        break;
      case 'n':
      case 'N':
      case KEY_DOWN:
        if(strchr(options,'N')!=NULL)
        {
          menu=1;
          if(pos<nbr_line-DUMP_MAX_LINES)
            pos++;
        }
        break;
      case KEY_PPAGE:
        if(strchr(options,'N')!=NULL)
        {
          menu=0;
          if(pos>DUMP_MAX_LINES-1)
            pos-=DUMP_MAX_LINES-1;
          else
            pos=0;
        }
        break;
      case KEY_NPAGE:
        if(strchr(options,'N')!=NULL)
        {
          menu=1;
          if(pos<nbr_line-DUMP_MAX_LINES-(DUMP_MAX_LINES-1))
            pos+=DUMP_MAX_LINES-1;
          else
            pos=nbr_line-DUMP_MAX_LINES;
        }
        break;
      case key_ESC:
      case 'q':
      case 'Q':
        done = TRUE;
        break;
    }
  } while(done==FALSE);
}

int screen_buffer_display(WINDOW *window, const char *options_org, const struct MenuItem *menuItems)
{
  unsigned int menu=0;
  return screen_buffer_display_ext(window,options_org,menuItems,&menu);
}

#define INTER_ANALYSE_X		0
#define INTER_ANALYSE_Y 	8
#define INTER_ANALYSE_MENU_X 	0
#define INTER_ANALYSE_MENU_Y 	(LINES-2)
#define INTER_MAX_LINES 	(INTER_ANALYSE_MENU_Y-INTER_ANALYSE_Y-2)
int screen_buffer_display_ext(WINDOW *window, const char *options_org, const struct MenuItem *menuItems, unsigned int *menu)
{
  int i;
  int first_line_to_display=0;
  int current_line=0;
  int done=0;
  char options[20];
  struct MenuItem menuDefault[]=
  {
    { 'P', "Previous",""},
    { 'N', "Next","" },
    { 'Q', "Quit","Quit this section"},
    { 0, NULL, NULL }
  };
  const unsigned int itemLength=8;
  /* FIXME itemLength */
  strncpy(options,"Q",sizeof(options));
  strncat(options,options_org,sizeof(options)-strlen(options));
  if(intr_buffer_screen[intr_nbr_line][0]!='\0')
    intr_nbr_line++;
  /* curses interface */
  do
  {
    int key;
    wmove(window, INTER_ANALYSE_Y-1, INTER_ANALYSE_X+4);
    wclrtoeol(window);
    if(first_line_to_display>0)
      wprintw(window, "Previous");
    if(intr_nbr_line>INTER_MAX_LINES && has_colors())
    {
      for (i=first_line_to_display; i<intr_nbr_line && (i-first_line_to_display)<INTER_MAX_LINES; i++)
      {
	wmove(window,INTER_ANALYSE_Y+i-first_line_to_display,INTER_ANALYSE_X);
	wclrtoeol(window);
	if(i==current_line)
	  wattrset(window, A_REVERSE);
	wprintw(window,"%s",intr_buffer_screen[i]);
	if(i==current_line)
	  wattroff(window, A_REVERSE);
      }
    }
    else
    {
      for (i=first_line_to_display; i<intr_nbr_line && (i-first_line_to_display)<INTER_MAX_LINES; i++)
      {
	wmove(window,INTER_ANALYSE_Y+i-first_line_to_display,INTER_ANALYSE_X);
	wclrtoeol(window);
	wprintw(window,"%s",intr_buffer_screen[i]);
      }
    }
    wmove(window, INTER_ANALYSE_Y+INTER_MAX_LINES, INTER_ANALYSE_X+4);
    wclrtoeol(window);
    if(i<intr_nbr_line)
      wprintw(window, "Next");
    key=wmenuSelect_ext(window, INTER_ANALYSE_MENU_Y+1,
	INTER_ANALYSE_MENU_Y, INTER_ANALYSE_MENU_X,
	(menuItems!=NULL?menuItems:menuDefault), itemLength, options,
	MENU_HORIZ | MENU_BUTTON | MENU_ACCEPT_OTHERS, menu,NULL);
    switch (key)
    {
      case key_ESC:
      case 'q':
      case 'Q':
        done = TRUE;
        break;
      case 'p':
      case 'P':
      case KEY_UP:
        if(current_line>0)
          current_line--;
        break;
      case 'n':
      case 'N':
      case KEY_DOWN:
        if(current_line<intr_nbr_line-1)
          current_line++;
        break;
      case KEY_PPAGE:
        if(current_line>INTER_MAX_LINES-1)
          current_line-=INTER_MAX_LINES-1;
        else
          current_line=0;
        break;
      case KEY_NPAGE:
        if(current_line+INTER_MAX_LINES-1 < intr_nbr_line-1)
          current_line+=INTER_MAX_LINES-1;
        else
          current_line=intr_nbr_line-1;
        break;
      default:
        if(strchr(options,toupper(key))!=NULL)
          return toupper(key);
        break;
    }
    if(current_line<first_line_to_display)
      first_line_to_display=current_line;
    if(current_line>=first_line_to_display+INTER_MAX_LINES)
      first_line_to_display=current_line-INTER_MAX_LINES+1;
  } while(done!=TRUE);
  return 0;
}

void aff_CHS(const CHS_t * CHS)
{
  wprintw(stdscr,"%5u %3u %2u ", CHS->cylinder, CHS->head, CHS->sector);
}

void aff_CHS_buffer(const CHS_t * CHS)
{
  screen_buffer_add("%5u %3u %2u ", CHS->cylinder, CHS->head, CHS->sector);
}

void aff_part(WINDOW *window,const unsigned int newline,const disk_t *disk_car,const partition_t *partition)
{
  const char *msg;
  msg=aff_part_aux(newline, disk_car, partition);
  wprintw(window,"%s",msg);
}

void aff_LBA2CHS(const disk_t *disk_car, const unsigned long int pos_LBA)
{
  unsigned long int tmp;
  unsigned long int cylinder, head, sector;
  tmp=disk_car->geom.sectors_per_head;
  sector=(pos_LBA%tmp)+1;
  tmp=pos_LBA/tmp;
  cylinder=tmp / disk_car->geom.heads_per_cylinder;
  head=tmp % disk_car->geom.heads_per_cylinder;
  wprintw(stdscr, "%lu/%lu/%lu", cylinder, head, sector);
}

int ask_YN(WINDOW *window)
{
  char res;
  curs_set(1);
  wrefresh(window);
  do
  {
    res=toupper(wgetch(window));
  } while((res!=c_NO)&&(res!=c_YES));
  curs_set(0);
  wprintw(window,"%c\n",res);
  return (res==c_YES);
}

int ask_confirmation(const char*_format, ...)
{
  va_list ap;
  int res;
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  va_start(ap,_format);
  vaff_txt(4, window, _format, ap);
  va_end(ap);
  res=ask_YN(window);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  return res;
}

static int display_message_ncurses(const char*msg)
{
  int pipo=0;
  static struct MenuItem menuGeometry[]=
  {
    { 'Q', "Ok", "" },
    { 0, NULL, NULL }
  };
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  mvwaddstr(window,5,0,msg);
  wmenuSimple(window,menuGeometry, pipo);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  return 0;
}

void not_implemented(const char *msg)
{
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  wmove(window,7,0);
  wprintw(window,"Function %s not implemented",msg);
  log_warning("Function %s not implemented\n",msg);
  wmove(window,22,0);
  wattrset(window, A_REVERSE);
  wprintw(window,"[ Abort ]");
  wattroff(window, A_REVERSE);
  wrefresh(window);
  while(wgetch(window)==ERR);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
}

#if defined(DJGPP) || defined(__MINGW32__)
#else
static SCREEN *screenp=NULL;
#endif

static char *filename_to_directory(const char *filename)
{
  char buf[2048];
  char *res;
#ifdef HAVE_READLINK
  int len;
  len=readlink(filename,buf,sizeof(buf)-1);
  if(len>=0)
    buf[len]='\0';
  else
  {
    strncpy(buf,filename,sizeof(buf)-1);
    buf[sizeof(buf)-1]='\0';
  }
#else
  strncpy(buf,filename,sizeof(buf)-1);
  buf[sizeof(buf)-1]='\0';
#endif
  res=dirname(buf);
#ifdef HAVE_GETCWD
  if(res!=NULL && strcmp(res,".")==0 && getcwd(buf, sizeof(buf)-1)!=NULL)
  {
    buf[sizeof(buf)-1]='\0';
    res=buf;
  }
#endif
#ifdef __CYGWIN__
  {
    char beautifull_dst_directory[2048];
    cygwin_conv_to_win32_path(res, beautifull_dst_directory);
    return strdup(beautifull_dst_directory);
  }
#else
  return strdup(res);
#endif
}

int start_ncurses(const char *prog_name, const char *real_prog_name)
{
#if defined(DJGPP) || defined(__MINGW32__)
  if(initscr()==NULL)
  {
    log_critical("initscr() has failed. Exiting\n");
    printf("initscr() has failed. Exiting\n");
    printf("Press Enter key to quit.\n");
    getchar();
    return 1;
  }
#else
  {
    int term_overwrite;
    char *terminfo=filename_to_directory(real_prog_name);
    for(term_overwrite=0;screenp==NULL && term_overwrite<=1;term_overwrite++)
    {
#ifdef HAVE_SETENV
#if defined(TARGET_BSD)
      setenv("TERM","cons25",term_overwrite);
#elif defined(TARGET_LINUX)
      setenv("TERM","linux",term_overwrite);
#elif defined(__CYGWIN__)
      setenv("TERM","cygwin",term_overwrite);
#elif defined(__OS2__)
      setenv("TERM","ansi",term_overwrite);
#elif defined(__APPLE__)
      setenv("TERM","xterm-color",term_overwrite);
#endif
#endif
      screenp=newterm(NULL,stdout,stdin);
#ifdef HAVE_SETENV
      if(screenp==NULL && terminfo!=NULL)
      {
        setenv("TERMINFO", terminfo, 1);
        screenp=newterm(NULL,stdout,stdin);
      }
      if(screenp==NULL)
      {
        setenv("TERMINFO",".",1);
        screenp=newterm(NULL,stdout,stdin);
      }
      if(screenp==NULL)
        unsetenv("TERMINFO");
#endif
    }
    if(screenp==NULL)
    {
      log_critical("Terminfo file is missing.\n");
#if defined(__CYGWIN__)
      printf("The terminfo file '%s\\c\\cygwin' is missing.\n", terminfo);
#else
      printf("Terminfo file is missing.\n");
#endif
      printf("Extract all files and subdirectories before running the program.\n");
      printf("Press Enter key to quit.\n");
      getchar();
      free(terminfo);
      return 1;
    }
    free(terminfo);
  }
#endif
  noecho();
#ifndef DJGPP
  nonl(); /*don't use for Dos version but enter will work with it... dilema */
#endif
  /*  intrflush(stdscr, FALSE); */
  cbreak();
  /* Should solve a problem with users who redefined the colors */
  if(has_colors())
  {
    start_color();
    init_pair(1, COLOR_RED, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
  }
  curs_set(0);
  {
    int quit=0;
    while(LINES>=8 && LINES<25 && quit==0)
    {
      aff_copy(stdscr);
      wmove(stdscr,4,0);
      wprintw(stdscr,"%s need 25 lines to work.", prog_name);
      wmove(stdscr,5,0);
      wprintw(stdscr,"Please enlarge the terminal.");
      wmove(stdscr,LINES-2,0);
      wattrset(stdscr, A_REVERSE);
      wprintw(stdscr,"[ Quit ]");
      wattroff(stdscr, A_REVERSE);
      wrefresh(stdscr);
      switch(wgetch(stdscr))
      {
	case 'q':
	case 'Q':
	case KEY_ENTER:
#ifdef PADENTER
	case PADENTER:
#endif
	case '\n':
	case '\r':
	  quit=1;
	  break;
      }
    }
  }
  if(LINES<25)
  {
    end_ncurses();
    printf("%s need 25 lines to work.\nPlease enlarge the terminal and restart %s.\n",prog_name,prog_name);
    log_critical("Terminal has only %u lines\n",LINES);
    return 1;
  }
  return 0;
}

int end_ncurses()
{
  wclear(stdscr);
  wrefresh(stdscr);
  nl();
  endwin();
#if defined(DJGPP) || defined(__MINGW32__)
#else
#ifdef HAVE_DELSCREEN
  if(screenp!=NULL)
    delscreen(screenp);
#endif
#endif
  return 0;
}

char *ask_log_location(const char*filename)
{
  static char response[LINE_LENGTH];
  aff_copy(stdscr);
  wmove(stdscr,6,0);
  wprintw(stdscr,"Cannot open %s: %s\n",filename, strerror(errno));
  wmove(stdscr,8,0);
  wprintw(stdscr,"Please enter the full log filename or press ");
  if(has_colors())
    wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(0));
  wprintw(stdscr,"Enter");
  if(has_colors())
    wbkgdset(stdscr,' ' | COLOR_PAIR(0));
  wmove(stdscr,9,0);
  wprintw(stdscr,"to abort log file creation.\n");
  if (get_string(response, LINE_LENGTH, NULL) > 0)
    return response;
  return NULL;
}

static int intrf_no_disk_ncurses(const char *prog_name)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"  %s is free software, and",prog_name);
  wmove(stdscr,5,0);
  wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"No harddisk found\n");
  wmove(stdscr,8,0);
#if defined(__CYGWIN__) || defined(__MINGW32__)
  wprintw(stdscr,"You need to be administrator to use %s.\n", prog_name);
  wmove(stdscr,9,0);
  wprintw(stdscr,"Under Win9x, use the DOS version instead.\n");
  wmove(stdscr,10,0);
  wprintw(stdscr,"Under Vista, select %s, right-click and choose \"Run as administrator\".\n", prog_name);
#elif defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    wprintw(stdscr,"You need to be root to use %s.\n", prog_name);
#ifdef SUDO_BIN
    {
      static const struct MenuItem menuSudo[]=
      {
	{'S',"Sudo","Use the sudo command to restart as root"},
	{'Q',"Quit",""},
	{0,NULL,NULL}
      };
      unsigned int menu=0;
      int command;
      command = wmenuSelect_ext(stdscr,24, 21, 0, menuSudo, 8,
	  "SQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
      if(command=='s' || command=='S')
	return 1;
      return 0;
    }
#endif
  }
#endif
#endif
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  wprintw(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(wgetch(stdscr)==ERR);
  return 0;
}

int check_enter_key_or_s(WINDOW *window)
{
  switch(wgetch_nodelay(window))
  {
    case KEY_ENTER:
#ifdef PADENTER
    case PADENTER:
#endif
    case '\n':
    case '\r':
    case 's':
    case 'S':
      return 1;
  }
  return 0;
}

static int interface_partition_type_ncurses(disk_t *disk_car)
{
  /* arch_list must match the order from menuOptions */
  const arch_fnct_t *arch_list[]={&arch_i386, &arch_gpt, &arch_mac, &arch_none, &arch_sun, &arch_xbox, NULL};
  unsigned int menu;
  for(menu=0;arch_list[menu]!=NULL && disk_car->arch!=arch_list[menu];menu++);
  if(arch_list[menu]==NULL)
  {
    menu=0;
    disk_car->arch=arch_list[menu];
  }
  /* ncurses interface */
  {
    int car;
    int real_key;
    struct MenuItem menuOptions[]=
    {
      { 'I', arch_i386.part_name, "Intel/PC partition" },
      { 'G', arch_gpt.part_name, "EFI GPT partition map (Mac i386, some x86_64...)" },
      { 'M', arch_mac.part_name, "Apple partition map" },
      { 'N', arch_none.part_name, "Non partitioned media" },
      { 'S', arch_sun.part_name, "Sun Solaris partition"},
      { 'X', arch_xbox.part_name, "XBox partition"},
      { 'Q', "Return", "Return to disk selection"},
      { 0, NULL, NULL }
    };
    aff_copy(stdscr);
    wmove(stdscr,5,0);
    wprintw(stdscr,"%s\n",disk_car->description_short(disk_car));
    wmove(stdscr,INTER_PARTITION_Y-1,0);
    wprintw(stdscr,"Please select the partition table type, press Enter when done.");
    wmove(stdscr,20,0);
    wprintw(stdscr,"Note: Do NOT select 'None' for media with only a single partition. It's very");
    wmove(stdscr,21,0);
    wprintw(stdscr,"rare for a drive to be 'Non-partitioned'.");
    car=wmenuSelect_ext(stdscr, 24, INTER_PARTITION_Y, INTER_PARTITION_X, menuOptions, 7, "IGMNSXQ", MENU_BUTTON | MENU_VERT | MENU_VERT_WARN, &menu,&real_key);
    switch(car)
    {
      case 'i':
      case 'I':
        disk_car->arch=&arch_i386;
        break;
      case 'g':
      case 'G':
        disk_car->arch=&arch_gpt;
        break;
      case 'm':
      case 'M':
        disk_car->arch=&arch_mac;
        break;
      case 'n':
      case 'N':
        disk_car->arch=&arch_none;
        break;
      case 's':
      case 'S':
        disk_car->arch=&arch_sun;
        break;
      case 'x':
      case 'X':
        disk_car->arch=&arch_xbox;
        break;
      case 'q':
      case 'Q':
        return 1;
    }
  }
  autoset_unit(disk_car);
  return 0;
}

#if defined(DJGPP) || defined(__OS2__)
void get_dos_drive_list(struct td_list_head *list);

void get_dos_drive_list(struct td_list_head *list)
{
  int i;
  for(i='a';i<='z';i++)
  {
    file_info_t *new_drive;
    new_drive=(file_info_t*)MALLOC(sizeof(*new_drive));
    new_drive->name[0]=i;
    new_drive->name[1]=':';
    new_drive->name[2]=PATH_SEP;
    new_drive->name[3]='\0';
    new_drive->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
    td_list_add_tail(&new_drive->list, list);
  }
}
#endif

#define ASK_LOCATION_WAITKEY 	0
#define ASK_LOCATION_UPDATE	1
#define ASK_LOCATION_NEWDIR	2
#define ASK_LOCATION_QUIT	3

char *ask_location(const char*msg, const char *src_dir)
{
  char dst_directory[4096];
  char *res=NULL;
  int quit;
  WINDOW *window=newwin(0,0,0,0);	/* full screen */
  aff_copy(window);
  td_getcwd(dst_directory, sizeof(dst_directory));
  do
  {
    DIR* dir;
    static file_info_t dir_list = {
      .list = TD_LIST_HEAD_INIT(dir_list.list),
      .name = {0}
    };
    wmove(window,7,0);
    wclrtoeol(window);	/* before addstr for BSD compatibility */
    if(has_colors())
      wbkgdset(window,' ' | A_BOLD | COLOR_PAIR(0));
    waddstr(window,"Directory listing in progress...");
    if(has_colors())
      wbkgdset(window,' ' | COLOR_PAIR(0));
    wrefresh(window);
#if defined(DJGPP) || defined(__OS2__)
    if(dst_directory[0]=='\0')
    {
      get_dos_drive_list(&dir_list.list);
      dir=NULL;
    }
    else
      dir=opendir(dst_directory);
#else
    dir=opendir(dst_directory);
#endif
    if(dir!=NULL)
    {
      struct dirent *dir_entrie;
      file_info_t *file_info;
      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
      do
      {
        char current_file[4096];
        dir_entrie=readdir(dir);
	/* if dir_entrie exists
	 *   there is enough room to store the filename
	 *   dir_entrie->d_name is ".", ".." or something that doesn't begin by a "."
	 * */
        if(dir_entrie!=NULL
            && strlen(dst_directory)+1+strlen(file_info->name)+1<=sizeof(current_file) &&
            (dir_entrie->d_name[0]!='.' ||
             dir_entrie->d_name[1]=='\0' ||
             (dir_entrie->d_name[1]=='.' && dir_entrie->d_name[2]=='\0'))
#ifdef __CYGWIN__
            && (strlen(dst_directory)>PATH_DRIVE_LENGTH || dir_entrie->d_name[0]!='.')
#endif
          )
        {
          strcpy(current_file,dst_directory);
#if defined(DJGPP) || defined(__OS2__)
          if(current_file[0]!='\0'&&current_file[1]!='\0'&&current_file[2]!='\0'&&current_file[3]!='\0')
#else
            if(current_file[1]!='\0')
#endif
              strcat(current_file,SPATH_SEP);
          strcat(current_file,dir_entrie->d_name);
#ifdef HAVE_LSTAT
          if(lstat(current_file,&file_info->stat)==0)
#else
            if(stat(current_file,&file_info->stat)==0)
#endif
	    {
#if defined(DJGPP) || defined(__OS2__)
	      /* If the C library doesn't use posix definition, st_mode need to be fixed */
	      if(S_ISDIR(file_info->stat.st_mode))
		file_info->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
	      else
		file_info->stat.st_mode=LINUX_S_IFREG|LINUX_S_IRWXUGO;
#endif
#ifdef __CYGWIN__
	      /* Fix Drive list */
	      if(strlen(dst_directory)<=PATH_DRIVE_LENGTH)
	      {
		file_info->stat.st_mode=LINUX_S_IFDIR|LINUX_S_IRWXUGO;
		file_info->stat.st_mtime=0;
		file_info->stat.st_uid=0;
		file_info->stat.st_gid=0;
	      }
#endif
	      strncpy(file_info->name,dir_entrie->d_name,sizeof(file_info->name));
	      td_list_add_sorted(&file_info->list, &dir_list.list, filesort);
	      file_info=(file_info_t*)MALLOC(sizeof(*file_info));
	    }
        }
      } while(dir_entrie!=NULL);
      free(file_info);
      closedir(dir);
    }
    if(dir_list.list.next!=&dir_list.list)
    {
      struct td_list_head *current_file=dir_list.list.next;
      int offset=0;
      int pos_num=0;
      int old_LINES=LINES;
      do
      {
	int dst_directory_ok=0;
	if(old_LINES!=LINES)
	{ /* Screen size has changed, reset to initial values */
	  current_file=dir_list.list.next;
	  offset=0;
	  pos_num=0;
	  old_LINES=LINES;
	}
        aff_copy(window);
        wmove(window,7,0);
#ifdef __CYGWIN__
        if(strlen(dst_directory)<=PATH_DRIVE_LENGTH)
          wprintw(window,"To select a drive, use the arrow keys.");
        else
          wprintw(window,"To select another directory, use the arrow keys.");
#elif defined(DJGPP) || defined(__OS2__)
        if(dst_directory[0]=='\0')
          wprintw(window,"To select a drive, use the arrow keys.");
        else
          wprintw(window,"To select another directory, use the arrow keys.");
#else
        wprintw(window,"To select another directory, use the arrow keys.");
#endif
        {
          struct td_list_head *file_walker = NULL;
          int i=0;
          td_list_for_each(file_walker,&dir_list.list)
          {
	    if(i++<offset)
	      continue;
            {
              file_info_t *file_info;
              file_info=td_list_entry(file_walker, file_info_t, list);
              wmove(window,8-1+i-offset,0);
              wclrtoeol(window);	/* before addstr for BSD compatibility */
              if(file_walker==current_file)
                wattrset(window, A_REVERSE);
              dir_aff_entry(window,file_info);
              if(file_walker==current_file)
                wattroff(window, A_REVERSE);
            }
            if(offset+INTER_DIR<=i)
              break;
          }
	  wmove(window, 8+INTER_DIR, 4);
	  wclrtoeol(window);
	  if(file_walker!=&dir_list.list && file_walker->next!=&dir_list.list)
	    wprintw(window, "Next");
        }
	if(strcmp(dst_directory,".")==0)
	{
	  aff_txt(4, window, msg, src_dir, "the program is running from");
	  dst_directory_ok=1;
	}
	else
	{
#ifdef __CYGWIN__
	  if(strlen(dst_directory)>PATH_DRIVE_LENGTH)
	  {
	    char beautifull_dst_directory[4096];
	    cygwin_conv_to_win32_path(dst_directory, beautifull_dst_directory);
	    aff_txt(4, window, msg, src_dir, beautifull_dst_directory);
	    dst_directory_ok=1;
	  }
#elif defined(DJGPP) || defined(__OS2__)
	  if(strlen(dst_directory)>0)
	  {
	    aff_txt(4, window, msg, src_dir, dst_directory);
	    dst_directory_ok=1;
	  }
#else
	  aff_txt(4, window, msg, src_dir, dst_directory);
	  dst_directory_ok=1;
#endif
	}
        wclrtoeol(window);	/* before addstr for BSD compatibility */
        wrefresh(window);
        do
        {
          quit=ASK_LOCATION_WAITKEY;
          switch(wgetch(window))
          {
            case 'y':
            case 'Y':
              if(dst_directory_ok>0)
              {
                res=strdup(dst_directory);
                quit=ASK_LOCATION_QUIT;
              }
              break;
            case 'n':
            case 'N':
              res=NULL;
              quit=ASK_LOCATION_QUIT;
              break;
            case KEY_UP:
	    case '8':
              if(current_file->prev!=&dir_list.list)
              {
                current_file=current_file->prev;
                pos_num--;
                quit=ASK_LOCATION_UPDATE;
              }
              break;
            case KEY_DOWN:
	    case '2':
              if(current_file->next!=&dir_list.list)
              {
                current_file=current_file->next;
                pos_num++;
                quit=ASK_LOCATION_UPDATE;
              }
              break;
            case KEY_PPAGE:
              {
                int i;
                for(i=0; i<INTER_DIR-1 && current_file->prev!=&dir_list.list; i++)
                {
                  current_file=current_file->prev;
                  pos_num--;
                  quit=ASK_LOCATION_UPDATE;
                }
              }
              break;
            case KEY_NPAGE:
              {
                int i;
                for(i=0; i<INTER_DIR-1 && current_file->next!=&dir_list.list; i++)
                {
                  current_file=current_file->next;
                  pos_num++;
                  quit=ASK_LOCATION_UPDATE;
                }
              }
              break;
	    case KEY_LEFT:
	    case '4':
	      set_parent_directory(dst_directory);
	      quit=ASK_LOCATION_NEWDIR;
	      break;
            case KEY_RIGHT:
            case '\r':
            case '\n':
	    case '6':
            case KEY_ENTER:
#ifdef PADENTER
            case PADENTER:
#endif
	      {
		file_info_t *file_info;
		file_info=td_list_entry(current_file, file_info_t, list);
		if(current_file!=&dir_list.list &&
		  (LINUX_S_ISDIR(file_info->stat.st_mode) || LINUX_S_ISLNK(file_info->stat.st_mode)))
		if(current_file!=&dir_list.list)
		{
		  if(strcmp(file_info->name,".")==0)
		  {
		  }
		  else if(strcmp(file_info->name,"..")==0)
		  {
		    set_parent_directory(dst_directory);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		  else if(strlen(dst_directory)+1+strlen(file_info->name)+1<=sizeof(dst_directory))
		  {
#if defined(DJGPP) || defined(__OS2__)
		    if(dst_directory[0]!='\0'&&dst_directory[1]!='\0'&&dst_directory[2]!='\0'&&dst_directory[3]!='\0')
#else
		      if(dst_directory[1]!='\0')
#endif
			strcat(dst_directory,SPATH_SEP);
		    strcat(dst_directory,file_info->name);
		    quit=ASK_LOCATION_NEWDIR;
		  }
		}
	      }
              break;

          }
	  if(pos_num<offset)
	    offset=pos_num;
	  if(pos_num>=offset+INTER_DIR)
	    offset=pos_num-INTER_DIR+1;
        } while(quit==ASK_LOCATION_WAITKEY && old_LINES==LINES);
      } while(quit==ASK_LOCATION_UPDATE || old_LINES!=LINES);
      delete_list_file_info(&dir_list.list);
    }
    else
    {
      set_parent_directory(dst_directory);
      quit=ASK_LOCATION_NEWDIR;
    }
  } while(quit==ASK_LOCATION_NEWDIR);
  delwin(window);
  (void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
  touchwin(stdscr);
#endif
  return res;
}

static int vaff_txt(int line, WINDOW *window, const char *_format, va_list ap)
{
  char buffer[1024];
  int i;
  vsnprintf(buffer,sizeof(buffer),_format,ap);
  buffer[sizeof(buffer)-1]='\0';
  for(i=0;buffer[i]!='\0';)
  {
    char buffer2[1024];
    int j,end=i,end2=i;
    for(j=i;buffer[j]!='\0' && (j-i)<COLUMNS;j++)
      if((buffer[j]==' ' || buffer[j]=='\t') && buffer[j+1]!='?' && buffer[j+1]!='[')
      {
        end=j;
        end2=j;
      }
      else if(buffer[j]=='\n')
      {
        end=j;
        end2=j;
        break;
      }
      else if(buffer[j]=='\\' || buffer[j]=='/')
        end2=j;
    if(end2>end && end-i<COLUMNS*3/4)
      end=end2;
    if(end==i)
      end=j-1;
    if(buffer[j]=='\0')
      end=j;
    wmove(window,line,0);
    line++;
    memcpy(buffer2,&buffer[i],end-i+1);
    buffer2[end-i+1]='\0';
    waddstr(window,buffer2);
    for(i=end;buffer[i]==' ' || buffer[i]=='\t' || buffer[i]=='\n'; i++);
  }
  return line;
}

int aff_txt(int line, WINDOW *window, const char *_format, ...)
{
  va_list ap;
  va_start(ap,_format);
  line=vaff_txt(line, window, _format, ap);
  va_end(ap);
  return line;
}

static void dir_aff_entry(WINDOW *window, file_info_t *file_info)
{
  struct tm		*tm_p;
  char str[11];
  char		datestr[80];
  if(file_info->stat.st_mtime!=0)
  {
    tm_p = localtime(&file_info->stat.st_mtime);
    snprintf(datestr, sizeof(datestr),"%2d-%s-%4d %02d:%02d",
        tm_p->tm_mday, monstr[tm_p->tm_mon],
        1900 + tm_p->tm_year, tm_p->tm_hour,
        tm_p->tm_min);
    /* May have to use %d instead of %e */
  } else {
    strncpy(datestr, "                 ",sizeof(datestr));
  }
  mode_string(file_info->stat.st_mode,str);
  wprintw(window, "%s %5u %5u   ", 
      str, (unsigned int)file_info->stat.st_uid, (unsigned int)file_info->stat.st_gid);
  wprintw(window, "%7llu", (long long unsigned int)file_info->stat.st_size);
  /* screen may overlap due to long filename */
  wprintw(window, " %s %s", datestr, file_info->name);
}
#else
char *ask_log_location(const char*filename)
{
  return NULL;
}

void not_implemented(const char *msg)
{
}

int ask_confirmation(const char*_format, ...)
{	/* Don't confirm */
  return 0;
}

char *ask_location(const char*msg, const char *src_dir)
{
  char dst_directory[4096];
  td_getcwd(dst_directory, sizeof(dst_directory));
  return strdup(dst_directory);
}
#endif

unsigned long long int ask_number_cli(char **current_cmd, const unsigned long long int val_cur, const unsigned long long int val_min, const unsigned long long int val_max, const char * _format, ...)
{
  if(*current_cmd!=NULL)
  {
    unsigned long int tmp_val;
    while(*current_cmd[0]==',')
      (*current_cmd)++;
#ifdef HAVE_ATOLL
      tmp_val = atoll(*current_cmd);
#else
      tmp_val = atol(*current_cmd);
#endif
    while(*current_cmd[0]!=',' && *current_cmd[0]!='\0')
      (*current_cmd)++;
    if (val_min==val_max || (tmp_val >= val_min && tmp_val <= val_max))
      return tmp_val;
    else
    {
      {
        char res[200];
        char res2[200];
        va_list ap;
        va_start(ap,_format);
        vsnprintf(res,sizeof(res),_format,ap);
        if(val_min!=val_max)
          snprintf(res2,sizeof(res2),"(%llu-%llu) :",val_min,val_max);
        else
          res2[0]='\0';
        va_end(ap);
        log_error(res);
        log_error(res2);
        log_error("Invalid value\n");
      }
    }
  }
  return val_cur;
}

void aff_part_buffer(const unsigned int newline,const disk_t *disk_car,const partition_t *partition)
{
  const char *msg;
  msg=aff_part_aux(newline, disk_car, partition);
  screen_buffer_add("%s\n", msg);
}

void log_CHS_from_LBA(const disk_t *disk_car, const unsigned long int pos_LBA)
{
  unsigned long int tmp;
  unsigned long int cylinder, head, sector;
  tmp=disk_car->geom.sectors_per_head;
  sector=(pos_LBA%tmp)+1;
  tmp=pos_LBA/tmp;
  cylinder=tmp / disk_car->geom.heads_per_cylinder;
  head=tmp % disk_car->geom.heads_per_cylinder;
  log_info("%lu/%lu/%lu", cylinder, head, sector);
}

int display_message(const char*msg)
{
  log_info("%s",msg);
#ifdef HAVE_NCURSES
  return display_message_ncurses(msg);
#else
  return 0;
#endif
}

int intrf_no_disk(const char *prog_name)
{
  log_critical("No disk found\n");
#ifdef HAVE_NCURSES
  return intrf_no_disk_ncurses(prog_name);
#else
  printf("No disk found\n");
  return 0;
#endif
}

int interface_partition_type(disk_t *disk_car, const int verbose, char**current_cmd)
{
  const arch_fnct_t *arch_list[]={&arch_i386, &arch_gpt, &arch_none, &arch_sun, &arch_mac, NULL};
  int ask_user=1;
  if(*current_cmd!=NULL)
  {
    int keep_asking;
    do
    {
      int i;
      ask_user=0;
      keep_asking=0;
      while(*current_cmd[0]==',')
        (*current_cmd)++;
      for(i=0;arch_list[i]!=NULL;i++)
        if(strncmp(*current_cmd, arch_list[i]->part_name_option, strlen(arch_list[i]->part_name_option))==0)
        {
          (*current_cmd)+=strlen(arch_list[i]->part_name_option);
          disk_car->arch=arch_list[i];
	  autoset_unit(disk_car);
          keep_asking=1;
        }
      if(strncmp(*current_cmd, "ask_type", 8)==0)
      {
	(*current_cmd)+=8;
	ask_user=1;
      }
    } while(keep_asking>0);
  }
  if(ask_user>0)
  {
#ifdef HAVE_NCURSES
    if(interface_partition_type_ncurses(disk_car))
      return 1;
#endif
  }
  log_info("%s\n",disk_car->description_short(disk_car));
  log_info("Partition table type: %s\n",disk_car->arch->part_name);
  hd_update_geometry(disk_car, 0,verbose);
  return 0;
}
