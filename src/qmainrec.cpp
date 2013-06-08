/*

    File: qmainrec.c

    Copyright (C) 1998-2013 Christophe GRENIER <grenier@cgsecurity.org>

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

#include <QApplication>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include "qphotorec.h"
#include "log.h"
#include "misc.h"
#include "dir.h"
#include "ext2_dir.h"
#include "ewf.h"
#include "file_jpg.h"
#include "ntfs_dir.h"

#ifdef Q_WS_X11
static void run_photorec(int argc, char **argv)
{
  int i;
  char **argv2;
  argv2 = (char **)MALLOC(sizeof(char *) * (argc + 2));
  argv2[0]=strdup("photorec");
  for (i=0; i <  argc; i++)
    argv2[i+1] = argv[i];
  argv2[i+1]=NULL;
  printf("DISPLAY variable not set. Switching to PhotoRec in text mode.\n");
  fflush(stdout);
  if(execv(argv2[0], argv2)<0)
  {
    printf("photorec failed: %s\n", strerror(errno));
  }
  free(argv2[0]);
  free(argv2);
}
#endif

int main(int argc, char *argv[])
{
  int log_errno=0;
  time_t my_time;
  FILE *log_handle;
#ifdef Q_WS_X11
  if(getenv("DISPLAY")==NULL)
    run_photorec(argc, argv);
#endif
  QApplication a(argc, argv);
  log_handle=log_open("qphotorec.log", TD_LOG_CREATE, &log_errno);
#ifdef HAVE_DUP2
  if(log_handle)
  {
    dup2(fileno(log_handle),2);
  }
#endif
  my_time=time(NULL);
  log_info("\n\n%s",ctime(&my_time));
  log_info("PhotoRec %s, Data Recovery Utility, %s\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org\n", VERSION, TESTDISKDATE);
  log_info("OS: %s\n" , get_os());
  log_info("Compiler: %s\n", get_compiler());
  log_info("Compilation date: %s\n", get_compilation_date());
  log_info("ext2fs lib: %s, ntfs lib: %s, ewf lib: %s, libjpeg: %s\n",
      td_ext2fs_version(), td_ntfs_version(), td_ewf_version(), td_jpeg_version());

  QPhotorec *p = new QPhotorec();
  p->showMaximized();
  p->show();
  int ret=a.exec();
  delete p;
  log_close();
  return ret;
}
