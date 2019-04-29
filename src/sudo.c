/*

    File: sudo.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef SUDO_BIN
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* execv */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <errno.h>
#include "types.h"
#include "common.h"
#include "sudo.h"
#include "log.h"

void run_sudo(const int argc, char **argv, const int create_log)
{
  char **argv2;
  if(argc==1)
  {
    argv2 = (char **)MALLOC(sizeof(char *) * 4);
    argv2[0] = strdup(SUDO_BIN);
    argv2[1] = argv[0];
    argv2[2] = strdup(create_log==TD_LOG_NONE?"/nolog":"/debug");
    argv2[3] = NULL;
  }
  else
  {
    int i;
    argv2 = (char **)MALLOC(sizeof(char *) * (argc + 2));
    argv2[0]=strdup(SUDO_BIN);
    for (i=0; i <  argc; i++)
      argv2[i+1] = argv[i];
    argv2[i+1]=NULL;
  }
  printf("sudo may ask your user password, it doesn't ask for the root password.\n");
  printf("Usually there is no echo or '*' displayed when you type your password.\n");
  printf("\n");
  fflush(stdout);
  if(execv(argv2[0], argv2)<0)
  {
    printf("%s failed: %s\n", SUDO_BIN, strerror(errno));
    printf("Press Enter key to quit.\n");
    (void)getchar();
  }
  free(argv2[0]);
  free(argv2);
}
#endif
