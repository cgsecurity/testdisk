/*

    File: poptions.c

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
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "log.h"
#include "poptions.h"

void interface_options_photorec_cli(struct ph_options *options, char **current_cmd)
{
  if(*current_cmd==NULL)
    return ;
  while(1)
  {
    skip_comma_in_command(current_cmd);
    /* paranoid, longer option first */
    if(check_command(current_cmd,"paranoid_no",11)==0)
    {
      options->paranoid=0;
    }
    else if(check_command(current_cmd,"paranoid_bf",11)==0)
    {
      options->paranoid=2;
    }
    else if(check_command(current_cmd,"paranoid",8)==0)
    {
      options->paranoid=1;
    }
    /* keep_corrupted_file */
    else if(check_command(current_cmd,"keep_corrupted_file_no",22)==0)
    {
      options->keep_corrupted_file=0;
    }
    else if(check_command(current_cmd,"keep_corrupted_file",19)==0)
    {
      options->keep_corrupted_file=1;
    }
    /* mode_ext2 */
    else if(check_command(current_cmd,"mode_ext2",9)==0)
    {
      options->mode_ext2=1;
    }
    /* expert */
    else if(check_command(current_cmd,"expert",6)==0)
    {
      options->expert=1;
    }
    /* lowmem */
    else if(check_command(current_cmd,"lowmem",6)==0)
    {
      options->lowmem=1;
    }
    else
    {
      interface_options_photorec_log(options);
      return ;
    }
  }
}

void interface_options_photorec_log(const struct ph_options *options)
{
  /* write new options to log file */
  log_info("New options :\n Paranoid : %s\n", options->paranoid?"Yes":"No");
  log_info(" Brute force : %s\n", ((options->paranoid)>1?"Yes":"No"));
  log_info(" Keep corrupted files : %s\n ext2/ext3 mode : %s\n Expert mode : %s\n Low memory : %s\n",
      options->keep_corrupted_file?"Yes":"No",
      options->mode_ext2?"Yes":"No",
      options->expert?"Yes":"No",
      options->lowmem?"Yes":"No");
}
