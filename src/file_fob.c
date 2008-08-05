/*

    File: file_fob.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "memmem.h"

static void register_header_check_fob(file_stat_t *file_stat);
static int header_check_fob(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_fob= {
  .extension="fob",
  .description="Microsoft Dynamics NAV (MS Navision)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_fob
};

static const unsigned char sign_navnl[5]	= {'N','A','V','N','L'};
static const unsigned char sign_navw[4]		= {'N','A','V','W'};
static const unsigned char magic_codeunit[9]	= {'C','o','d','e','u','n','i','t',' '};
static const unsigned char magic_dataport[9]	= {'D','a','t','a','p','o','r','t',' '};
static const unsigned char magic_form[5]	= {'F','o','r','m',' '};
static const unsigned char magic_menusuite[10]	= {'M','e','n','u','S','u','i','t','e',' '};
static const unsigned char magic_report[7]	= {'R','e','p','o','r','t',' '};
static const unsigned char magic_table[6]	= {'T','a','b','l','e',' '};
static const unsigned char magic_xmlport[8]	= {'X','M','L','p','o','r','t',' '};

static void register_header_check_fob(file_stat_t *file_stat)
{
  register_header_check(0, magic_codeunit,  sizeof(magic_codeunit), 	&header_check_fob, file_stat);
  register_header_check(0, magic_dataport,  sizeof(magic_dataport), 	&header_check_fob, file_stat);
  register_header_check(0, magic_form,      sizeof(magic_form), 	&header_check_fob, file_stat);
  register_header_check(0, magic_menusuite, sizeof(magic_menusuite), 	&header_check_fob, file_stat);
  register_header_check(0, magic_report,    sizeof(magic_report), 	&header_check_fob, file_stat);
  register_header_check(0, magic_table,     sizeof(magic_table), 	&header_check_fob, file_stat);
  register_header_check(0, magic_xmlport,   sizeof(magic_xmlport), 	&header_check_fob, file_stat);
}

static int header_check_fob(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if((memcmp(buffer, magic_codeunit, sizeof(magic_codeunit))==0 ||
      memcmp(buffer, magic_dataport, sizeof(magic_dataport))==0 ||
      memcmp(buffer, magic_form, sizeof(magic_form))==0 ||
      memcmp(buffer, magic_menusuite, sizeof(magic_menusuite))==0 ||
      memcmp(buffer, magic_report, sizeof(magic_report))==0 ||
      memcmp(buffer, magic_table, sizeof(magic_table))==0 ||
      memcmp(buffer, magic_xmlport, sizeof(magic_xmlport))==0) &&
      (td_memmem(buffer, buffer_size, sign_navnl, sizeof(sign_navnl))!=NULL ||
       td_memmem(buffer, buffer_size, sign_navw, sizeof(sign_navw))!=NULL))
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_fob.extension;
    return 1;
  }
  return 0;
}
