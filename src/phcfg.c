/*

    File: phcfg.c

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* getuid */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "log.h"
#include "phcfg.h"

void reset_array_file_enable(file_enable_t *files_enable)
{
  file_enable_t *file_enable;
  for(file_enable=files_enable;file_enable->file_hint!=NULL;file_enable++)
    file_enable->enable=file_enable->file_hint->enable_by_default;
}

/*
   PhotoRec should try to load the configuration from
   - $HOME/.photorec.cfg
   - $SBIN/photorec.cfg

   PhotoRec stores the configuration in
   - $HOME/.photorec.cfg
   - DOS: $SBIN/photorec.cfg
*/

#define WIN_PHOTOREC_CFG "\\photorec.cfg"
#define DOT_PHOTOREC_CFG "/.photorec.cfg"
#define PHOTOREC_CFG "photorec.cfg"

static FILE *file_options_save_aux(void)
{
  char *filename=NULL;
#if defined(__CYGWIN__) || defined(__MINGW32__)
  {
    char *path;
    path = getenv("USERPROFILE");
    if (path == NULL)
      path = getenv("HOMEPATH");
    if(path!=NULL)
    {
      filename=(char*)MALLOC(strlen(path)+strlen(WIN_PHOTOREC_CFG)+1);
      strcpy(filename, path);
      strcat(filename, WIN_PHOTOREC_CFG);
    }
  }
#endif
#if !defined(DJGPP) && !defined(DISABLED_FOR_FRAMAC)
  if(filename==NULL)
  {
    char *home;
    home = getenv("HOME");
    if (home != NULL)
    {
      filename=(char*)MALLOC(strlen(home)+strlen(DOT_PHOTOREC_CFG)+1);
      strcpy(filename, home);
      strcat(filename, DOT_PHOTOREC_CFG);
    }
  }
  if(filename!=NULL)
  {
    FILE *handle=fopen(filename,"wb");
    if(handle)
    {
      log_info("Create file %s\n", filename);
      free(filename);
      return handle;
    }
    log_error("Can't create file %s: %s\n", filename, strerror(errno));
    free(filename);
    filename=NULL;
  }
#endif
  {
    FILE *handle=fopen(PHOTOREC_CFG,"wb");
    if(handle)
    {
      log_info("Create file %s\n", PHOTOREC_CFG);
      return handle;
    }
    log_error("Can't create file %s: %s\n", PHOTOREC_CFG, strerror(errno));
  }
  return NULL;
}

static FILE *file_options_load_aux(void)
{
#if defined(__CYGWIN__) || defined(__MINGW32__)
  {
    char *path;
    path = getenv("USERPROFILE");
    if (path == NULL)
      path = getenv("HOMEPATH");
    if(path!=NULL)
    {
      FILE*handle;
      char *filename=NULL;
      filename=(char*)MALLOC(strlen(path)+strlen(WIN_PHOTOREC_CFG)+1);
      strcpy(filename, path);
      strcat(filename, WIN_PHOTOREC_CFG);
      handle=fopen(filename,"rb");
      if(handle!=NULL)
      {
	log_info("Load parameters from %s\n", filename);
	free(filename);
	return handle;
      }
      free(filename);
    }
  }
#endif
#if !defined(DJGPP) && !defined(DISABLED_FOR_FRAMAC)
  {
    char *home;
    home = getenv("HOME");
    if (home != NULL)
    {
      FILE*handle;
      char *filename=(char*)MALLOC(strlen(home)+strlen(DOT_PHOTOREC_CFG)+1);
      strcpy(filename, home);
      strcat(filename, DOT_PHOTOREC_CFG);
      handle=fopen(filename,"rb");
      if(handle!=NULL)
      {
	log_info("Load parameters from %s\n", filename);
	free(filename);
	return handle;
      }
      free(filename);
    }
  }
#endif
  {
    FILE *handle=fopen(PHOTOREC_CFG,"rb");
    if(handle!=NULL)
    {
      log_info("Load parameters from %s\n", PHOTOREC_CFG);
      return handle;
    }
  }
  return NULL;
}

int file_options_save(const file_enable_t *files_enable)
{
  FILE *handle;
  const file_enable_t *file_enable;
  handle=file_options_save_aux();
  if(handle==NULL)
    return -1;
  /*@
    @ loop invariant \valid_read(files_enable);
    @*/
  for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
  {
    /*@ assert \valid_read(file_enable); */
    if(file_enable->file_hint->extension!=NULL)
    {
      if(file_enable->enable==0)
	fprintf(handle, "%s,disable\n", file_enable->file_hint->extension);
      else
	fprintf(handle, "%s,enable\n", file_enable->file_hint->extension);
    }
  }
  fclose(handle);
  return 0;
}

int file_options_load(file_enable_t *files_enable)
{
  FILE *handle;
  char buffer[512];
  handle=file_options_load_aux();
  if(handle==NULL)
    return -1;
// TODO parse the file
  while(fgets(buffer, sizeof(buffer)-1, handle)!=NULL)
  {
    const char *extension=&buffer[0];
    char *extension_status;
#ifdef __FRAMAC__
  Frama_C_make_unknown(buffer, sizeof(buffer)-1);
#endif
    buffer[sizeof(buffer)-1]='\0';
    extension_status=strchr(buffer,',');
    if(extension_status!=NULL)
    {
      file_enable_t *file_enable;
      const unsigned int cmd_length=extension_status-extension;
      *extension_status='\0';
      extension_status++;
#ifdef DEBUG_PHCFG
      log_debug("extension=%s, extension_status=%s", extension, extension_status);
#endif
      for(file_enable=&files_enable[0];file_enable->file_hint!=NULL;file_enable++)
      {
	if(file_enable->file_hint->extension!=NULL &&
	    strlen(file_enable->file_hint->extension)==cmd_length &&
	    memcmp(file_enable->file_hint->extension,extension,cmd_length)==0)
	{
	  file_enable->enable=(strncmp(extension_status, "enable",6)==0);
	}
      }
    }
  }
  fclose(handle);
  return 0;
}

