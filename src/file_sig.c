/*

    File: file_sig.c

    Copyright (C) 2010 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

static void register_header_check_sig(file_stat_t *file_stat);
static int header_check_sig(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_sig= {
  .extension="custom",
  .description="Own custom signatures",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_sig
};

#define WIN_PHOTOREC_SIG "\\photorec.sig"
#define DOT_PHOTOREC_SIG "/.photorec.sig"
#define PHOTOREC_SIG "photorec.sig"

typedef struct signature_s signature_t;
struct signature_s
{
  const char *extension;
  unsigned char *sig;
  unsigned int sig_size;
  unsigned int offset;
  signature_t *next;
};

static signature_t *signatures=NULL;
static void signature_insert(const char *extension, unsigned int offset, unsigned char *sig, unsigned int sig_size)
{
  /* FIXME: small memory leak */
  signature_t *newsig=(signature_t*)MALLOC(sizeof(*newsig));
  newsig->extension=extension;
  newsig->sig=sig;
  newsig->sig_size=sig_size;
  newsig->offset=offset;
  newsig->next=signatures;
  signatures=newsig;
}

static int header_check_sig(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  signature_t *sig;
  for(sig=signatures; sig!=NULL; sig=sig->next)
  {
    if(memcmp(&buffer[sig->offset], sig->sig, sig->sig_size)==0)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=sig->extension;
      return 1;
    }
  }
  return 0;
}

static FILE *open_signature_file(void)
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
      filename=(char*)MALLOC(strlen(path)+strlen(WIN_PHOTOREC_SIG)+1);
      strcpy(filename, path);
      strcat(filename, WIN_PHOTOREC_SIG);
      handle=fopen(filename,"rb");
      if(handle!=NULL)
      {
	log_info("Open signature file %s\n", filename);
	free(filename);
	return handle;
      }
      free(filename);
    }
  }
#endif
#ifndef DJGPP
  {
    const char *home = getenv("HOME");
    if (home != NULL)
    {
      FILE*handle;
      char *filename=(char*)MALLOC(strlen(home)+strlen(DOT_PHOTOREC_SIG)+1);
      strcpy(filename, home);
      strcat(filename, DOT_PHOTOREC_SIG);
      handle=fopen(filename,"rb");
      if(handle!=NULL)
      {
	log_info("Open signature file %s\n", filename);
	free(filename);
	return handle;
      }
      free(filename);
    }
  }
#endif
  {
    FILE *handle=fopen(PHOTOREC_SIG,"rb");
    if(handle!=NULL)
    {
      log_info("Open signature file %s\n", PHOTOREC_SIG);
      return handle;
    }
  }
  return NULL;
}

static char *str_uint(char *src, unsigned int *resptr)
{
  unsigned int res=0;
  if(*src=='0' && (*(src+1)=='x' || *(src+1)=='X'))
  {
    for(src+=2;;src++)
    {
      if(*src>='0' && *src<='9')
	res=res*16+(*src)-'0';
      else if(*src>='A' && *src<='F')
	res=res*16+(*src)-'A'+10;
      else if(*src>='a' && *src<='f')
	res=res*16+(*src)-'a'+10;
      else
      {
	*resptr=res;
	return src;
      }
    }
  }
  else
  {
    for(;*src>='0' && *src<='9';src++)
      res=res*10+(*src)-'0';
    *resptr=res;
    return src;
  }

}

static char *parse_signature_file(file_stat_t *file_stat, char *pos)
{
  while(*pos!='\0')
  {
    /* skip comments */
    while(*pos=='#')
    {
      while(*pos!='\0' && *pos!='\n')
	pos++;
      if(*pos=='\0')
	return pos;
      pos++;
    }
    /* each line is composed of "extension offset signature" */
    {
      char *extension;
      unsigned int offset=0;
      unsigned char *tmp=NULL;
      unsigned int signature_max_size=512;
      unsigned int signature_size=0;
      {
	const char *extension_start=pos;
	while(*pos!='\0' && !isspace(*pos))
	  pos++;
	if(*pos=='\0')
	  return pos;
	*pos='\0';
	extension=strdup(extension_start);
	pos++;
      }
      /* skip space */
      while(isspace(*pos))
	pos++;
      /* read offset */
      pos=str_uint(pos, &offset);
      /* read signature */
      tmp=(unsigned char *)MALLOC(signature_max_size);
      while(*pos!='\n' && *pos!='\0')
      {
	if(signature_size==signature_max_size)
	{
	  unsigned char *tmp_old=tmp;
	  signature_max_size*=2;
	  tmp=(unsigned char *)realloc(tmp, signature_max_size);
	  if(tmp==NULL)
	  {
	    free(extension);
	    free(tmp_old);
	    return pos;
	  }
	}
	if(isspace(*pos) || *pos=='\r' || *pos==',')
	  pos++;
	else if(*pos== '\'')
	{
	  pos++;
	  if(*pos=='\0')
	  {
	    free(extension);
	    free(tmp);
	    return pos;
	  }
	  else if(*pos=='\\')
	  {
	    pos++;
	    if(*pos=='\0')
	    {
	      free(extension);
	    free(tmp);
	      return pos;
	    }
	    else if(*pos=='b')
	      tmp[signature_size++]='\b';
	    else if(*pos=='n')
	      tmp[signature_size++]='\n';
	    else if(*pos=='t')
	      tmp[signature_size++]='\t';
	    else if(*pos=='r')
	      tmp[signature_size++]='\r';
	    else if(*pos=='0')
	      tmp[signature_size++]='\0';
	    else
	      tmp[signature_size++]=*pos;
	    pos++;
	  }
	  else
	  {
	    tmp[signature_size++]=*pos;
	    pos++;
	  }
	  if(*pos!='\'')
	  {
	    free(extension);
	    free(tmp);
	    return pos;
	  }
	  pos++;
	}
	else if(*pos=='"')
	{
	  pos++;
	  for(; *pos!='"' && *pos!='\0'; pos++)
	  {
	    if(signature_size==signature_max_size)
	    {
	      unsigned char *tmp_old=tmp;
	      signature_max_size*=2;
	      tmp=(unsigned char *)realloc(tmp, signature_max_size);
	      if(tmp==NULL)
	      {
		free(extension);
		free(tmp_old);
		return pos;
	      }
	    }
	    if(*pos=='\\')
	    {
	      pos++;
	      if(*pos=='\0')
	      {
		free(extension);
		free(tmp);
		return pos;
	      }
	      else if(*pos=='b')
		tmp[signature_size++]='\b';
	      else if(*pos=='n')
		tmp[signature_size++]='\n';
	      else if(*pos=='r')
		tmp[signature_size++]='\r';
	      else if(*pos=='t')
		tmp[signature_size++]='\t';
	      else if(*pos=='0')
		tmp[signature_size++]='\0';
	      else
		tmp[signature_size++]=*pos;
	    }
	    else
	      tmp[signature_size++]=*pos;;
	  }
	  if(*pos!='"')
	  {
	    free(extension);
	    free(tmp);
	    return pos;
	  }
	  pos++;
	}
	else if(*pos=='0' && (*(pos+1)=='x' || *(pos+1)=='X'))
	{
	  pos+=2;
	  while(isxdigit(*pos) && isxdigit(*(pos+1)))
	  {
	    unsigned int val=(*pos);
	    if(*pos>='0' && *pos<='9')
	      val-='0';
	    else if(*pos>='A' && *pos<='F')
	      val=val-'A'+10;
	    else if(*pos>='a' && *pos<='f')
	      val=val-'a'+10;
	    pos++;
	    val*=16;
	    val+=(*pos);
	    if(*pos>='0' && *pos<='9')
	      val-='0';
	    else if(*pos>='A' && *pos<='F')
	      val=val-'A'+10;
	    else if(*pos>='a' && *pos<='f')
	      val=val-'a'+10;
	    pos++;
	    tmp[signature_size++]=val;
	  }
	}
	else
	{
	  free(extension);
	  free(tmp);
	  return pos;
	}
      }
      if(*pos=='\n')
	pos++;
      if(signature_size>0)
      {
	/* FIXME: Small memory leak */
	unsigned char *signature=(unsigned char *)MALLOC(signature_size);
	log_info("register a signature for %s\n", extension);
	memcpy(signature, tmp, signature_size);
	register_header_check(offset, signature, signature_size, &header_check_sig, file_stat);
	signature_insert(extension, offset, signature, signature_size);
      }
      else
      {
	free(extension);
      }
      free(tmp);
    }
  }
  return pos;
}

static void register_header_check_sig(file_stat_t *file_stat)
{
  char *pos;
  char *buffer;
  size_t buffer_size;
  struct stat stat_rec;
  FILE *handle;
  handle=open_signature_file();
  if(!handle)
    return;
  if(fstat(fileno(handle), &stat_rec)<0 || stat_rec.st_size>100*1024*1024)
  {
    fclose(handle);
    return;
  }
  buffer_size=stat_rec.st_size;
  buffer=(char *)MALLOC(buffer_size+1);
  if(fread(buffer,1,buffer_size,handle)!=buffer_size)
  {
    fclose(handle);
    free(buffer);
    return;
  }
  fclose(handle);
  buffer[buffer_size]='\0';
  pos=buffer;
  pos=parse_signature_file(file_stat, pos);
  if(*pos!='\0')
  {
    log_warning("Can't parse signature: %s\n", pos);
  }
  free(buffer);
}


