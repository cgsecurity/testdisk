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
#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_sig)
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
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

static int signature_cmp(const struct td_list_head *a, const struct td_list_head *b);

#ifndef __FRAMAC__
#include "list_add_sorted.h"
#else
/*@
  @ requires \valid(newe);
  @ requires \valid(head);
  @ requires separation: \separated(newe, head);
  @ requires list_separated(head->prev, newe);
  @ requires list_separated(head, newe);
  @ requires finite(head->prev);
  @ requires finite(head);
  @*/
static inline void td_list_add_sorted_sig(struct td_list_head *newe, struct td_list_head *head)
{
  struct td_list_head *pos;
  /*@
    @ loop invariant \valid(pos);
    @ loop invariant \valid(pos->prev);
    @ loop invariant \valid(pos->next);
    @ loop invariant pos == head || \separated(pos, head);
    @ loop assigns pos;
    @*/
  td_list_for_each(pos, head)
  {
    /*@ assert \valid_read(newe); */
    /*@ assert \valid_read(pos); */
    if(signature_cmp(newe,pos)<0)
      break;
  }
  if(pos != head)
  {
      __td_list_add(newe, pos->prev, pos);
  }
  else
  {
    /*@ assert finite(head->prev); */
    /*@ assert finite(head); */
    /*@ assert list_separated(head->prev, newe); */
    /*@ assert list_separated(head, newe); */
    td_list_add_tail(newe, head);
  }
}
#endif

#if 0
/*@ requires valid_string_s: valid_read_string(s);
  @ ensures  valid_string(\result);
  @*/
static char *td_strdup(const char *s)
{
  size_t l = strlen(s) + 1;
  char *p = (char *)MALLOC(l);
  /*@ assert valid_read_string(s); */
  memcpy(p, s, l);
  p[l-1]='\0';
  /*@ assert valid_read_string(p); */
  return p;
}
#endif

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_sig(file_stat_t *file_stat);

const file_hint_t file_hint_sig= {
  .extension="custom",
  .description="Own custom signatures",
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
  struct td_list_head list;
  const char *extension;
  const char *sig;
  unsigned int sig_size;
  unsigned int offset;
};

/*@
   predicate valid_signature(signature_t *sig) = (\valid_read(sig) &&
     valid_read_string(sig->extension) &&
     \initialized(&sig->offset) &&
     \initialized(&sig->sig_size) &&
     sig->offset <= PHOTOREC_MAX_SIG_OFFSET &&
     0 < sig->sig_size <= PHOTOREC_MAX_SIG_SIZE &&
     sig->offset + sig->sig_size <= PHOTOREC_MAX_SIG_OFFSET &&
     \valid_read((const char *)sig->sig+(0..sig->sig_size-1))
   );
   @*/

static signature_t signatures={
  .list = TD_LIST_HEAD_INIT(signatures.list)
};

/*@
  @ assigns \nothing;
  @*/
static int signature_cmp(const struct td_list_head *a, const struct td_list_head *b)
{
  const signature_t *sig_a=td_list_entry_const(a, const signature_t, list);
  const signature_t *sig_b=td_list_entry_const(b, const signature_t, list);
  int res;
  /*@ assert \valid_read(sig_a); */
  /*@ assert \valid_read(sig_b); */
  /*@ assert valid_signature(sig_a); */
  /*@ assert valid_signature(sig_b); */
  if(sig_a->sig_size==0 && sig_b->sig_size!=0)
    return -1;
  if(sig_a->sig_size!=0 && sig_b->sig_size==0)
    return 1;
  /*@ assert 0 <= sig_a->offset <= PHOTOREC_MAX_SIG_OFFSET; */
  /*@ assert 0 <= sig_b->offset <= PHOTOREC_MAX_SIG_OFFSET; */
  res=(int)sig_a->offset - (int)sig_b->offset;
  if(res!=0)
    return res;
  if(sig_a->sig_size<=sig_b->sig_size)
  {
    res=memcmp(sig_a->sig,sig_b->sig, sig_a->sig_size);
    if(res!=0)
      return res;
    return 1;
  }
  else
  {
    res=memcmp(sig_a->sig,sig_b->sig, sig_b->sig_size);
    if(res!=0)
      return res;
    return -1;
  }
}

/*@
  @ requires offset <= PHOTOREC_MAX_SIG_OFFSET;
  @ requires 0 < sig_size <= PHOTOREC_MAX_SIG_SIZE;
  @ requires offset + sig_size <= PHOTOREC_MAX_SIG_OFFSET;
  @ requires \valid_read((const char *)sig + (0 .. sig_size-1));
  @ requires valid_read_string(ext);
  @*/
static void signature_insert(const char *ext, unsigned int offset, const void*sig, unsigned int sig_size)
{
  /* FIXME: memory leak for newsig */
  signature_t *newsig;
  /*@ assert \valid_read((const char *)sig+(0..sig_size-1)); */
  /*@ assert valid_read_string(ext); */
  newsig=(signature_t*)MALLOC(sizeof(*newsig));
  /*@ assert \valid(newsig); */
  newsig->extension=ext;
  newsig->sig=(const char *)sig;
  newsig->sig_size=sig_size;
  newsig->offset=offset;
  /*@ assert newsig->sig_size == sig_size; */

  /*@ assert \valid_read(newsig); */
  /*@ assert valid_read_string(newsig->extension); */
  /*@ assert \initialized(&newsig->offset); */
  /*@ assert \initialized(&newsig->sig_size); */
  /*@ assert newsig->offset <= PHOTOREC_MAX_SIG_OFFSET; */
  /*@ assert 0 < newsig->sig_size <= PHOTOREC_MAX_SIG_SIZE; */
  /*@ assert newsig->offset + newsig->sig_size <= PHOTOREC_MAX_SIG_OFFSET; */
  /*@ assert \valid_read((const char *)sig+(0..sig_size-1)); */
  /*@ assert \valid_read((const char *)sig+(0..newsig->sig_size-1)); */
  /*@ assert (const char *)newsig->sig ==(const char *)sig; */
  /*@ assert \valid_read((const char *)newsig->sig+(0..0)); */
  /*@ assert \valid_read((const char *)newsig->sig+(0..newsig->sig_size-1)); */

  /*@ assert valid_signature(newsig); */
#ifdef __FRAMAC__
  td_list_add_sorted_sig(&newsig->list, &signatures.list);
#else
  td_list_add_sorted(&newsig->list, &signatures.list, signature_cmp);
#endif
}

/*@
  @ requires separation: \separated(&file_hint_sig, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns *file_recovery_new;
  @*/
static int header_check_sig(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  struct td_list_head *pos;
  /*@
    @ loop invariant \valid(pos);
    @ loop assigns pos;
    @*/
  td_list_for_each(pos, &signatures.list)
  {
    const signature_t *sig = td_list_entry(pos, signature_t, list);
    /*@ assert \valid_read(sig); */
    /*@ assert sig->offset + sig->sig_size <= buffer_size; */
    /*@ assert valid_read_string(sig->extension); */
    /*@ assert valid_signature(sig); */
    if(memcmp(&buffer[sig->offset], sig->sig, sig->sig_size)==0)
    {
      reset_file_recovery(file_recovery_new);
      file_recovery_new->extension=sig->extension;
      /*@ assert valid_file_recovery(file_recovery_new); */
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
      char *filename;
      size_t len_home;
      const size_t len_sig=strlen(DOT_PHOTOREC_SIG);
      size_t fn_size=len_sig;
#ifndef DISABLED_FOR_FRAMAC
      len_home=strlen(home);
      fn_size+=len_home;
#endif
      filename=(char*)MALLOC(fn_size + 1);
#ifndef DISABLED_FOR_FRAMAC
      strcpy(filename, home);
#else
      filename[0]='\0';
#endif
      strcat(filename, DOT_PHOTOREC_SIG);
      handle=fopen(filename,"rb");
      if(handle!=NULL)
      {
#ifndef DISABLED_FOR_FRAMAC
	log_info("Open signature file %s\n", filename);
#endif
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
#ifndef DISABLED_FOR_FRAMAC
      log_info("Open signature file %s\n", PHOTOREC_SIG);
#endif
      return handle;
    }
  }
  return NULL;
}

/*@
  @ requires \valid(ptr);
  @ requires valid_read_string(*ptr);
  @ ensures  \initialized(ptr);
  @ ensures  valid_read_string(*ptr);
  @ assigns  *ptr;
  @*/
static unsigned int str_uint_hex(char **ptr)
{
  char *src=*ptr;
  unsigned int res=0;
  /*@
    @ loop invariant valid_read_string(src);
    @ loop invariant res < 0x10000000;
    @ loop assigns src, res;
    @*/
  for(;;src++)
  {
    const char c=*src;
    if(c>='0' && c<='9')
      res=res*16+(c-'0');
    else if(c>='A' && c<='F')
      res=res*16+(c-'A'+10);
    else if(c>='a' && c<='f')
      res=res*16+(c-'a'+10);
    else
    {
      *ptr=src;
      return res;
    }
    if(res >= 0x10000000)
    {
      *ptr=src;
      return res;
    }
  }
}

/*@
  @ requires \valid(ptr);
  @ requires valid_read_string(*ptr);
  @ ensures  \initialized(ptr);
  @ ensures  valid_read_string(*ptr);
  @ assigns  *ptr;
  @*/
static unsigned int str_uint_dec(char **ptr)
{
  char *src=*ptr;
  unsigned int res=0;
  /*@
    @ loop invariant valid_read_string(src);
    @ loop invariant res < 0x10000000;
    @ loop assigns src, res;
    @*/
  for(;*src>='0' && *src<='9';src++)
  {
    res=res*10+(*src)-'0';
    if(res >= 0x10000000)
    {
      *ptr=src;
      return res;
    }
  }
  *ptr=src;
  return res;
}

/*@
  @ requires \valid(ptr);
  @ requires valid_read_string(*ptr);
  @ ensures  \initialized(ptr);
  @ ensures  valid_read_string(*ptr);
  @ assigns  *ptr;
  @*/
static unsigned int str_uint(char **ptr)
{
  const char *src=*ptr;
  if(*src=='0' && (*(src+1)=='x' || *(src+1)=='X'))
  {
    (*ptr)+=2;
    return str_uint_hex(ptr);
  }
  return str_uint_dec(ptr);
}

/*@
  @ terminates \true;
  @ assigns  \nothing;
  @ */
static unsigned char escaped_char(const unsigned char c)
{
  switch(c)
  {
    case 'b':
      return '\b';
    case 'n':
      return '\n';
    case 't':
      return '\t';
    case 'r':
      return '\r';
    case '0':
      return '\0';
    default:
      return c;
  }
}

/*@
  @ terminates \true;
  @ ensures 0 <= \result <= 0x10;
  @ assigns \nothing;
  @*/
static unsigned int load_hex1(const unsigned char c)
{
  if(c>='0' && c<='9')
    return c-'0';
  else if(c>='A' && c<='F')
    return c-'A'+10;
  else if(c>='a' && c<='f')
    return c-'a'+10;
  return 0x10;
}

/*@
  @ terminates \true;
  @ ensures 0 <= \result <= 0x100;
  @ assigns \nothing;
  @*/
static unsigned int load_hex2(const unsigned char c1, const unsigned char c2)
{
  unsigned int val1=load_hex1(c1);
  unsigned int val2=load_hex1(c2);
  if(val1 >= 0x10 || val2 >=0x10)
    return 0x100;
  return (val1*16)+val2;
}

/*@
  @ requires \valid(ptr);
  @ requires \valid(*ptr);
  @ requires valid_string(*ptr);
  @ requires \valid(tmp + (0 .. PHOTOREC_MAX_SIG_SIZE-1));
  @ requires \separated(ptr, tmp + (..));
  @ ensures  valid_string(*ptr);
  @ ensures  \initialized(tmp + (0 .. \result-1));
  @ assigns  *ptr, tmp[0 .. PHOTOREC_MAX_SIG_SIZE-1];
  @*/
static unsigned int load_signature(char **ptr, unsigned char *tmp)
{
  unsigned int signature_size=0;
  char *pos=*ptr;
  /*@
    @ loop invariant \valid(*ptr);
    @ loop invariant valid_string(pos);
    @ loop invariant signature_size <= PHOTOREC_MAX_SIG_SIZE;
    @ loop invariant \valid(tmp + (0 .. PHOTOREC_MAX_SIG_SIZE-1));
    @ loop assigns pos, signature_size, tmp[0 .. PHOTOREC_MAX_SIG_SIZE-1];
    @*/
  while(*pos!='\n' && *pos!='\0')
  {
    if(signature_size>=PHOTOREC_MAX_SIG_SIZE)
      return 0;
    /*@ assert signature_size < PHOTOREC_MAX_SIG_SIZE; */
    if(*pos ==' ' || *pos=='\t' || *pos=='\r' || *pos==',')
      pos++;
    else if(*pos== '\'')
    {
      pos++;
      if(*pos=='\0')
	return 0;
      if(*pos=='\\')
      {
	pos++;
	if(*pos=='\0')
	  return 0;
	tmp[signature_size++]=escaped_char(*(unsigned char *)pos);
      }
      else
      {
	tmp[signature_size++]=*(unsigned char *)pos;
      }
      pos++;
      if(*pos!='\'')
	return 0;
      pos++;
    }
    else if(*pos=='"')
    {
      pos++;
      /*@
	@ loop invariant valid_string(pos);
	@ loop invariant signature_size <= PHOTOREC_MAX_SIG_SIZE;
	@ loop assigns pos, signature_size, tmp[0 .. PHOTOREC_MAX_SIG_SIZE-1];
	@*/
      while(*pos!='"')
      {
	if(*pos=='\0')
	  return 0;
	if(signature_size>=PHOTOREC_MAX_SIG_SIZE)
	  return 0;
	if(*pos=='\\')
	{
	  pos++;
	  if(*pos=='\0')
	    return 0;
	  tmp[signature_size++]=escaped_char(*(unsigned char *)pos);
	}
	else
	  tmp[signature_size++]=*(unsigned char *)pos;
	pos++;
      }
      /*@ assert *pos=='"'; */
      pos++;
    }
    else if(*pos=='0' && (*(pos+1)=='x' || *(pos+1)=='X'))
    {
      pos+=2;
      /*@ assert valid_string(pos); */
      /*@
	@ loop invariant valid_string(pos);
	@ loop invariant signature_size <= PHOTOREC_MAX_SIG_SIZE;
	@ loop assigns pos, signature_size, tmp[0 .. PHOTOREC_MAX_SIG_SIZE-1];
	@*/
      while(
#ifdef DISABLED_FOR_FRAMAC
	  *pos!='\0' && *(pos+1)!='\0'
#else
	  isxdigit(*pos) && isxdigit(*(pos+1))
#endif
	  )
      {
	unsigned int val;
	if(signature_size>=PHOTOREC_MAX_SIG_SIZE)
	  return 0;
	/*@ assert valid_string(pos); */
	/*@ assert valid_string(pos+1); */
	val=load_hex2(*(unsigned char *)pos, *(unsigned char *)(pos+1));
	if(val >= 0x100)
	  break;
	pos+=2;
	tmp[signature_size++]=val;
      }
    }
    else
    {
      return 0;
    }
    /*@ assert valid_string(pos); */
  }
  *ptr=pos;
  return signature_size;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @ requires valid_file_stat(file_stat);
  @ requires valid_string(pos);
  @ ensures  valid_string(\result);
  @*/
static char *parse_signature_line(file_stat_t *file_stat, char *pos)
{
  /* each line is composed of "extension sig_offset signature" */
  const char *sig_ext=pos;
  unsigned char *sig_sig=NULL;
  unsigned int sig_offset=0;
  unsigned int sig_size;
  /* Read the extension */
  /*@
    @ loop invariant valid_read_string(sig_ext);
    @ loop invariant valid_string(pos);
    @ loop assigns pos;
    @*/
  while(*pos!=' ' && *pos!='\t')
  {
    if(*pos=='\0' || *pos=='\n' || *pos=='\r')
      return pos;
    pos++;
  }
  *pos='\0';
  pos++;
  /*@ assert valid_string(pos); */
#ifndef DISABLED_FOR_FRAMAC
  log_info("register a signature for %s\n", sig_ext);
#endif
  /* skip spaces */
  /*@
    @ loop invariant valid_string(pos);
    @ loop assigns pos;
    @*/
  while(*pos=='\t' || *pos==' ')
  {
    /*@ assert *pos == '\t' || *pos== ' '; */
    /*@ assert valid_string(pos); */
    pos++;
  }
  sig_offset=str_uint(&pos);
  if(sig_offset > PHOTOREC_MAX_SIG_OFFSET)
  {
    /* Invalid sig_offset */
    return pos;
  }
  /*@ assert sig_offset <= PHOTOREC_MAX_SIG_OFFSET; */
  /* read signature */
  sig_sig=(unsigned char *)MALLOC(PHOTOREC_MAX_SIG_SIZE);
  /*@ assert valid_string(pos); */
  sig_size=load_signature(&pos, sig_sig);
  if(sig_size==0)
  {
    free(sig_sig);
    return pos;
  }
  if(*pos=='\n')
    pos++;
  /*@ assert sig_offset <= PHOTOREC_MAX_SIG_OFFSET; */
  /*@ assert sig_size <= PHOTOREC_MAX_SIG_SIZE; */
  if(sig_size>0 && sig_offset + sig_size <= PHOTOREC_MAX_SIG_OFFSET )
  {
    /* FIXME: memory leak for signature */
    char *signature;
    /*@ assert sig_size > 0; */
    /*@ assert sig_offset + sig_size <= PHOTOREC_MAX_SIG_OFFSET; */
    signature=(char*)MALLOC(sig_size);
    /*@ assert \valid(signature + (0 .. sig_size - 1)); */
    memcpy(signature, sig_sig, sig_size);
    signature_insert(sig_ext, sig_offset, signature, sig_size);
#ifndef DISABLED_FOR_FRAMAC
    register_header_check(sig_offset, signature, sig_size, &header_check_sig, file_stat);
#endif
  }
  free(sig_sig);
  return pos;
}

/*@
  @ requires valid_register_header_check(file_stat);
  @ requires valid_file_stat(file_stat);
  @ requires valid_string(pos);
  @ ensures  valid_string(\result);
  @*/
static char *parse_signature_file(file_stat_t *file_stat, char *pos)
{
#ifndef DISABLED_FOR_FRAMAC
  /*@
    @ loop invariant valid_file_stat(file_stat);
    @ loop invariant valid_string(pos);
    @*/
  while(*pos!='\0')
#endif
  {
    /* skip comments */
    /*@
      @ loop invariant valid_string(pos);
      @ loop assigns pos;
      @*/
    while(*pos=='#')
    {
      /*@
	@ loop invariant valid_string(pos);
	@ loop assigns pos;
	@*/
      while(*pos!='\0' && *pos!='\n')
	pos++;
      if(*pos=='\0')
	return pos;
      pos++;
    }
    /* skip empty lines */
    /*@
      @ loop invariant valid_string(pos);
      @ loop assigns pos;
      @*/
    while(*pos=='\n' || *pos=='\r')
      pos++;
    pos=parse_signature_line(file_stat, pos);
  }
  return pos;
}

static void register_header_check_sig(file_stat_t *file_stat)
{
  char *pos;
  static char *buffer=NULL;
  size_t buffer_size;
  struct stat stat_rec;
  FILE *handle;
//  if(!td_list_empty(&signatures.list))
  if(buffer!=NULL)
    return ;
  handle=open_signature_file();
  if(!handle)
    return;
#ifdef DISABLED_FOR_FRAMAC
  buffer_size=1024*1024;
#else
  if(fstat(fileno(handle), &stat_rec)<0 || stat_rec.st_size>100*1024*1024)
  {
    fclose(handle);
    return;
  }
  buffer_size=stat_rec.st_size;
#endif
  buffer=(char *)MALLOC(buffer_size+1);
  if(fread(buffer,1,buffer_size,handle)!=buffer_size)
  {
    fclose(handle);
    free(buffer);
    return;
  }
  fclose(handle);
#if defined(__FRAMAC__)
  Frama_C_make_unknown(buffer, buffer_size);
#endif
  buffer[buffer_size]='\0';
  pos=buffer;
  pos=parse_signature_file(file_stat, pos);
  if(*pos!='\0')
  {
#ifndef DISABLED_FOR_FRAMAC
    log_warning("Can't parse signature: %s\n", pos);
#endif
  }
//  free(buffer);
}
#endif
