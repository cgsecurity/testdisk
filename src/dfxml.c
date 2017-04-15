/*

    File: xml.c

    Copyright (C) 2011 Simson Garfinkel
    Copyright (C) 2011 Christophe Grenier
  
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

#ifdef ENABLE_DFXML
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
#include <errno.h>
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include "types.h"
#include "common.h"
#include "dir.h"
#include "filegen.h"
#include "photorec.h"
#include "ext2_dir.h"
#include "ewf.h"
#include "file_jpg.h"
#include "file_gz.h"
#include "ntfs_dir.h"
#include "misc.h"
#include "dfxml.h"

static FILE *xml_handle = NULL;
static int xml_stack_depth = 0;
static char *command_line = NULL;

static const char *xml_header = "<?xml version='1.0' encoding='UTF-8'?>\n";
static char xml_dir[2048];
static char xml_fname[2048];			/* what photorec uses elsewhere */


FILE *xml_open(const char *recup_dir, const unsigned int dir_num)
{
  snprintf(xml_dir, sizeof(xml_dir), "%s.%u/", recup_dir,dir_num);
  snprintf(xml_fname, sizeof(xml_fname), "%s.%u/report.xml", recup_dir, dir_num);
  xml_handle = fopen(xml_fname,"w");
  return xml_handle;
}

void xml_set_command_line(const int argc, char **argv)
{
  int i;
  int len=argc;
  if(command_line!=NULL)
    return ;
  /* Capture the command line */
  for(i=0; i<argc; i++)
  {
    len+=strlen(argv[i]);
  }
  command_line = (char *)MALLOC(len);
  command_line[0]='\0';
  for(i=0; i<argc; i++)
  {
    if(i>0)
      strcat(command_line," ");
    strcat(command_line, argv[i]);
  }
}

void xml_clear_command_line(void)
{
  free(command_line);
  command_line=NULL;
}

void xml_close()
{
  if(xml_handle==NULL)
    return;
  fclose(xml_handle);
  xml_handle = NULL;
}

static void xml_spaces(void)
{
  int i;
  if(xml_handle==NULL)
    return;
  for(i = 0; i < xml_stack_depth * 2; i++)
  {
    fputc(' ', xml_handle);
  }
}

static void xml_tagout(const char *tag,const char *attribute)
{
  if(attribute[0]=='\0')
    xml_printf("<%s>", tag);
  else
    xml_printf("<%s %s>", tag, attribute);
}

/**
 * output the closing tag */
static void xml_ctagout(const char *tag)
{
  xml_printf("</%s>", tag);
}

void xml_push(const char *tag,const char *attribute)
{
  if(xml_handle==NULL)
    return;
  xml_tagout(tag, attribute);
  fputc('\n', xml_handle);
  xml_stack_depth++;
}

void xml_pop(const char *tag)
{
  if(xml_handle==NULL)
    return;
  xml_stack_depth--;
  xml_ctagout(tag);
  fputc('\n', xml_handle);
}

void xml_printf(const char *fmt,...)
{
  va_list ap;
  if(xml_handle==NULL)
    return;
  va_start(ap, fmt);
  xml_spaces();
  vfprintf(xml_handle, fmt, ap);
  va_end(ap);
}

void xml_out2s(const char *tag, const char *value)
{
  if(xml_handle==NULL)
    return;
  xml_spaces();
  fprintf(xml_handle, "<%s>", tag);
  for(;*value!='\0'; value++)
  {
    if(*value=='&')
      fputs("&amp;", xml_handle);
    else
      putc(*value, xml_handle);
  }
  fprintf(xml_handle, "</%s>\n", tag);
}

void xml_out2i(const char *tag, const uint64_t value)
{
  xml_printf("<%s>%llu</%s>\n", tag, (long long unsigned)value, tag);
}

void xml_add_DFXML_creator(const char *package, const char *version)
{
  xml_push("creator","");
  xml_out2s("package", package);
  xml_out2s("version", version);
  xml_push("build_environment","");
  xml_printf("<compiler>%s</compiler>\n", get_compiler());
#ifdef RECORD_COMPILATION_DATE
  xml_out2s("compilation_date", get_compilation_date());
#endif
  xml_printf("<library name='libext2fs' version='%s'/>\n", td_ext2fs_version());
  xml_printf("<library name='libewf' version='%s'/>\n", td_ewf_version());
  xml_printf("<library name='libjpeg' version='%s'/>\n", td_jpeg_version());
  xml_printf("<library name='libntfs' version='%s'/>\n", td_ntfs_version());
  xml_printf("<library name='zlib' version='%s'/>\n", td_zlib_version());
  xml_pop("build_environment");
  xml_push("execution_environment","");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  xml_out2s("os_sysname", "Windows");
  xml_out2s("os_release", get_os());
  xml_out2s("os_version", get_os());
#ifdef HAVE_SYS_UTSNAME_H
  {
    struct utsname name;
    if(uname(&name)==0)
    {
      xml_out2s("host", name.nodename);
      xml_out2s("arch", name.machine);
    }
  }
#endif
#elif defined(HAVE_SYS_UTSNAME_H)
  {
    struct utsname name;
    if(uname(&name)==0)
    {
      xml_out2s("os_sysname", name.sysname);
      xml_out2s("os_release", name.release);
      xml_out2s("os_version", name.version);
      xml_out2s("host", name.nodename);
      xml_out2s("arch", name.machine);
    }
  }
#elif defined(UNAMES)
  xml_out2s("os_sysname", UNAMES);
#endif
#ifdef HAVE_GETEUID
  xml_out2i("uid", geteuid());
#if 0
#ifdef HAVE_GETPWUID
  {
    struct passwd *tmp=getpwuid(getuid());
    if(tmp != NULL)
    {
      xml_out2s("username", tmp->pw_name);
    }
  }
#endif
#endif
#endif
  {
    char outstr[200];
    const time_t t = time(NULL);
    struct tm tm_tmp;
    const struct tm *tmp = localtime_r(&t,&tm_tmp);
    if (tmp != NULL &&
	strftime(outstr, sizeof(outstr), "%Y-%m-%dT%H:%M:%S%z", tmp) != 0)
    {
      xml_out2s("start_time", outstr);
    }
  }
  xml_pop("execution_environment");
  xml_pop("creator");
}

void xml_setup(disk_t *disk, const partition_t *partition)
{
  if(xml_handle==NULL)
    return;
  fputs(xml_header, xml_handle);
  xml_push("dfxml", "xmloutputversion='1.0'");
  xml_push("metadata",
      "\n  xmlns='http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML' "
      "\n  xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
      "\n  xmlns:dc='http://purl.org/dc/elements/1.1/'" );
  xml_out2s("dc:type","Carve Report");
  xml_pop("metadata");
  xml_add_DFXML_creator("PhotoRec", VERSION);
  xml_push("source", "");
  xml_out2s("image_filename", disk->device);
  xml_out2i("sectorsize", disk->sector_size);
  if(disk->model != NULL)
    xml_out2s("device_model", disk->model);
  xml_out2i("image_size", disk->disk_real_size);
  xml_push("volume", "");
  xml_push("byte_runs", "");
  xml_printf( "<byte_run offset='0' img_offset='%llu' len='%llu'/>\n",
      (long long unsigned)partition->part_offset,
      (long long unsigned)partition->part_size);
  xml_pop("byte_runs");
  if(partition->blocksize > 0)
    xml_out2i("block_size", partition->blocksize);
  xml_pop("volume");
  xml_pop("source");
  xml_push("configuration", "");
  xml_pop("configuration");			// configuration
}

void xml_shutdown(void)
{
  if(xml_handle==NULL)
    return;
  xml_pop("dfxml");
  xml_close();
}

/* If fname begins with xml_dir then just return the relative part */
static const char *relative_name(const char *fname)
{
  if(fname==NULL)
    return "";
  if(strncmp(fname, xml_dir, strlen(xml_dir))==0)
    return fname+strlen(xml_dir);
  return fname;
}

/* See filegen.h for the definition of file_recovery_struct */
void xml_log_file_recovered(const file_recovery_t *file_recovery)
{
  struct td_list_head *tmp;
  uint64_t file_size=0;
  if(xml_handle==NULL)
    return;
  if(file_recovery==NULL || file_recovery->filename[0]=='\0')
    return;
  xml_push("fileobject", "");
  xml_out2s("filename", relative_name(file_recovery->filename));
  xml_out2i("filesize", file_recovery->file_size);
  xml_push("byte_runs", "");
  td_list_for_each(tmp, &file_recovery->location.list)
  {
    const alloc_list_t *element=td_list_entry_const(tmp, const alloc_list_t, list);
    if(element->data>0)
    {
      const uint64_t len=element->end - element->start + 1;
      xml_printf( "<byte_run offset='%llu' img_offset='%llu' len='%llu'/>\n",
	  (long long unsigned)file_size,
	  (long long unsigned)element->start,
	  (long long unsigned)len);
      file_size+=len;
    }
  }
  xml_pop("byte_runs");
  xml_pop("fileobject");
  fflush(xml_handle);
}
#endif
