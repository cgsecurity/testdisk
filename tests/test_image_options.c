/* Synthetic option/session tests: no physical device or recovered user files. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"
#include "poptions.h"
#include "sessionp.h"
#include "log.h"

/* Options are tested with the actual common.c parser and sessionp.c serializer.
 * Logging is the only substituted dependency. */
int log_redirect(const unsigned int level, const char *format, ...)
{
  (void)level;
  (void)format;
  return 0;
}

int log_close(void)
{
  return 0;
}

static void test_numbers(void)
{
  static const char *invalid[]={"", "-1", "+1", " 1", "1 ", "1.0", "2kb",
    "18446744073709551616", "999999999999999999999999", "1,2", "0x10"};
  size_t i;
  uint64_t value=42;
  assert(photorec_parse_image_minimum("0", 1, &value)==0 && value==0);
  assert(photorec_parse_image_minimum("000123", 6, &value)==0 && value==123);
  assert(photorec_parse_image_minimum("18446744073709551615", 20, &value)==0);
  assert(value==UINT64_MAX);
  for(i=0; i<sizeof(invalid)/sizeof(invalid[0]); i++)
  {
    value=42;
    assert(photorec_parse_image_minimum(invalid[i], strlen(invalid[i]), &value)<0);
    assert(value==42);
  }
}

static void test_cli(void)
{
  struct ph_options options={0};
  char commands[]="paranoid_no,image_min_width,640,image_min_height,480,image_min_pixels,307200,image_min_bytes,18446744073709551615,search";
  char *cmd=commands;
  assert(interface_options_photorec_cli(&options, &cmd)==0);
  assert(options.paranoid==0);
  assert(options.image_min_width==640 && options.image_min_height==480);
  assert(options.image_min_pixels==307200 && options.image_min_bytes==UINT64_MAX);
  assert(strcmp(cmd, "search")==0);
  cmd="image_min_width,0,image_min_height,0,image_min_pixels,0,image_min_bytes,0,search";
  assert(interface_options_photorec_cli(&options, &cmd)==0);
  assert(options.image_min_width==0 && options.image_min_height==0);
  assert(options.image_min_pixels==0 && options.image_min_bytes==0);
  assert(strcmp(cmd, "search")==0);
  cmd=NULL;
  assert(interface_options_photorec_cli(&options, &cmd)==0);
}

static void test_invalid_cli(void)
{
  static const char *names[]={"image_min_width", "image_min_height", "image_min_pixels", "image_min_bytes"};
  static const char *values[]={"", "-1", "+2", " 3", "4 ", "5.5", "6kb", "18446744073709551616", ",search", "search"};
  size_t i,j;
  for(i=0; i<sizeof(names)/sizeof(names[0]); i++)
  {
    struct ph_options options={0};
    char command[128];
    char *cmd;
    options.image_min_width=11;
    options.image_min_height=12;
    options.image_min_pixels=13;
    options.image_min_bytes=14;
    snprintf(command, sizeof(command), "%s", names[i]);
    cmd=command;
    assert(interface_options_photorec_cli(&options, &cmd)<0);
    for(j=0; j<sizeof(values)/sizeof(values[0]); j++)
    {
      snprintf(command, sizeof(command), "%s,%s,search", names[i], values[j]);
      cmd=command;
      assert(interface_options_photorec_cli(&options, &cmd)<0);
      assert(options.image_min_width==11 && options.image_min_height==12);
      assert(options.image_min_pixels==13 && options.image_min_bytes==14);
      assert(cmd==command); /* Never skip an invalid field into a later search. */
    }
  }
}

static void test_session_round_trip(void)
{
  struct ph_options options={0}, loaded={0};
  struct ph_param params={0};
  file_enable_t formats[1]={{0}};
  disk_t disk={0};
  partition_t partition={0};
  arch_fnct_t architecture={0};
  alloc_data_t space={0}, loaded_space={0};
  char *device=NULL, *commands=NULL, *cmd;
  architecture.part_name_option="partition_none";
  disk.device="synthetic-image.dd";
  disk.arch=&architecture;
  disk.sector_size=512;
  params.disk=&disk;
  params.partition=&partition;
  params.status=STATUS_FIND_OFFSET;
  params.offset=PH_INVALID_OFFSET;
  options.list_file_format=formats;
  options.image_min_width=640;
  options.image_min_height=480;
  options.image_min_pixels=307200;
  options.image_min_bytes=UINT64_MAX;
  TD_INIT_LIST_HEAD(&space.list);
  TD_INIT_LIST_HEAD(&loaded_space.list);
  assert(session_save(&space, &params, &options)==0);
  assert(session_load(&device, &commands, &loaded_space)==0);
  assert(device!=NULL && strcmp(device, "synthetic-image.dd")==0);
  assert(commands!=NULL);
  cmd=strstr(commands, "options,");
  assert(cmd!=NULL);
  cmd+=strlen("options,");
  assert(interface_options_photorec_cli(&loaded, &cmd)==0);
  assert(loaded.image_min_width==640 && loaded.image_min_height==480);
  assert(loaded.image_min_pixels==307200 && loaded.image_min_bytes==UINT64_MAX);
  assert(strncmp(cmd, "wholespace,search,", strlen("wholespace,search,"))==0);
  free(device);
  free(commands);
  assert(remove("photorec.ses")==0);
}

int main(void)
{
  test_numbers();
  test_cli();
  test_invalid_cli();
  test_session_round_trip();
  puts("Image options: strict numbers, CLI limits/errors, and session round trip passed.");
  return 0;
}
