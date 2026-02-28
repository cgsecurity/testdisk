/*

    File: json_output.c

    Copyright (C) 2025 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <inttypes.h>

#include "json_output.h"

/* Maximum nesting depth for objects/arrays */
#define JSON_MAX_DEPTH 32

/* Container type on the depth stack */
typedef enum {
  JSON_CONTAINER_OBJECT = 0,
  JSON_CONTAINER_ARRAY  = 1
} json_container_t;

struct json_writer {
  FILE              *out;
  int                depth;
  /* track whether current container already has at least one element */
  int                has_item[JSON_MAX_DEPTH];
  /* track container type at each depth level */
  json_container_t   container[JSON_MAX_DEPTH];
};

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Print indentation: 2 spaces per depth level */
static void json_indent(const json_writer_t *w)
{
  int i;
  for(i = 0; i < w->depth; i++)
    fprintf(w->out, "  ");
}

/* Print a comma+newline separator if the current container already has items */
static void json_separator(json_writer_t *w)
{
  if(w->depth > 0 && w->has_item[w->depth - 1])
    fprintf(w->out, ",\n");
  else if(w->depth > 0)
    fprintf(w->out, "\n");
}

/* Mark current container as having at least one item */
static void json_mark_item(json_writer_t *w)
{
  if(w->depth > 0)
    w->has_item[w->depth - 1] = 1;
}

/* Write a key (with indentation) when inside an object.
 * When inside an array or at top level, just indent. */
static void json_write_key(json_writer_t *w, const char *key)
{
  json_separator(w);
  json_indent(w);
  if(key != NULL &&
     w->depth > 0 &&
     w->container[w->depth - 1] == JSON_CONTAINER_OBJECT)
  {
    fprintf(w->out, "\"%s\": ", key);
  }
}

/* Write a JSON-escaped string value (without surrounding quotes).
 * Handles: \", \\, \/, \b, \f, \n, \r, \t, and \uXXXX for other controls. */
static void json_escape(FILE *out, const char *str)
{
  const unsigned char *p = (const unsigned char *)str;
  fputc('"', out);
  for(; *p != '\0'; p++)
  {
    unsigned char c = *p;
    switch(c)
    {
      case '"':  fputs("\\\"", out); break;
      case '\\': fputs("\\\\", out); break;
      case '\b': fputs("\\b",  out); break;
      case '\f': fputs("\\f",  out); break;
      case '\n': fputs("\\n",  out); break;
      case '\r': fputs("\\r",  out); break;
      case '\t': fputs("\\t",  out); break;
      default:
        if(c < 0x20)
          /* control character: use \uXXXX encoding */
          fprintf(out, "\\u%04x", (unsigned int)c);
        else
          fputc(c, out);
        break;
    }
  }
  fputc('"', out);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

json_writer_t *json_writer_create(FILE *out)
{
  json_writer_t *w;
  if(out == NULL)
    return NULL;
  w = (json_writer_t *)malloc(sizeof(json_writer_t));
  if(w == NULL)
    return NULL;
  w->out   = out;
  w->depth = 0;
  memset(w->has_item,  0, sizeof(w->has_item));
  memset(w->container, 0, sizeof(w->container));
  return w;
}

void json_writer_destroy(json_writer_t *w)
{
  if(w == NULL)
    return;
  free(w);
}

void json_object_begin(json_writer_t *w, const char *key)
{
  if(w == NULL || w->depth >= JSON_MAX_DEPTH)
    return;
  json_write_key(w, key);
  fprintf(w->out, "{");
  /* push object context */
  w->container[w->depth] = JSON_CONTAINER_OBJECT;
  w->has_item[w->depth]  = 0;
  w->depth++;
  json_mark_item(w);
}

void json_object_end(json_writer_t *w)
{
  if(w == NULL || w->depth <= 0)
    return;
  w->depth--;
  /* close brace on its own line if object had content */
  if(w->has_item[w->depth])
  {
    fprintf(w->out, "\n");
    json_indent(w);
  }
  fprintf(w->out, "}");
  /* top-level: emit a trailing newline for readability */
  if(w->depth == 0)
    fprintf(w->out, "\n");
}

void json_array_begin(json_writer_t *w, const char *key)
{
  if(w == NULL || w->depth >= JSON_MAX_DEPTH)
    return;
  json_write_key(w, key);
  fprintf(w->out, "[");
  /* push array context */
  w->container[w->depth] = JSON_CONTAINER_ARRAY;
  w->has_item[w->depth]  = 0;
  w->depth++;
  json_mark_item(w);
}

void json_array_end(json_writer_t *w)
{
  if(w == NULL || w->depth <= 0)
    return;
  w->depth--;
  if(w->has_item[w->depth])
  {
    fprintf(w->out, "\n");
    json_indent(w);
  }
  fprintf(w->out, "]");
  if(w->depth == 0)
    fprintf(w->out, "\n");
}

void json_write_string(json_writer_t *w, const char *key, const char *value)
{
  if(w == NULL)
    return;
  json_write_key(w, key);
  if(value == NULL)
    fprintf(w->out, "null");
  else
    json_escape(w->out, value);
  json_mark_item(w);
}

void json_write_int(json_writer_t *w, const char *key, int64_t value)
{
  if(w == NULL)
    return;
  json_write_key(w, key);
  fprintf(w->out, "%" PRId64, value);
  json_mark_item(w);
}

void json_write_uint(json_writer_t *w, const char *key, uint64_t value)
{
  if(w == NULL)
    return;
  json_write_key(w, key);
  fprintf(w->out, "%" PRIu64, value);
  json_mark_item(w);
}

void json_write_bool(json_writer_t *w, const char *key, int value)
{
  if(w == NULL)
    return;
  json_write_key(w, key);
  fprintf(w->out, "%s", value ? "true" : "false");
  json_mark_item(w);
}
