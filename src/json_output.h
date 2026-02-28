/*

    File: json_output.h

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

#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/* Opaque JSON writer handle */
typedef struct json_writer json_writer_t;

/* Create a new JSON writer writing to 'out'. Returns NULL on allocation failure. */
json_writer_t *json_writer_create(FILE *out);

/* Destroy writer and free resources. Does not close the underlying FILE. */
void json_writer_destroy(json_writer_t *w);

/* Begin a named object (key may be NULL at top level / inside array). */
void json_object_begin(json_writer_t *w, const char *key);

/* End the current object. */
void json_object_end(json_writer_t *w);

/* Begin a named array (key may be NULL at top level / inside array). */
void json_array_begin(json_writer_t *w, const char *key);

/* End the current array. */
void json_array_end(json_writer_t *w);

/* Write a string key/value pair. value may be NULL (written as JSON null). */
void json_write_string(json_writer_t *w, const char *key, const char *value);

/* Write a signed 64-bit integer key/value pair. */
void json_write_int(json_writer_t *w, const char *key, int64_t value);

/* Write an unsigned 64-bit integer key/value pair. */
void json_write_uint(json_writer_t *w, const char *key, uint64_t value);

/* Write a boolean key/value pair (0 = false, non-zero = true). */
void json_write_bool(json_writer_t *w, const char *key, int value);

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* _JSON_OUTPUT_H */
