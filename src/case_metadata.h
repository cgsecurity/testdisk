/*

    File: case_metadata.h

    Copyright (C) 2025 TestDisk/PhotoRec forensic case metadata module

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
#ifndef _CASE_METADATA_H
#define _CASE_METADATA_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* Forensic case metadata — populated by examiner before analysis */
typedef struct {
	char	case_id[128];		/* unique case identifier */
	char	examiner[128];		/* examiner name / badge */
	char	evidence_id[128];	/* evidence item number */
	char	notes[512];		/* free-form notes */
	char	start_time[32];		/* ISO 8601 acquisition start */
	char	end_time[32];		/* ISO 8601 acquisition end   */
	char	tool_version[32];	/* e.g. "PhotoRec 7.3"        */
	char	hostname[64];		/* machine running the tool   */
} case_metadata_t;

/* Zero-initialise and fill tool_version + hostname */
void	case_metadata_init(case_metadata_t *meta);

/* Stamp start_time with current wall-clock (ISO 8601) */
void	case_metadata_set_start(case_metadata_t *meta);

/* Stamp end_time with current wall-clock (ISO 8601) */
void	case_metadata_set_end(case_metadata_t *meta);

#endif /* _CASE_METADATA_H */
