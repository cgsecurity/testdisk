/*

    File: audit_trail.h

    Copyright (C) 2025 TestDisk/PhotoRec forensic audit trail module

    Append-only, cryptographically chained log.
    Each entry: TIMESTAMP|PREV_HASH|OPERATION|DETAILS|ENTRY_HASH
    where ENTRY_HASH = SHA-256(TIMESTAMP|PREV_HASH|OPERATION|DETAILS)
    and   PREV_HASH  = ENTRY_HASH of previous entry
                       (zero hash "000...0" for the first entry).

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
#ifndef _AUDIT_TRAIL_H
#define _AUDIT_TRAIL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* Open (or create) the audit trail file; must be called once before
 * audit_trail_log().  Returns 0 on success, -1 on error. */
int	audit_trail_open(const char *filepath);

/* Append one entry to the open trail.
 * operation — short verb, e.g. "OPEN", "HASH", "RECOVER"
 * details   — free-form detail string (pipe characters are escaped)
 * Returns 0 on success, -1 on error or if trail not open. */
int	audit_trail_log(const char *operation, const char *details);

/* Flush and close the trail.  Returns 0 on success, -1 on error. */
int	audit_trail_close(void);

#endif /* _AUDIT_TRAIL_H */
