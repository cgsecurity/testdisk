dnl Copyright (C) 2007-2015 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

# AC_PROG_MKDIR_P
# is a backport of autoconf-2.60's AC_PROG_MKDIR_P, with a fix
# for interoperability with automake-1.9.6 from autoconf-2.62.
# Remove this macro when we can assume autoconf >= 2.62 or
# autoconf >= 2.60 && automake >= 1.10.
# AC_AUTOCONF_VERSION was introduced in 2.62, so use that as the witness.
m4_ifndef([AC_AUTOCONF_VERSION],[
m4_ifdef([AC_PROG_MKDIR_P], [
  dnl For automake-1.9.6 && autoconf < 2.62: Ensure MKDIR_P is AC_SUBSTed.
  m4_define([AC_PROG_MKDIR_P],
    m4_defn([AC_PROG_MKDIR_P])[
    AC_SUBST([MKDIR_P])])], [
  dnl For autoconf < 2.60: Backport of AC_PROG_MKDIR_P.
  AC_DEFUN_ONCE([AC_PROG_MKDIR_P],
    [AC_REQUIRE([AM_PROG_MKDIR_P])dnl defined by automake
     MKDIR_P='$(mkdir_p)'
     AC_SUBST([MKDIR_P])])])
])
