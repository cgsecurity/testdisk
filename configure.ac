#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([testdisk],[7.2],[grenier@cgsecurity.org])
AC_LANG(C)
sinclude(acx_pthread.m4)
sinclude(mkdir.m4)
TESTDISKDATE="February 2024"
AC_SUBST(TESTDISKDATE)
AC_DEFINE_UNQUOTED([TESTDISKDATE],"$TESTDISKDATE",[Date of release])
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_HOST([])
AC_CANONICAL_TARGET([])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_DEFINE([_GNU_SOURCE], 1, [Enable GNU extensions])
AH_TEMPLATE([TARGET_LINUX], [Define for LINUX target])
AH_TEMPLATE([TARGET_BSD], [Define for BSD target])
AH_TEMPLATE([TARGET_SOLARIS], [Define for SOLARIS target])

# This is required to get past a stupid configure bug when making the rpm.
# Basically it is broken to specify the host as a command line argument to
# configure on its own, i.e. without giving --host=. It is supposed to work
# but doesn't. So this sets host and erases nonopt effectively moving the
# standalone command line option into the --host= form.
if test "x$nonopt" != "xNONE"; then
    host="$nonopt"
    nonopt="NONE"
fi

# Command-line options.
AC_ARG_WITH([ncurses],
    AS_HELP_STRING([--without-ncurses],[disabled use of the curses/ncurses/pdcurses/curses library (default is NO)]))

AC_ARG_WITH(ncurses-lib,
    AS_HELP_STRING([--with-ncurses-lib=DIR],[location of the ncurses library]),
    [ ncurses_lib_dir="${withval}"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(ncurses-includes,
    AS_HELP_STRING([--with-ncurses-includes=DIR],[location of the ncurses includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([ext2fs],
    AS_HELP_STRING([--without-ext2fs],[disabled use of the ext2fs library (default is NO)]))

AC_ARG_WITH(ext2fs-lib,
    AS_HELP_STRING([--with-ext2fs-lib=DIR],[location of the ext2fs library]),
    [ ext2fs_lib_a="${withval}/libext2fs.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(ext2fs-includes,
    AS_HELP_STRING([--with-ext2fs-includes=DIR],[location of the ext2fs includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH(com_err-lib,
    AS_HELP_STRING([--with-com_err-lib=DIR],[location of the com_err library]),
    [ com_err_lib_a="${withval}/libcom_err.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(com_err-includes,
    AS_HELP_STRING([--with-com_err-includes=DIR],[location of the com_err includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([jpeg],
    AS_HELP_STRING([--without-jpeg],[disabled use of the jpeg library (default is NO)]))

AC_ARG_WITH(jpeg-lib,
    AS_HELP_STRING([--with-jpeg-lib=DIR],[location of the jpeg library]),
    [ jpeg_lib_a="${withval}/libjpeg.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(jpeg-includes,
    AS_HELP_STRING([--with-jpeg-includes=DIR],[location of the jpeg includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([ntfs],
    AS_HELP_STRING([--without-ntfs],[disabled use of the ntfs library (default is NO)]))

AC_ARG_WITH([coverity-fix],
    AS_HELP_STRING([--with-coverity-fix],[Enable a coverity bug workaround]),
    [CFLAGS="${CFLAGS} -D_Float128=__uint128_t -D_Float32x=int -D_Float32=int -D_Float64x=long -D_Float64=long"])

AC_ARG_WITH(ntfs-lib,
    AS_HELP_STRING([--with-ntfs-lib=DIR],[location of the ntfs library]),
    [ ntfs_lib_a="${withval}/libntfs.a"
      LDFLAGS="${LDFLAGS} -L${withval}"
    ])

AC_ARG_WITH(ntfs-includes,
    AS_HELP_STRING([--with-ntfs-includes=DIR],[location of the ntfs includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([ntfs3g],
    AS_HELP_STRING([--without-ntfs3g],[disabled use of the ntfs3g library (default is NO)]))

AC_ARG_WITH(ntfs3g-lib,
    AS_HELP_STRING([--with-ntfs3g-lib=DIR],[location of the ntfs3g library]),
    [ ntfs3g_lib_a="${withval}/libntfs-3g.a"
      LDFLAGS="${LDFLAGS} -L${withval}"
    ])

AC_ARG_WITH(ntfs3g-includes,
    AS_HELP_STRING([--with-ntfs3g-includes=DIR],[location of the ntfs3g includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH(dal-lib,
    AS_HELP_STRING([--with-dal-lib=DIR],[location of the dal library]),
    [ LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH([reiserfs],
    AS_HELP_STRING([--without-reiserfs],[disabled use of the reiserfs library (default is NO)]))

AC_ARG_WITH(reiserfs-lib,
    AS_HELP_STRING([--with-reiserfs-lib=DIR],[location of the reiserfs library]),
    [ reiserfs_lib_a="${withval}/libreiserfs.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(reiserfs-includes,
    AS_HELP_STRING([--with-reiserfs-includes=DIR],[location of the reiserfs includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([ewf],
    AS_HELP_STRING([--without-ewf],[disabled use of the ewf library (default is NO)]))

AC_ARG_WITH(ewf-lib,
    AS_HELP_STRING([--with-ewf-lib=DIR],[location of the ewf library]),
    [ ewf_lib_a="${withval}/libewf.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(ewf-includes,
    AS_HELP_STRING([--with-ewf-includes=DIR],[location of the ewf includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([iconv],
    AS_HELP_STRING([--without-iconv],[disabled use of the iconv library (default is NO)]))

AC_ARG_WITH(iconv-lib,
    AS_HELP_STRING([--with-iconv-lib=DIR],[location of the iconv library]),
    [ iconv_lib_a="${withval}/libiconv.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(iconv-includes,
    AS_HELP_STRING([--with-iconv-includes=DIR],[location of the iconv includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH(giconv-lib,
    AS_HELP_STRING([--with-giconv-lib=DIR],[location of the giconv library]),
    [ iconv_lib_a="${withval}/libgiconv.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(giconv-includes,
    AS_HELP_STRING([--with-giconv-includes=DIR],[location of the giconv includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])

AC_ARG_WITH([zlib],
    AS_HELP_STRING([--without-zlib],[disabled use of the zlib library (default is NO)]))

AC_ARG_WITH([uuid],
    AS_HELP_STRING([--without-uuid],[disabled use of the uuid library]))

AC_ARG_ENABLE([assert],
    AS_HELP_STRING([--enable-assert],[enable compilation of assert code (default is YES)]),
    [case "${enableval}" in
       yes) use_assert=true ;;
       no)  use_assert=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-assert]) ;;
     esac],
     [use_assert=true])

AC_ARG_ENABLE([sudo],
    AS_HELP_STRING([--enable-sudo],[enable use of sudo (default is NO)]),
    [case "${enableval}" in
       yes) use_sudo=true ;;
       no)  use_sudo=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-sudo]) ;;
     esac],
     [use_sudo=false])

AC_ARG_WITH(sudo-bin,
    AS_HELP_STRING([--with-sudo-bin=PROG],[location of the sudo binary]),
    [SUDO_BIN="${withval}"])

AC_ARG_WITH(uuid-lib,
    AS_HELP_STRING([--with-uuid-lib=DIR],[location of the uuid library]),
    [ uuid_lib_a="${withval}/libuuid.a"
    LDFLAGS="${LDFLAGS} -L${withval}" ])

AC_ARG_WITH(uuid-includes,
    AS_HELP_STRING([--with-uuid-includes=DIR],[location of the uuid includes files]),
    [CPPFLAGS="${CPPFLAGS} -I${withval}"])


AC_ARG_ENABLE([missing-uuid-ok],
    AS_HELP_STRING([--enable-missing-uuid-ok], [force compilation even if both uuidgen and uuid_generate are missing, for developpement only (default is NO)]),
    [case "${enableval}" in
       yes) missing_uuid_ok=true ;;
       no)  missing_uuid_ok=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-missing_uuid_ok]) ;;
     esac],
     [missing_uuid_ok=false])

AC_ARG_ENABLE([qt],
    AS_HELP_STRING([--enable-qt],[enable use of qt (default is YES)]),
    [case "${enableval}" in
       yes) use_qt=true ;;
       no)  use_qt=false ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-qt]) ;;
     esac],
     [use_qt=true])

AC_ARG_ENABLE([dfxml],
    AS_HELP_STRING([--disable-dfxml]),
    [case "${enableval}" in
      yes) AC_DEFINE([ENABLE_DFXML],1,[Define to 1 if DFXML log is enabled]) ;;
      no) ;;
      *) AC_MSG_ERROR([bad value ${enableval} for --enable-dfxml]) ;;
     esac],
    [AC_DEFINE([ENABLE_DFXML],1,[Define to 1 if DFXML log is enabled])])

# Enable code coverage collection
AC_ARG_ENABLE(coverage,
[  --enable-coverage[=LEVEL]
			  enable compiler's code coverage collection.
			  Use to measure compiler performance and locate
			  unused parts of the compiler. With LEVEL, specify
			  optimization. Values are opt, noopt,
			  default is noopt],
[case "${enableval}" in
  yes|noopt)
    coverage_flags="--coverage -frandom-seed=\$@ -O0"
    ;;
  opt)
    coverage_flags="--coverage -frandom-seed=\$@ -O2"
    ;;
  no)
    # a.k.a. --disable-coverage
    coverage_flags=""
    ;;
  *)
    AC_MSG_ERROR(unknown coverage setting $enableval)
    ;;
esac],
[coverage_flags=""])

AC_ARG_ENABLE(gprof,
    AS_HELP_STRING([--enable-gprof],
      [Produce gprof profiling data in 'gmon.out' (GCC only).]),
[if test "$enableval" = "yes" ; then
  coverage_flags="$coverage_flags -pg"
fi])

# Determine if stack protection is disabled
AC_ARG_ENABLE([stack-protector],
    AS_HELP_STRING([--disable-stack-protector],
      [Disable the use of -fstack-protector-strong]))
AS_IF([test "x$enable_stack_protector" = "xno"],
    [stackProtector=0],
    [stackProtector=1]
    )

AC_ARG_ENABLE([record-compilation-date],
    AS_HELP_STRING([--enable-record-compilation-date],[record compilation date (default is NO)]),
    [case "${enableval}" in
       yes) AC_DEFINE([RECORD_COMPILATION_DATE],1,[Define to 1 to record compilation date]) ;;
       no)  ;;
       *) AC_MSG_ERROR([bad value ${enableval} for --enable-record-compilation-date]) ;;
     esac]
     )

use_icon=no

case "$target" in
*-*-*cygwin*)
  use_icon=yes
  win_target=yes
;;
*-*-*mingw*)
  use_icon=yes
  win_target=yes
;;
*-*-*djgpp)
  if test -z "$CC" ; then CC=gcc; fi
  stackProtector=0
;;
*-*-*bsd*)
  AC_DEFINE([TARGET_BSD], 1)
;;
*-*-linux*)
  AC_DEFINE([TARGET_LINUX], 1)
;;
*-*-solaris*)
  AC_DEFINE([TARGET_SOLARIS], 1)
;;
esac
# freebsd 4.X doesn't have stdint.h
# progsreiserfs header check for this variable to avoid this file inclusion
# IMOO progsreiserfs need to check for headers file presence instead
case "$target" in
    *freebsd4)
	AC_DEFINE([__freebsd__], 1,[Define for freebsd4 target and progsreiserfs compatibility])
    ;;
esac

AM_CONDITIONAL(USEICON, test "$use_icon" = yes)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
PKG_PROG_PKG_CONFIG
AC_ARG_VAR(WINDRES, [Windows Resource compiler tool path])
AC_PATH_TOOL(WINDRES,windres,)
AC_SUBST(WINDRES)
if test -z "$WINDRES"; then
  AC_MSG_WARN(Could not find a windres tool in your PATH.)
fi

# Enable large file support.
AC_SYS_LARGEFILE

# Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADERS([sys/types.h sys/stat.h stdlib.h stdint.h unistd.h])
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([byteswap.h curses.h cygwin/fs.h cygwin/version.h dal/file_dal.h dal/file.h ddk/ntddstor.h dirent.h endian.h errno.h fcntl.h features.h giconv.h glob.h iconv.h io.h libgen.h limits.h linux/fs.h linux/hdreg.h linux/types.h locale.h machine/endian.h malloc.h ncurses.h ncurses/curses.h ncurses/ncurses.h ncursesw/curses.h ncursesw/ncurses.h ntfs/version.h pwd.h scsi/scsi.h scsi/scsi_ioctl.h scsi/sg.h setjmp.h signal.h stdarg.h sys/cygwin.h sys/disk.h sys/disklabel.h sys/dkio.h sys/endian.h sys/ioctl.h sys/sysmacros.h sys/param.h sys/select.h sys/time.h sys/utsname.h sys/vtoc.h time.h utime.h w32api/ddk/ntdddisk.h windef.h windows.h zlib.h])

#--------------------------------------------------------------------
# Check for iconv support (for Unicode conversion).
#--------------------------------------------------------------------
#
# We need to find an iconv library that matches the installed iconv.h header
# (if any). It is important to check header/library compatibility. It's
# fairly common to have iconv support both in libc and from libiconv. In that
# case, a naive check that iconv() is in libc will succeed, but if we use
# libiconv's iconv.h, it will redefine iconv() to functions that exist
# only in libiconv, and we'll get link errors.
#
# First, check if there's a working iconv in libc (ie. if the test program
# compiles and links without any extra flags).
if test "x$with_iconv" != "xno"; then
AC_MSG_CHECKING(iconv support)
AC_LINK_IFELSE([AC_LANG_SOURCE([#include <iconv.h>
int main(int argc,char **argv) { iconv_open("foo","bar"); }])]
,
  # libc has a working iconv.
  AC_DEFINE(HAVE_ICONV,1, [Define if you have this function])
  AC_MSG_RESULT([[yes, in libc]])
  have_iconv=yes
)

if test "x$have_iconv" != "xyes" ; then
  # libc doesn't have a working iconv. Try adding -liconv and any user
  # supplied directory.

  old_LIBS="$LIBS"
  if test "${iconv_lib_a}" = ""; then
    LIBS="-liconv $LIBS"
  else
    LIBS="${iconv_lib_a} $LIBS"
  fi
  AC_LINK_IFELSE([AC_LANG_SOURCE([#include <iconv.h>
  int main(int argc,char **argv) { iconv_open("foo","bar"); }])]
  ,
    # -liconv works.
    AC_DEFINE(HAVE_ICONV,1, [Define if you have this function])
    AC_MSG_RESULT([[yes, -liconv]])
    have_iconv=yes
  ,
    LIBS="$old_LIBS"
  )
fi

if test "x$have_iconv" != "xyes" ; then
  # -liconv didn't work. Try giconv.h and -lgiconv.
  # BSDs install this lib as libgiconv.
  old_LIBS="$LIBS"
  if test "${giconv_lib_a}" = ""; then
    LIBS="-lgiconv $LIBS"
  else
    LIBS="${giconv_lib_a} $LIBS"
  fi
  AC_LINK_IFELSE([AC_LANG_SOURCE([#include <giconv.h>
  int main(int argc,char **argv) { iconv_open("foo","bar"); }])]
  ,
    AC_DEFINE(HAVE_ICONV,1, [Define if you have this function])
    AC_DEFINE(HAVE_GICONV,1, [Define if you have this function])
    AC_MSG_RESULT([[yes, -lgiconv]])
  ,
    AC_MSG_RESULT([[no]])
    LIBS="$old_LIBS"
  )
fi
else
  AC_MSG_WARN(Use of iconv function disabled)
fi

if test "x$have_iconv" != "xyes"; then
  if test "x$with_iconv" = "xyes"; then
    AC_MSG_ERROR([iconv requested but not found])
  fi
fi

AC_CHECK_HEADERS(sys/mount.h,,,
[[
#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
]])

AC_CHECK_HEADERS([winbase.h],,,
[[
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
#include <stdarg.h>
]])
AC_CHECK_HEADERS([winioctl.h],,,
[[
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
]])
AC_CHECK_HEADERS([w32api/winioctl.h],,,
[[
#ifdef HAVE_WINDEF_H
#include <windef.h>
#endif
]])

AC_CHECK_HEADERS([ext2fs/ext2_fs.h],,,
[[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
]])
AC_CHECK_HEADERS([ext2fs/ext2fs.h],,
              use_ext2fs=no
              AC_MSG_WARN(Disable use of ext2fs library),
[[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
]])

# libewf checks HAVE_OFF64_T, so defines it
AC_CHECK_TYPE(
 [off64_t],
 [AC_DEFINE( [HAVE_OFF64_T], [1], [Define to 1 if off64_t is available])],
 [AC_DEFINE( [HAVE_OFF64_T], [0], [Define to 0 if off64_t is not available])])

AC_CHECK_HEADERS([libewf.h],,
              use_ewf=no
              AC_MSG_WARN(Disable use of ewf library))

AC_CHECK_HEADERS([jpeglib.h], use_jpeg_header=ok)
if test -z "${use_jpeg_header}"; then
	use_jpeg=no
	AC_MSG_WARN(Disable use of jpeg library)
fi

AC_CHECK_HEADERS([ntfs/attrib.h ntfs/volume.h],,
              use_ntfs=no
              AC_MSG_WARN(Disable use of ntfs library))

AC_CHECK_HEADERS([ntfs-3g/attrib.h ntfs-3g/volume.h],,
              use_ntfs3g=no
              AC_MSG_WARN(Disable use of ntfs3g library))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_BIGENDIAN(,
    [AC_DEFINE([TESTDISK_LSB], 1,
      [Define to 1 if your processor stores words with the least significant
      byte first (like Intel and VAX, unlike Motorola and SPARC).])]
    ,)
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS
AC_STRUCT_TM
AC_CHECK_TYPE(
 [paddr_t],
 [AC_DEFINE( [HAVE_PADDR_T], [1], [Define to 1 if paddr_t is available])],
 [AC_DEFINE( [HAVE_PADDR_T], [0], [Define to 0 if paddr_t is not available])])

AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([dal_t.block_size],,,[#include <dal/dal.h>])
AC_CHECK_MEMBERS([dal_t.error],,,[#include <dal/dal.h>])
AC_CHECK_MEMBERS([dal_t.entity],,,[#include <dal/dal.h>])
AC_CHECK_MEMBERS([dal_t.name],,,[#include <dal/dal.h>])
AC_CHECK_MEMBERS([struct dal_ops.dev],,,[#include <dal/dal.h>])
AC_CHECK_MEMBERS([struct struct_io_manager.set_option,
struct struct_io_manager.read_blk64,
struct struct_io_manager.write_blk64],,,[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_EXT2FS_EXT2_FS_H
#include <ext2fs/ext2_fs.h>
#endif
#ifdef HAVE_EXT2FS_EXT2FS_H
#include <ext2fs/ext2fs.h>
#endif
])
AC_CHECK_MEMBERS([struct tm.tm_gmtoff])

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
# As no alternate function is provided,
# these checks should not be used if we want to cross-compile the programs
#AC_FUNC_MEMCMP
#AC_FUNC_STAT
#AC_FUNC_VPRINTF
#AC_FUNC_MALLOC

# Checks for libraries.
if test "x$with_ncurses" != "xno"; then
  AC_CHECK_LIB(ncursesw, initscr, [ ncurses_lib="ncursesw" ])
 if test -z "${ncurses_lib}"; then
  AC_CHECK_LIB( ncurses, initscr, [ ncurses_lib="ncurses" ])
 fi
 if test -z "${ncurses_lib}"; then
  AC_CHECK_LIB(pdcurses, initscr, [ ncurses_lib="pdcurses" ])
 fi
 if test -z "${ncurses_lib}"; then
  AC_CHECK_LIB(curses, initscr,   [ ncurses_lib="curses" ])
 fi
 if test -z "${ncurses_lib}"; then
   AC_MSG_ERROR(At least one of ncursesw/ncurses/pdcurses/curses library must be present)
 fi
 AC_DEFINE([HAVE_NCURSES],1,[Define to 1 if you have one of the ncursesw/ncurses/pdcurses/curses library.])
 if test "${ncurses_lib_dir}" != "" -a -e "${ncurses_lib_dir}/lib${ncurses_lib}.a"; then
   testdisk_LDADD="$testdisk_LDADD ${ncurses_lib_dir}/lib${ncurses_lib}.a"
   photorec_LDADD="$photorec_LDADD ${ncurses_lib_dir}/lib${ncurses_lib}.a"
 else
   testdisk_LDADD="$testdisk_LDADD -l${ncurses_lib}"
   photorec_LDADD="$photorec_LDADD -l${ncurses_lib}"
 fi

 if test "${ncurses_lib}" = "ncursesw"; then
  AC_CHECK_LIB(tinfow,keypad, [ tinfo_lib="tinfow" ])
 fi
 if test -z "${tinfo_lib}"; then
  AC_CHECK_LIB(tinfo,keypad, [ tinfo_lib="tinfo" ])
 fi
 if test "${tinfo_lib}" != ""; then
      AC_DEFINE([HAVE_TINFO],1,[Define to 1 if you have the tinfo library (-ltinfo).])
   # if lib${ncurses_lib}.a is present, try to use libtinfo.a
   if test "${ncurses_lib_dir}" != "" -a -e "${ncurses_lib_dir}/lib${ncurses_lib}.a";
   then
     if test -e "${ncurses_lib_dir}/lib${tinfo_lib}.a"; then
       testdisk_LDADD="$testdisk_LDADD ${ncurses_lib_dir}/lib${tinfo_lib}.a"
       photorec_LDADD="$photorec_LDADD ${ncurses_lib_dir}/lib${tinfo_lib}.a"
     fi
   else
     testdisk_LDADD="$testdisk_LDADD -l${tinfo_lib}"
     photorec_LDADD="$photorec_LDADD -l${tinfo_lib}"
   fi
 fi
  ac_save_LIBS="$LIBS"
  LIBS="$LIBS $photorec_LDADD"
  AC_CHECK_FUNCS([assume_default_colors])
  LIBS="$ac_save_LIBS"
else
  AC_MSG_WARN(Use of ncurses library disabled)
fi

if test "x$use_ext2fs" != "xno"; then
if test "x$with_ext2fs" != "xno"; then
  ac_save_LIBS="$LIBS"
  AC_CHECK_LIB(com_err,com_err,[
      AC_DEFINE([HAVE_LIBCOMM_ERR],1,[Define to 1 if you have the com_err library (-lcom_err).])
      if test "${com_err_lib_a}" = ""; then
	LIBS="-lcom_err $LIBS"
        photorec_LDADD="-lcom_err $photorec_LDADD"
        qphotorec_LDADD="-lcom_err $qphotorec_LDADD"
        testdisk_LDADD="-lcom_err $testdisk_LDADD"
      else
	LIBS="${com_err_lib_a} $LIBS"
        photorec_LDADD="${com_err_lib_a} $photorec_LDADD"
        qphotorec_LDADD="${com_err_lib_a} $qphotorec_LDADD"
        testdisk_LDADD="${com_err_lib_a} $testdisk_LDADD"
      fi
      have_com_err=yes
      ], AC_MSG_WARN(No com_err library detected))

  AC_CHECK_LIB(ext2fs,ext2fs_open,[
      AC_DEFINE([HAVE_LIBEXT2FS],1,[Define to 1 if you have the ext2fs library (-lext2fs).])
      if test "${ext2fs_lib_a}" = ""; then
	LIBS="-lext2fs $LIBS"
        photorec_LDADD="-lext2fs $photorec_LDADD"
        qphotorec_LDADD="-lext2fs $qphotorec_LDADD"
        testdisk_LDADD="-lext2fs $testdisk_LDADD"
      else
	LIBS="${ext2fs_lib_a} $LIBS"
        photorec_LDADD="${ext2fs_lib_a} $photorec_LDADD"
        qphotorec_LDADD="${ext2fs_lib_a} $qphotorec_LDADD"
        testdisk_LDADD="${ext2fs_lib_a} $testdisk_LDADD"
      fi
      have_ext2fs=yes
      ],AC_MSG_WARN(No ext2fs library detected))
  AC_CHECK_FUNCS([ext2fs_get_generic_bitmap_start])
  LIBS="$ac_save_LIBS"
else
  AC_MSG_WARN(Use of ext2fs library disabled)
fi
fi

if test "x$have_ext2fs" != "xyes"; then
  if test "x$with_ext2fs" = "xyes"; then
    AC_MSG_ERROR([ext2fs requested but not found])
  fi
fi


if test "x$use_jpeg" != "xno"; then
if test "x$with_jpeg" != "xno"; then
  AC_CHECK_LIB(jpeg,jpeg_std_error,[
      AC_DEFINE([HAVE_LIBJPEG],1,[Define to 1 if you have the jpeg library (-ljpeg).])
      if test "${jpeg_lib_a}" = ""; then
        photorec_LDADD="$photorec_LDADD -ljpeg"
        qphotorec_LDADD="$qphotorec_LDADD -ljpeg"
        fidentify_LDADD="$fidentify_LDADD -ljpeg"
      else
        photorec_LDADD="$photorec_LDADD ${jpeg_lib_a}"
        qphotorec_LDADD="$qphotorec_LDADD ${jpeg_lib_a}"
        fidentify_LDADD="$fidentify_LDADD ${jpeg_lib_a}"
      fi
      have_jpeg=yes
      ],AC_MSG_WARN(No jpeg library detected))
#  )
else
  AC_MSG_WARN(Use of jpeg library disabled)
fi
fi

if test "x$have_jpeg" != "xyes"; then
  if test "x$with_jpeg" = "xyes"; then
    AC_MSG_ERROR([jpeg requested but not found])
  fi
fi

if test "x$use_ntfs3g" != "xno"; then
if test "x$with_ntfs3g" != "xno"; then
  AC_CHECK_LIB(ntfs-3g,ntfs_device_mount,
  [
    AC_DEFINE([HAVE_LIBNTFS3G],1,[Define to 1 if you have the ntfs3g library (-lntfs3g).])
    if test "${ntfs3g_lib_a}" = ""; then
      photorec_LDADD="-lntfs-3g $photorec_LDADD"
      qphotorec_LDADD="-lntfs-3g $qphotorec_LDADD"
      testdisk_LDADD="-lntfs-3g $testdisk_LDADD"
    else
      photorec_LDADD="${ntfs3g_lib_a} $photorec_LDADD"
      qphotorec_LDADD="${ntfs3g_lib_a} $qphotorec_LDADD"
      testdisk_LDADD="${ntfs3g_lib_a} $testdisk_LDADD"
    fi
    have_ntfs3g=yes
    use_ntfs=no
  ],
  AC_MSG_WARN(No ntfs-3g library detected)
  )
else
  AC_MSG_WARN(Use of ntfs3g library disabled)
fi
fi

if test "x$have_ntfs-3g" != "xyes"; then
  if test "x$with_ntfs-3g" = "xyes"; then
    AC_MSG_ERROR([ntfs-3g requested but not found])
  fi
fi

if test "x$use_ntfs" != "xno"; then
if test "x$with_ntfs" != "xno"; then
  AC_CHECK_LIB(ntfs,ntfs_device_mount,
  [
    AC_DEFINE([HAVE_LIBNTFS],1,[Define to 1 if you have the ntfs library (-lntfs).])
    if test "${ntfs_lib_a}" = ""; then
      photorec_LDADD="-lntfs $photorec_LDADD"
      qphotorec_LDADD="-lntfs $qphotorec_LDADD"
      testdisk_LDADD="-lntfs $testdisk_LDADD"
    else
      photorec_LDADD="${ntfs_lib_a} $photorec_LDADD"
      qphotorec_LDADD="${ntfs_lib_a} $qphotorec_LDADD"
      testdisk_LDADD="${ntfs_lib_a} $testdisk_LDADD"
    fi
    have_ntfs=yes
  ],
    AC_CHECK_LIB(ntfs,ntfs_libntfs_version,
    [
      AC_DEFINE([HAVE_LIBNTFS],1,[Define to 1 if you have the ntfs library (-lntfs).])
      if test "${ntfs_lib_a}" = ""; then
	photorec_LDADD="-lntfs $photorec_LDADD"
	qphotorec_LDADD="-lntfs $qphotorec_LDADD"
	testdisk_LDADD="-lntfs $testdisk_LDADD"
      else
	photorec_LDADD="${ntfs_lib_a} $photorec_LDADD"
	qphotorec_LDADD="${ntfs_lib_a} $qphotorec_LDADD"
	testdisk_LDADD="${ntfs_lib_a} $testdisk_LDADD"
      fi
      have_ntfs=yes
    ],AC_MSG_WARN(No ntfs library detected))
  )
else
  AC_MSG_WARN(Use of ntfs library disabled)
fi
fi

if test "x$have_ntfs" != "xyes"; then
  if test "x$with_ntfs" = "xyes"; then
    AC_MSG_ERROR([ntfs requested but not found])
  fi
fi

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_LIBNTFS
#include <ntfs/volume.h>
#include <ntfs/attrib.h>
#endif
#ifdef HAVE_LIBNTFS3G
#include <ntfs-3g/volume.h>
#include <ntfs-3g/attrib.h>
#endif
]],
[[ ntfs_mbstoucs(NULL,NULL); ]])],
    [ac_cv_c_ntfs_mbstoucs_have_two_arguments=yes],
    [ac_cv_c_ntfs_mbstoucs_have_two_arguments=no])
if test "${ac_cv_c_ntfs_mbstoucs_have_two_arguments}" != "no"; then
  AC_DEFINE([NTFS_MBSTOUCS_HAVE_TWO_ARGUMENTS], 1, [Define if ntfs_mbstoucs takes two parameters.])
fi

if test "x$use_reiserfs" != "xno"; then
if test "x$with_reiserfs" != "xno"; then
  AC_CHECK_LIB(reiserfs,libreiserfs_get_version,[
  AC_DEFINE([HAVE_LIBREISERFS],1,[Define to 1 if you have the reiserfs library (-lreiserfs).])
  if test "${reiserfs_lib_a}" = ""; then
    testdisk_LDADD="$testdisk_LDADD -lreiserfs"
  else
    testdisk_LDADD="$testdisk_LDADD ${reiserfs_lib_a}"
  fi
  have_reiserfs=yes
  ],AC_MSG_WARN(No reiserfs library detected),[-ldal])
else
  AC_MSG_WARN(Use of reiserfs library disabled)
fi
fi

if test "x$have_reiserfs" != "xyes"; then
  if test "x$with_reiserfs" = "xyes"; then
    AC_MSG_ERROR([reiserfs requested but not found])
  fi
fi

# Check for UUID functions
AC_CHECK_HEADERS([sys/uuid.h uuid/uuid.h uuid.h])
found_uuid_function=yes
AC_CHECK_FUNCS([uuidgen],,[found_uuid_function=no])
if test "x$with_uuid" != "xno"; then
  if test "x${found_uuid_function}" != "xyes";
  then
    AC_CHECK_LIB(uuid_generate, uuid, [
      AC_DEFINE([HAVE_LIBUUID],1,[Define to 1 if you have the uuid library (-luuid).])
      testdisk_LDADD="-luuid $testdisk_LDADD"
      have_uuid=yes
      found_uuid_function=yes
    ])
  fi
  if test "x$found_uuid_function" != "xyes";
  then
    found_uuid_function=yes
    AC_CHECK_LIB(uuid_create, uuid, [
      AC_DEFINE([HAVE_LIBUUID],1,[Define to 1 if you have the uuid library (-luuid).])
      testdisk_LDADD="-luuid $testdisk_LDADD"
      have_uuid=yes
      found_uuid_function=yes
    ])
  fi
fi

if test "${found_uuid_function}" = "yes";
then
  OLDLIBS="$LIBS"
  LIBS="$OLDLIBS $testdisk_LDADD"
  AC_CHECK_FUNCS([uuid_create])
  AC_CHECK_FUNCS([uuid_generate])
  LIBS="$OLDLIBS"
fi

if test "${found_uuid_function}" = "no";
then
  if test "${missing_uuid_ok}" = "true";
  then
    AC_MSG_WARN(No uuid_create or uuid_generate function in library libuuid or uuidgen function present)
  else
    AC_MSG_ERROR(No uuid_create or uuid_generate function in library libuuid or uuidgen function present. Either fix it or use "--enable-missing-uuid-ok")
  fi
fi

if test "x$use_zlib" != "xno"; then
if test "x$with_zlib" != "xno"; then
  AC_CHECK_LIB(z, compress2, [
      AC_DEFINE([HAVE_LIBZ],1,[Define to 1 if you have the z library (-lz).])
      have_zlib=yes
      LIBS="-lz $LIBS"
  ], AC_MSG_WARN(Missing function: compress2 in library zlib))
fi
fi

if test "x$have_zlib" != "xyes"; then
  if test "x$with_zlib" = "xyes"; then
    AC_MSG_ERROR([zlib requested but not found])
  fi
fi
#
if test "x$use_ewf" != "xno"; then
if test "x$with_ewf" != "xno"; then
  AC_CHECK_LIB(ewf,libewf_check_file_signature,[
  AC_DEFINE([HAVE_LIBEWF],1,[Define to 1 if you have the ewf library (-lewf).])
  if test "${ewf_lib_a}" = ""; then
    photorec_LDADD="-lewf $photorec_LDADD"
    qphotorec_LDADD="-lewf $qphotorec_LDADD"
    testdisk_LDADD="-lewf $testdisk_LDADD"
  else
    photorec_LDADD="${ewf_lib_a} $photorec_LDADD"
    qphotorec_LDADD="${ewf_lib_a} $qphotorec_LDADD"
    testdisk_LDADD="${ewf_lib_a} $testdisk_LDADD"
  fi
  have_ewf=yes
  OLDLIBS="$LIBS"
  LIBS="$OLDLIBS $photorec_LDADD"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <libewf.h>]],
      [[ libewf_get_bytes_per_sector(NULL,NULL); ]])],
    [ac_cv_c_libewf_get_bytes_per_sector_have_two_arguments=yes],
    [ac_cv_c_libewf_get_bytes_per_sector_have_two_arguments=no])
  if test "${ac_cv_c_libewf_get_bytes_per_sector_have_two_arguments}" != "no"; then
        AC_DEFINE([LIBEWF_GET_BYTES_PER_SECTOR_HAVE_TWO_ARGUMENTS], 1, [Define if libewf_get_bytes_per_sector takes two parameters.])
  fi
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <libewf.h>]],
      [[ libewf_get_media_size(NULL,NULL); ]])],
    [ac_cv_c_libewf_get_media_size_have_two_arguments=yes],
    [ac_cv_c_libewf_get_media_size_have_two_arguments=no])
  if test "${ac_cv_c_libewf_get_media_size_have_two_arguments}" != "no"; then
        AC_DEFINE([LIBEWF_GET_MEDIA_SIZE_HAVE_TWO_ARGUMENTS], 1, [Define if libewf_get_media_size takes two parameters.])
  fi
  AC_CHECK_TYPE(
  [libewf_handle_t],
  [AC_DEFINE( [HAVE_LIBEWF_HANDLE_T], [1], [Define to 1 if libewf_handle_t is available])],,
  [#include <libewf.h>])
  ],[
  AC_MSG_WARN(No ewf library detected)
  ],[])
  LIBS="$OLDLIBS"
else
  AC_MSG_WARN(Use of ewf library disabled)
fi
fi

if test "x$have_ewf" != "xyes"; then
  if test "x$with_ewf" = "xyes"; then
    AC_MSG_ERROR([ewf requested but not found])
  fi
fi
#-Wconversion -Wmissing-noreturn -ffunction-sections -Wl,--gc-sections -Wl,--print-gc-sections
for option in -Wdeclaration-after-statement -Wall -Wextra -MD -Wpointer-arith -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wshadow -Wwrite-strings -W -Wcast-align -Waggregate-return -Wbad-function-cast -Wcast-qual -Wundef -Wredundant-decls -Wsign-compare -Wnested-externs -Winline -Wdisabled-optimization -Wfloat-equal -Wmissing-format-attribute -Wmultichar -Wc++-compat -Wformat=2 -Wtrampolines -Wunreachable-code -Wvla
do
  SAVE_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $option"
  AC_MSG_CHECKING([whether gcc understands $option])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
      [has_option=yes],
      [has_option=no; CFLAGS="$SAVE_CFLAGS"])
  AC_MSG_RESULT($has_option)
  unset has_option
  unset SAVE_CFLAGS
done
unset option

AC_LANG_PUSH([C++])
for option in -Wall -MD -Wpointer-arith -Wmissing-declarations -Wshadow -Wwrite-strings -W -Wcast-align -Wcast-qual -Wundef -Wredundant-decls -Wsign-compare -Wdisabled-optimization -Wmissing-format-attribute -Wmultichar -Wformat=2 -fvisibility=hidden -fvisibility-inlines-hidden -fPIC -Wtrampolines -Wvla
do
  SAVE_CXXFLAGS="$CXXFLAGS"
  CXXFLAGS="$CXXFLAGS $option"
  AC_MSG_CHECKING([whether g++ understands $option])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
      [has_option=yes],
      [has_option=no; CXXFLAGS="$SAVE_CXXFLAGS"])
  AC_MSG_RESULT($has_option)
  unset has_option
  unset SAVE_CXXFLAGS
done
unset option
AC_LANG_POP([C++])

#if defined __GNUC__ && !defined _FORTIFY_SOURCE
AC_DEFINE([_FORTIFY_SOURCE], 2, [enable compile-time and run-time bounds-checking, and some warnings])
#endif

case "$target" in
  *hpux*)
	;;
  *)
	AC_CHECK_FUNCS(pread)
  ;;
esac

AC_CHECK_FUNCS([ atexit atoll chdir chmod delscreen dirname dup2 execv fdatasync fseeko fsync ftello ftruncate getcwd geteuid getpwuid libewf_handle_read_buffer_at_offset libewf_handle_write_buffer_at_offset localtime_r lstat memalign memchr memset mkdir posix_fadvise posix_memalign pwrite readlink setenv setlocale sigaction signal sleep snprintf strcasecmp strcasestr strchr strdup strerror strncasecmp strptime strrchr strstr strtol strtoul strtoull touchwin uname utime vsnprintf wctomb ])
if test "$ac_cv_func_mkdir" = "no"; then
  AC_MSG_ERROR(No mkdir function detected)
fi

if test "$ac_cv_func_execv" = "yes" -a "$use_sudo" = "true";
then
    if test -z "$SUDO_BIN"; then
        AC_PATH_PROG([SUDO], [sudo], [AC_MSG_ERROR([sudo requested but not found])])
	SUDO_BIN="$SUDO"
    fi
    AC_DEFINE_UNQUOTED([SUDO_BIN], "$SUDO_BIN", [Path to sudo for privileged operations])
fi

if test "$use_assert" = "false";
then
  AC_DEFINE(NDEBUG, 1, [Disable the assert error checking])
fi

#reiserfs_fs_open_fast may not been detected because of lack of -ldal
OLDLIBS="$LIBS"
LIBS="$OLDLIBS $testdisk_LDADD -ldal"
AC_CHECK_FUNCS([reiserfs_fs_open_fast])
LIBS="$OLDLIBS"
AC_CHECK_FUNCS([ntfs_libntfs_version ntfs_volume_startup])

export QT_SELECT=qt5
if test "$use_qt" = "true";
then
  PKG_CHECK_MODULES(QT5GUI, [Qt5Gui  >= 5.0.0],,use_qt=false)
  PKG_CHECK_MODULES(QT5WIDGETS, [Qt5Widgets  >= 5.0.0],,use_qt=false)
  AC_MSG_CHECKING([whether Qt5 is using --std=c++14])
  qt_config=`$PKG_CONFIG --variable=qt_config Qt5Core | grep "c++14"`
  if test "x$qt_config" != "x" ;
  then
    AC_MSG_RESULT([[yes]])
    AC_LANG_PUSH([C++])
    option="--std=c++14"
    SAVE_CXXFLAGS="$CXXFLAGS"
    CXXFLAGS="$CXXFLAGS $option"
    AC_MSG_CHECKING([whether g++ understands $option])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
	[has_option=yes],
	[has_option=no; CXXFLAGS="$SAVE_CXXFLAGS"])
    AC_MSG_RESULT($has_option)
    unset has_option
    unset SAVE_CXXFLAGS
    unset option
    AC_LANG_POP([C++])
  else
    AC_MSG_RESULT([[no]])
    AC_MSG_CHECKING([whether Qt5 is using --std=c++11])
    qt_config=`$PKG_CONFIG --variable=qt_config Qt5Core | grep "c++11"`
    if test "x$qt_config" != "x" ;
    then
      AC_MSG_RESULT([[yes]])
      AC_LANG_PUSH([C++])
      option="--std=c++11"
      SAVE_CXXFLAGS="$CXXFLAGS"
      CXXFLAGS="$CXXFLAGS $option"
      AC_MSG_CHECKING([whether g++ understands $option])
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
	  [has_option=yes],
	  [has_option=no; CXXFLAGS="$SAVE_CXXFLAGS"])
      AC_MSG_RESULT($has_option)
      unset has_option
      unset SAVE_CXXFLAGS
      unset option
      AC_LANG_POP([C++])
    else
      AC_MSG_RESULT([[no]])
    fi
  fi

  AC_CHECK_TOOLS(MOC,[moc-qt5 moc],)
  if test x$MOC = x ; then
	AC_MSG_WARN(Could not find a moc-qt5 or moc tool in your PATH.)
	use_qt=false
  fi
  AC_CHECK_TOOLS(RCC,[rcc-qt5 rcc],)
  if test x$RCC = x ; then
	AC_MSG_WARN(Could not find a rcc-qt5 or rcc tool in your PATH.)
	use_qt=false
  fi
  AC_CHECK_TOOLS(LRELEASE,[lrelease-qt5 lrelease],)
  if test x$LRELEASE = x ; then
	AC_MSG_WARN(Could not find a lrelease-qt5 or lrelease tool in your PATH.)
	use_qt=false
  fi
  qphotorec_LDADD="$qphotorec_LDADD $QT5GUI_LIBS $QT5WIDGETS_LIBS"
  qphotorec_CXXFLAGS="$qphotorec_CXXFLAGS $QT5GUI_CFLAGS $QT5WIDGETS_CFLAGS"
fi
AM_CONDITIONAL(USEQT, test "$use_qt" = true)
if test "$win_target" = yes;
then
  qphotorec_LDADD="$qphotorec_LDADD -mwindows"
fi

# e2fsprogs may be using pthread
# checks for pthreads
SAVE_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -static"
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
CFLAGS="$SAVE_CFLAGS"

# If using stack protection, try -fstack-protector-strong, if not try to fallback to -fstack-protector-all
if test $stackProtector = 1;
then
      AC_MSG_CHECKING([whether stack protection works with gcc])
      SAVE_CFLAGS="$CFLAGS"
      CFLAGS="$SAVE_CFLAGS -fstack-protector-strong"
      AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([])],
	[has_option=yes],
	[CFLAGS="$SAVE_CFLAGS -fstack-protector-all"]
	[AC_COMPILE_IFELSE(
	  [AC_LANG_PROGRAM([])],
	  [has_option=yes],
	  [has_option=no; CFLAGS="$SAVE_CFLAGS"]
	  [AC_MSG_WARN([Cannot configure with stack protection])]
	  )]
	)
      AC_MSG_RESULT($has_option)
      unset has_option
      unset SAVE_CFLAGS
fi
if test $stackProtector = 1;
then
      AC_MSG_CHECKING([whether stack protection works with g++])
      AC_LANG_PUSH([C++])
      SAVE_CXXFLAGS="$CXXFLAGS"
      CXXFLAGS="$SAVE_CXXFLAGS -fstack-protector-strong"
      AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([])],
	[has_option=yes],
	[CXXFLAGS="$SAVE_CXXFLAGS -fstack-protector-all"]
	[AC_COMPILE_IFELSE(
	  [AC_LANG_PROGRAM([])],
	  [has_option=yes],
	  [has_option=no]
	  [CXXFLAGS="$SAVE_CXXFLAGS"]
	  [AC_MSG_WARN([Cannot configure with stack protection])]
	  )]
	)
      AC_MSG_RESULT($has_option)
      unset has_option
      unset SAVE_CXXFLAGS
      AC_LANG_POP([C++])
fi

photorecf_LDADD=$photorec_LDADD
fuzzerfidentify_LDADD="-fsanitize=fuzzer $fidentify_LDADD"
CFLAGS="$CFLAGS $coverage_flags"
CXXFLAGS="$CXXFLAGS $coverage_flags"
CPPFLAGS="$CPPFLAGS $coverage_flags"
AC_SUBST(CFLAGS)
AC_SUBST(CXXFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(MOC)
AC_SUBST(LRELEASE)
AC_SUBST(QT_SELECT)
AC_SUBST(fidentify_LDADD)
AC_SUBST(fuzzerfidentify_LDADD)
AC_SUBST(testdisk_LDADD)
AC_SUBST(photorec_LDADD)
AC_SUBST(photorecf_LDADD)
AC_SUBST(qphotorec_LDADD)
AC_SUBST(qphotorec_CXXFLAGS)
AC_CONFIG_FILES([
	Makefile
	icons/Makefile
	src/Makefile
	man/Makefile
	man/testdisk.8 man/photorec.8 man/qphotorec.8 man/fidentify.8
	man/zh_CN/Makefile
	man/zh_CN/testdisk.8 man/zh_CN/photorec.8 man/zh_CN/qphotorec.8 man/zh_CN/fidentify.8
	linux/testdisk.spec
])
AC_OUTPUT
