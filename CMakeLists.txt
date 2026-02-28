cmake_minimum_required(VERSION 3.16)
project(testdisk VERSION 7.3 LANGUAGES C CXX)

# ── Build options ────────────────────────────────────────────────────────────
option(WITH_NCURSES  "Enable ncurses/ncursesw UI"     ON)
option(WITH_EXT2FS   "Enable ext2fs library"          ON)
option(WITH_JPEG     "Enable libjpeg support"         ON)
option(WITH_NTFS3G   "Enable ntfs-3g library"         ON)
option(WITH_EWF      "Enable libewf (EnCase) support" ON)
option(WITH_ZLIB     "Enable zlib compression"        ON)
option(WITH_UUID     "Enable uuid library"            ON)
option(WITH_QT       "Build qphotorec Qt5 GUI"        ON)
option(BUILD_TESTS   "Build unit tests (requires cmocka)" ON)

# ── Standard requirements ────────────────────────────────────────────────────
set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CheckStructHasMember)
include(TestBigEndian)
include(GNUInstallDirs)

# ── config.h generation ──────────────────────────────────────────────────────
# HAVE_* variables set below drive cmake/config.h.cmake -> build/config.h

# Platform detection
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(TARGET_LINUX 1)
elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
    set(TARGET_BSD 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    set(TARGET_SOLARIS 1)
endif()

# ── Dependency detection ─────────────────────────────────────────────────────

# ncurses (required for TUI binaries)
if(WITH_NCURSES)
    find_package(Curses)
    if(CURSES_FOUND)
        set(HAVE_NCURSES 1)
        if(CURSES_LIBRARY MATCHES "ncursesw")
            set(NCURSES_LIB ncursesw)
        elseif(CURSES_LIBRARY MATCHES "ncurses")
            set(NCURSES_LIB ncurses)
        else()
            set(NCURSES_LIB curses)
        endif()
    else()
        message(WARNING "ncurses not found -- TUI will be unavailable")
    endif()
endif()

# ext2fs + com_err
if(WITH_EXT2FS)
    # check_include_file takes only (header varname) -- no extra args
    check_include_file("ext2fs/ext2fs.h" HAVE_EXT2FS_EXT2FS_H)
    check_include_file("ext2fs/ext2_fs.h" HAVE_EXT2FS_EXT2_FS_H)
    if(HAVE_EXT2FS_EXT2FS_H)
        find_library(EXT2FS_LIB ext2fs)
        find_library(COM_ERR_LIB com_err)
        if(EXT2FS_LIB)
            set(HAVE_LIBEXT2FS 1)
        endif()
        if(COM_ERR_LIB)
            set(HAVE_LIBCOMM_ERR 1)
        endif()
    endif()
endif()

# libjpeg
if(WITH_JPEG)
    find_package(JPEG)
    if(JPEG_FOUND)
        set(HAVE_LIBJPEG 1)
        check_include_file("jpeglib.h" HAVE_JPEGLIB_H)
    endif()
endif()

# ntfs-3g
if(WITH_NTFS3G)
    find_library(NTFS3G_LIB ntfs-3g)
    check_include_file("ntfs-3g/attrib.h" HAVE_NTFS3G_ATTRIB_H)
    check_include_file("ntfs-3g/volume.h"  HAVE_NTFS3G_VOLUME_H)
    if(NTFS3G_LIB AND HAVE_NTFS3G_ATTRIB_H AND HAVE_NTFS3G_VOLUME_H)
        set(HAVE_LIBNTFS3G 1)
    endif()
endif()

# libewf
if(WITH_EWF)
    find_library(EWF_LIB ewf)
    check_include_file("libewf.h" HAVE_LIBEWF_H)
    if(EWF_LIB AND HAVE_LIBEWF_H)
        set(HAVE_LIBEWF 1)
    endif()
endif()

# zlib
if(WITH_ZLIB)
    find_package(ZLIB)
    if(ZLIB_FOUND)
        set(HAVE_LIBZ 1)
        check_include_file("zlib.h" HAVE_ZLIB_H)
    endif()
endif()

# uuid
if(WITH_UUID)
    find_library(UUID_LIB uuid)
    check_include_file("uuid/uuid.h" HAVE_UUID_UUID_H)
    if(UUID_LIB)
        set(HAVE_LIBUUID 1)
        set(CMAKE_REQUIRED_LIBRARIES ${UUID_LIB})
        check_function_exists(uuid_generate HAVE_UUID_GENERATE)
        check_function_exists(uuid_create   HAVE_UUID_CREATE)
        set(CMAKE_REQUIRED_LIBRARIES "")
    endif()
endif()

# iconv (usually built into glibc on Linux)
check_include_file("iconv.h" HAVE_ICONV_H)
check_function_exists(iconv HAVE_ICONV)

# Qt5 (optional -- for qphotorec)
if(WITH_QT)
    find_package(Qt5 COMPONENTS Widgets Gui QUIET)
    if(Qt5Widgets_FOUND)
        set(USE_QT TRUE)
        set(CMAKE_AUTOMOC ON)
        set(CMAKE_AUTORCC ON)
        message(STATUS "Qt5 found -- qphotorec will be built")
    else()
        message(STATUS "Qt5 not found -- qphotorec will not be built")
        set(USE_QT FALSE)
    endif()
endif()

# ── Common header checks ─────────────────────────────────────────────────────
foreach(_hdr
    byteswap.h dirent.h endian.h errno.h fcntl.h features.h glob.h
    iconv.h libgen.h limits.h locale.h malloc.h pwd.h setjmp.h
    signal.h stdarg.h sys/disk.h sys/ioctl.h sys/param.h
    sys/select.h sys/time.h sys/utsname.h time.h utime.h
    ncurses.h ncursesw/curses.h ncursesw/ncurses.h
    linux/fs.h linux/hdreg.h linux/types.h
    sys/sysmacros.h
)
    string(MAKE_C_IDENTIFIER "HAVE_${_hdr}" _varname)
    string(TOUPPER "${_varname}" _varname)
    check_include_file("${_hdr}" ${_varname})
endforeach()

# ── Function checks ───────────────────────────────────────────────────────────
foreach(_fn
    atexit atoll chdir chmod dirname dup2 execv fdatasync fseeko fsync
    ftello ftruncate getcwd geteuid getpwuid localtime_r lstat memalign
    memchr memset mkdir pread pwrite posix_fadvise posix_memalign
    readlink setenv setlocale sigaction signal sleep snprintf
    strcasecmp strcasestr strchr strdup strerror strncasecmp strptime
    strrchr strstr strtol strtoul strtoull uname utime vsnprintf wctomb
)
    string(TOUPPER "HAVE_${_fn}" _varname)
    check_function_exists(${_fn} ${_varname})
endforeach()

# ── Type / endian checks ──────────────────────────────────────────────────────
test_big_endian(_is_big_endian)
if(NOT _is_big_endian)
    set(TESTDISK_LSB 1)
endif()

check_type_size("off_t"  SIZEOF_OFF_T)
check_type_size("size_t" SIZEOF_SIZE_T)

# ── Compiler warning flags (shared across src/ and tests/) ───────────────────
# No -Werror: upstream code has many pre-existing warnings
set(TESTDISK_C_WARN_FLAGS
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wno-cast-align
    -Wno-unused-result
)

# ── Generate config.h ─────────────────────────────────────────────────────────
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
)

# ── Subdirectories ────────────────────────────────────────────────────────────
add_subdirectory(src)

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
