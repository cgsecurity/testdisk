/*

    File: misc.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_WINDOWS_H
#  include <windows.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_CYGWIN_VERSION_H
#include <cygwin/version.h>
#endif
#include "types.h"
#include "common.h"
#include "misc.h"

const char *get_os(void)
{
#ifdef WIN32
  {
    static char buffer[100] = {0x00};
    /* For more information, read
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getting_the_system_version.asp
    */
    OSVERSIONINFOEX Ver;
    int Extended = 1;
    memset(&Ver,0,sizeof(OSVERSIONINFOEX));
    Ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionEx((OSVERSIONINFO *)&Ver)) {
      Extended 		= 0;
      Ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      if (!GetVersionEx((OSVERSIONINFO *)&Ver)) {
	snprintf(buffer, sizeof(buffer) - 1, "Windows");
	return buffer;
      }
    }

    /* ----------------- 9x/NT4 family ------------------ */

    if (Ver.dwMajorVersion == 4 && Ver.dwMinorVersion == 0)
    {
      /* no info about Win95 SP1, Win95 OSR2.1, Win95 OSR2.5.... */
      if(Ver.dwBuildNumber == 950)
	snprintf(buffer, sizeof(buffer) - 1, "Windows 95");
      else if (Ver.dwBuildNumber == 1111)
	snprintf(buffer, sizeof(buffer) - 1, "Windows 95 OSR2.x");
      else if(Ver.dwBuildNumber == 1381)
	snprintf(buffer, sizeof(buffer) - 1, "Windows NT 4.0");
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows 95 or NT 4.0 (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 4 && Ver.dwMinorVersion == 10)
    {
      /* no info about Win98 SP1.... */
      if(Ver.dwBuildNumber == 1998)
	snprintf(buffer, sizeof(buffer) - 1, "Windows 98");
      else if (Ver.dwBuildNumber == 2222)
	snprintf(buffer, sizeof(buffer) - 1, "Windows 98 SE");
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows 98 (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 4 && Ver.dwMinorVersion == 90)
    {
      if(Ver.dwBuildNumber == 3000)
	snprintf(buffer, sizeof(buffer) - 1, "Windows ME");
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows ME (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 5 && Ver.dwMinorVersion == 0)
    {
      if(Ver.dwBuildNumber == 2195)
	snprintf(buffer, sizeof(buffer) - 1, "Windows 2000");
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows 2000 (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 5 && Ver.dwMinorVersion == 1)
    {
      if(Ver.dwBuildNumber == 2600)
      {
	snprintf(buffer, sizeof(buffer) - 1, "Windows XP");
#if defined(_MSC_VER) && _MSC_VER > 1200 /* 6.0 has it undeclared */
	if (Extended) {
	  if (Ver.wSuiteMask & VER_SUITE_PERSONAL) {
	    snprintf(buffer+strlen(buffer), sizeof(buffer) - 1 - strlen(buffer)," Home");
	  } else {
	    snprintf(buffer+strlen(buffer), sizeof(buffer) - 1 - strlen(buffer)," Pro");
	  }
	}
#endif
      }
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows XP (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 5 && Ver.dwMinorVersion == 2)
    {
      snprintf(buffer, sizeof(buffer) - 1, "Windows 2003 (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 6 && Ver.dwMinorVersion == 0)
    {
       if( Ver.wProductType == VER_NT_WORKSTATION )
	 snprintf(buffer, sizeof(buffer) - 1, "Windows Vista (%lu)", Ver.dwBuildNumber);
       else
	 snprintf(buffer, sizeof(buffer) - 1, "Windows Server 2008 (%lu)", Ver.dwBuildNumber);
    }
    else if (Ver.dwMajorVersion == 6 && Ver.dwMinorVersion == 1)
    {
      if( Ver.wProductType == VER_NT_WORKSTATION )
	snprintf(buffer, sizeof(buffer) - 1, "Windows 7 (%lu)", Ver.dwBuildNumber);
      else
	snprintf(buffer, sizeof(buffer) - 1, "Windows Server 2008 R2 (%lu)", Ver.dwBuildNumber);
    }
    else
    {
      snprintf(buffer, sizeof(buffer) - 1, "Windows %s %i.%i.%i",
	  (Ver.wProductType == VER_NT_WORKSTATION ? "WorkStation" : "Server"),
	  (int)Ver.dwMajorVersion, (int)Ver.dwMinorVersion, (int)Ver.dwBuildNumber);
    }

    if (Extended && Ver.wServicePackMajor != 0) {
      snprintf(buffer+strlen(buffer), sizeof(buffer) - 1 - strlen(buffer)," SP%i",Ver.wServicePackMajor);
    }
    return buffer;
  }
#elif defined(DJGPP)
  return "DOS";
#elif defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
  {
    struct utsname Ver;
    if(uname(&Ver)==0)
    {
      static char buffer[100] = {0x00};
      snprintf(buffer, sizeof(buffer) - 1, "%s, kernel %s (%s) %s",
	  Ver.sysname, Ver.release, Ver.version, Ver.machine);
      return buffer;
    }
  }
#endif
#if defined(__FreeBSD__)
  return "FreeBSD";
#elif defined(__NetBSD__)
  return "NetBSD";
#elif defined(__OpenBSD__)
  return "BSD";
#elif defined(__GNU__)
  return "GNU/Hurd";
#elif defined(sun) || defined(__sun) || defined(__sun__)
#  ifdef __SVR4
  return "Sun Solaris";
#  else
  return "SunOS";
#  endif
#elif defined(hpux) || defined(__hpux) || defined(__hpux__)
  return "HP-UX";
#elif defined(ultrix) || defined(__ultrix) || defined(__ultrix__)
  return "DEC Ultrix";
#elif defined(sgi) || defined(__sgi)
  return "SGI Irix";
#elif defined(__osf__)
  return "OSF Unix";
#elif defined(bsdi) || defined(__bsdi__)
  return "BSDI Unix";
#elif defined(_AIX)
  return "AIX Unix";
#elif defined(_UNIXWARE)
  return "SCO Unixware";
#elif defined(DGUX)
  return "DG Unix";
#elif defined(__QNX__)
  return "QNX";
#elif defined(__APPLE__)
  return "Apple";
#elif defined(__OS2__)
  return "OS2";
#else
  return "unknown";
#endif
}

const char *get_compiler(void)
{
  static char buffer[100] = {0x00};
#ifdef WIN32
#  ifdef _MSC_VER
  if (_MSC_VER == 1200) { /* ? */
    return "MS VC 6.0";
  } else if (_MSC_VER == 1300) {
    return "MS VC .NET 2002";
  } else if (_MSC_VER == 1310) {
    return "MS VC .NET 2003";
  } else if (_MSC_VER == 1400) {
    return "MS VC .NET 2005";
  } else {
    snprintf(buffer, sizeof(buffer) - 1, "MS VC %i",_MSC_VER);
  }
#  elif defined(__BORLANDC__)
  snprintf(buffer, sizeof(buffer) - 1, "Borland C++ %i",__BORLANDC__);
#  elif defined(__MINGW32__)
  snprintf(buffer, sizeof(buffer) - 1, "GCC %i.%i, MinGW %i.%i", __GNUC__, __GNUC_MINOR__, __MINGW32_MAJOR_VERSION, __MINGW32_MINOR_VERSION);
#  elif defined(__CYGWIN__)
#if defined(CYGWIN_VERSION_DLL_MAJOR) && defined(CYGWIN_VERSION_DLL_MINOR)
  snprintf(buffer, sizeof(buffer) - 1, "GCC %i.%i, Cygwin %i.%i", __GNUC__, __GNUC_MINOR__, CYGWIN_VERSION_DLL_MAJOR, CYGWIN_VERSION_DLL_MINOR);
#else
  snprintf(buffer, sizeof(buffer) - 1, "GCC %i.%i, Cygwin", __GNUC__, __GNUC_MINOR__);
#endif
#  elif defined(__GNUC__)
  snprintf(buffer, sizeof(buffer) - 1, "GCC %i.%i", __GNUC__, __GNUC_MINOR__);
#  else
  return "unknown compiler";
#  endif
#elif defined(DJGPP)
  snprintf(buffer, sizeof(buffer) - 1, "djgpp %d.%d", __DJGPP, __DJGPP_MINOR);
#elif defined(__GNUC__)
  snprintf(buffer, sizeof(buffer) - 1, "GCC %i.%i", __GNUC__, __GNUC_MINOR__);
#elif defined(__SUNPRO_CC)
  snprintf(buffer, sizeof(buffer) - 1, "Sun C++ %x", __SUNPRO_CC);
#elif defined(__INTEL_COMPILER)
  snprintf(buffer, sizeof(buffer) - 1, "Intel Compiler %ld", __INTEL_COMPILER);
#else
  return "unknown compiler";
#endif
  return buffer;
}

const char *get_compilation_date(void)
{
  static char buffer[100] = {0x00};
#ifdef __DATE__ 
#ifdef HAVE_STRPTIME
  struct tm tm;
  memset(&tm,0,sizeof(tm));
  if(strptime(__DATE__, "%b %d %Y", &tm)!=NULL)
    sprintf(buffer, "%4d-%02d-%02dT", tm.tm_year + 1900, tm.tm_mon+1, tm.tm_mday);
  else
    strcpy(buffer, __DATE__);
#ifdef __TIME__
  strcat(buffer, __TIME__);
#endif
#else
  strcpy(buffer, __DATE__);
#ifdef __TIME__
  strcat(buffer, " ");
  strcat(buffer, __TIME__);
#endif
#endif
#endif
  return buffer;
}
