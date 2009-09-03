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
#ifdef HAVE_CYGWIN_VERSION_H
#include <cygwin/version.h>
#endif
#include "types.h"
#include "common.h"
#include "misc.h"

const char *get_os(void)
{
  static char 	buffer[100] = {0x00};
#ifdef WIN32
  {
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
	  (Ver.wProductType == VER_NT_WORKSTATION ? "WorkStation" : Server),
	  (int)Ver.dwMajorVersion, (int)Ver.dwMinorVersion, (int)Ver.dwBuildNumber);
    }

    if (Extended && Ver.wServicePackMajor != 0) {
      snprintf(buffer+strlen(buffer), sizeof(buffer) - 1 - strlen(buffer)," SP%i",Ver.wServicePackMajor);
    }
  }
#elif defined(DJGPP)
  snprintf(buffer, sizeof(buffer) - 1, "DOS");
#elif defined(HAVE_SYS_UTSNAME_H)
  {
    struct utsname	Ver;
    uname(&Ver);
    snprintf(buffer, sizeof(buffer) - 1, "%s, kernel %s (%s) %s", Ver.sysname, Ver.release, Ver.version, Ver.machine);
  }
#elif defined(__FreeBSD__)
  snprintf(buffer, sizeof(buffer) - 1, "FreeBSD");
#elif defined(__NetBSD__)
  snprintf(buffer, sizeof(buffer) - 1, "NetBSD");
#elif defined(__OpenBSD__)
  snprintf(buffer, sizeof(buffer) - 1, "OpenBSD");
#elif defined(__GNU__)
  snprintf(buffer, sizeof(buffer) - 1, "GNU/Hurd");
#elif defined(sun) || defined(__sun) || defined(__sun__)
#  ifdef __SVR4
  snprintf(buffer, sizeof(buffer) - 1, "Sun Solaris");
#  else
  snprintf(buffer, sizeof(buffer) - 1, "SunOS");
#  endif
#elif defined(hpux) || defined(__hpux) || defined(__hpux__)
  snprintf(buffer, sizeof(buffer) - 1, "HP-UX");
#elif defined(ultrix) || defined(__ultrix) || defined(__ultrix__)
  snprintf(buffer, sizeof(buffer) - 1, "DEC Ultrix");
#elif defined(sgi) || defined(__sgi)
  snprintf(buffer, sizeof(buffer) - 1, "SGI Irix");
#elif defined(__osf__)
  snprintf(buffer, sizeof(buffer) - 1, "OSF Unix");
#elif defined(bsdi) || defined(__bsdi__)
  snprintf(buffer, sizeof(buffer) - 1, "BSDI Unix");
#elif defined(_AIX)
  snprintf(buffer, sizeof(buffer) - 1, "AIX Unix");
#elif defined(_UNIXWARE)
  snprintf(buffer, sizeof(buffer) - 1, "SCO Unixware");
#elif defined(DGUX)
  snprintf(buffer, sizeof(buffer) - 1, "DG Unix");
#elif defined(__QNX__)
  snprintf(buffer, sizeof(buffer) - 1, "QNX");
#elif defined(__APPLE__)
  snprintf(buffer, sizeof(buffer) - 1, "Apple");
#elif defined(__OS2__)
  snprintf(buffer, sizeof(buffer) - 1, "OS2");
#else
  snprintf(buffer, sizeof(buffer) - 1, "unknown");
#endif
  return buffer;
}

const char *get_compiler(void)
{
  static char buffer[100] = {0x00};
#ifdef WIN32
#  ifdef _MSC_VER
  if (_MSC_VER == 1200) { /* ? */
    snprintf(buffer, sizeof(buffer) - 1, "MS VC 6.0");
  } else if (_MSC_VER == 1300) {
    snprintf(buffer, sizeof(buffer) - 1, "MS VC .NET 2002");
  } else if (_MSC_VER == 1310) {
    snprintf(buffer, sizeof(buffer) - 1, "MS VC .NET 2003");
  } else if (_MSC_VER == 1400) {
    snprintf(buffer, sizeof(buffer) - 1, "MS VC .NET 2005");
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
  snprintf(buffer, sizeof(buffer) - 1, "unknown compiler");
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
  snprintf(buffer, sizeof(buffer) - 1, "unknown compiler");
#endif
#ifdef __DATE__ 
  strcat(buffer, " - ");
  strcat(buffer, __DATE__);
#ifdef __TIME__
  strcat(buffer, " ");
  strcat(buffer, __TIME__);
#endif
#endif
  return buffer;
}
