#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
 
#ifdef DISABLED_FOR_FRAMAC
#undef HAVE_LIBJPEG
#endif

#if defined(HAVE_LIBJPEG) && defined(HAVE_JPEGLIB_H)
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <jpeglib.h>
#include "suspend.h"

void suspend_memory(j_common_ptr cinfo) {
};

int resume_memory(j_common_ptr cinfo)
{
  /* Can't resume */
  return -1;
};
#endif
