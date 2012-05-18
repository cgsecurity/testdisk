#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* unlink, ftruncate */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <ctype.h>      /* tolower */
#ifdef HAVE_LOCALE_H
#include <locale.h>	/* setlocale */
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <QtGui>
#include "qphotorec.h"
#include "types.h"
#include "common.h"
#include "hdcache.h"
#include "hdaccess.h"
#include "fnctdsk.h"

QPhotorec::QPhotorec(QWidget *parent)
{
  setupUi(this);
}

void QPhotorec::setupUi(QWidget *MainWindow)
{
  MainWindow->setWindowTitle(tr("QPhotorec"));
  HDDlistWidget = new QListWidget();
  QVBoxLayout *mainLayout = new QVBoxLayout();
  mainLayout->addWidget(HDDlistWidget);
  QPushButton *button_next = new QPushButton("&Proceed");
  mainLayout->addWidget(button_next);
  QPushButton *button_quit= new QPushButton("&Quit");
  mainLayout->addWidget(button_quit);
  MainWindow->setLayout(mainLayout);
  ashow();
}

void QPhotorec::ashow()
{
  int verbose=1;
  int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  list_disk_t *list_disk=NULL;
  list_disk_t *element_disk;

  list_disk=hd_parse(list_disk, verbose, testdisk_mode);

  hd_update_all_geometry(list_disk, verbose);
  /* Activate the cache, even if photorec has its own */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
  /* save disk parameters to rapport */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    HDDlistWidget->addItem(disk->description_short(disk));
  }
}
