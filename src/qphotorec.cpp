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
#include <QApplication>
#include <QLayoutItem>
#include <QLabel>
#include <QLayout>
#include "types.h"
#include "common.h"
#include "hdcache.h"
#include "hdaccess.h"
#include "fnctdsk.h"
#include "qphotorec.h"

QPhotorec::QPhotorec(QWidget *my_parent) : QWidget(my_parent)
{
  const int verbose=1;
  const int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  list_disk_t *element_disk;

  list_disk=hd_parse(NULL, verbose, testdisk_mode);

  hd_update_all_geometry(list_disk, verbose);
  /* Activate the cache, even if photorec has its own */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
  if(list_disk==NULL)
    no_disk();
  else
    disk_sel();
}

void QPhotorec::partition_selection(disk_t *disk)
{
  this->setWindowTitle(tr("QPhotoRec: partition selection"));
  QLabel *t_copy = new QLabel("PhotoRec 6.14-WIP, Data Recovery Utility, May 2012\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org");
  QPushButton *button_quit= new QPushButton("&Quit");

  clearWidgets();
  QLayout *mainLayout = this->layout();
  QLabel *t_disk = new QLabel(disk->description_short(disk));
  
  mainLayout->addWidget(t_copy);
  mainLayout->addWidget(t_disk);
  mainLayout->addWidget(button_quit);
  
  connect( button_quit, SIGNAL(clicked()), qApp, SLOT(quit()) );
}

void QPhotorec::disk_selected()
{
  if(HDDlistWidget->selectedItems().count()==1)
  {
    list_disk_t *element_disk;
    const QString& s = HDDlistWidget->selectedItems()[0]->text();
    for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    {
      disk_t *disk=element_disk->disk;
      if(QString(disk->description_short(disk)).compare(s)==0)
      {
	return partition_selection(disk);
      }
    }
  }
}

void QPhotorec::no_disk()
{
  this->setWindowTitle(tr("QPhotoRec"));
  QLabel *t_copy = new QLabel("PhotoRec 6.14-WIP, Data Recovery Utility, May 2012\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org");
  QLabel *t_free_soft = new QLabel("PhotoRec is free software, and\ncomes with ABSOLUTELY NO WARRANTY.");
  QLabel *t_no_disk = new QLabel("No harddisk found\n");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  t_no_disk->setText("No harddisk found\n"
      "You need to be administrator to use this program.\n"
      "Under Win9x, use the DOS version instead.\n"
      "Under Vista or later, select this program, right-click and choose \"Run as administrator\".\n");
#elif defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    t_no_disk->setText("No harddisk found\n"
	"You need to be root to use PhotoRec.");
  }
#endif
#endif
  QPushButton *button_quit= new QPushButton("&Quit");

  QVBoxLayout *mainLayout = new QVBoxLayout();
  mainLayout->addWidget(t_copy);
  mainLayout->addWidget(t_free_soft);
  mainLayout->addWidget(t_no_disk);
  mainLayout->addWidget(button_quit);
  this->setLayout(mainLayout);
  connect( button_quit, SIGNAL(clicked()), qApp, SLOT(quit()) );
}


void QPhotorec::disk_sel()
{
  list_disk_t *element_disk;
  this->setWindowTitle(tr("QPhotoRec"));
  QLabel *t_copy = new QLabel("PhotoRec 6.14-WIP, Data Recovery Utility, May 2012\nChristophe GRENIER <grenier@cgsecurity.org>\nhttp://www.cgsecurity.org");
  QLabel *t_free_soft = new QLabel("PhotoRec is free software, and\ncomes with ABSOLUTELY NO WARRANTY.");
  QLabel *t_select = new QLabel("Please select a media");

  HDDlistWidget = new QListWidget();
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
  {
    disk_t *disk=element_disk->disk;
    HDDlistWidget->addItem(disk->description_short(disk));
  }
  HDDlistWidget->setToolTip("Disk capacity must be correctly detected for a successful recovery.\n"
      "If a disk listed above has incorrect size, check HD jumper settings, BIOS\n"
      "detection, and install the latest OS patches and disk drivers."
  );

  QPushButton *button_proceed = new QPushButton("&Proceed");
  QPushButton *button_quit= new QPushButton("&Quit");

  QWidget *B_widget = new QWidget(this);
  QHBoxLayout *B_layout = new QHBoxLayout(B_widget);
  B_layout->addWidget(button_proceed);
  B_layout->addWidget(button_quit);
  B_widget->setLayout(B_layout);

  QVBoxLayout *mainLayout = new QVBoxLayout();
  //QLayout *mainLayout = this->layout();
  mainLayout->addWidget(t_copy);
  mainLayout->addWidget(t_free_soft);
  mainLayout->addWidget(t_select);
  mainLayout->addWidget(HDDlistWidget);
  mainLayout->addWidget(B_widget);
  this->setLayout(mainLayout);

  connect( button_quit, SIGNAL(clicked()), qApp, SLOT(quit()) );
  connect( button_proceed, SIGNAL(clicked()), this, SLOT(disk_selected()));
  connect( HDDlistWidget, SIGNAL(itemDoubleClicked(QListWidgetItem *)), this, SLOT(disk_selected()));
}

void QPhotorec::clearWidgets()
{
  while(1)
  {
    QLayoutItem *layoutwidget;
    layoutwidget = this->layout()->takeAt(0);
    if(layoutwidget==NULL)
      return ;
    layoutwidget->widget()->deleteLater();
  }
}
