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
#include "common.h"
#include "hdcache.h"
#include "hdaccess.h"
#include "fnctdsk.h"

extern const arch_fnct_t arch_i386;

QPhotorec::QPhotorec()
{
	editor = new QListWidget();
	btn = new QPushButton();
	QVBoxLayout *mainLayout = new QVBoxLayout();
	mainLayout->addWidget(editor);
	mainLayout->addWidget(btn);
	setLayout(mainLayout);
	setWindowTitle(tr("QPhotorec"));
	show();

}

void QPhotorec::show()
{
	int verbose=1;
	const arch_fnct_t *arch=&arch_i386;
	int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
	list_disk_t *list_disk=NULL;
	list_disk_t *element_disk;

	if(list_disk==NULL)
	    list_disk=hd_parse(list_disk,verbose,arch,testdisk_mode);

	hd_update_all_geometry(list_disk,0,verbose);
	/* Activate the cache, even if photorec has its own */
	for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
	        element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
	/* save disk parameters to rapport */
	int i = 0;
	for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
	{
		disk_t *disk=element_disk->disk;
		if(disk->model==NULL)
			//log_info("%s, sector size=%u\n", disk->description(disk), disk->sector_size);
			editor->insertItem(i, QString("%s, sector size=%u").arg(disk->description(disk)).arg(disk->sector_size));
		else
			//log_info("%s, sector size=%u - %s\n", disk->description(disk), disk->sector_size, disk->model);
			editor->insertItem(i, QString("%s, sector size=%u - %s").arg(disk->description(disk)).arg(disk->sector_size).arg(disk->model));
			i++;
	}

}
