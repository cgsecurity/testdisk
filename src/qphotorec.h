//
// C++ Interface: qphotorec
//
// Description: 
//
//
// Author: TestDisk and PhotoRec are written and maintained by Christophe GRENIER <grenier@cgsecurity.org>, (C) 2008
//
// Copyright: See COPYING file that comes with this distribution
//
//
#ifndef QPHOTOREC_H
#define QPHOTOREC_H
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <QWidget>
#include <QListWidget>
#include <QPushButton>
#include "types.h"
#include "common.h"

class QPhotorec: public QWidget
{
  	Q_OBJECT

        public:
                QPhotorec(QWidget *parent = 0);
                void disk_sel();
                void no_disk();
		void partition_selection(disk_t *disk);
        private slots:
		void disk_selected();
        private:
                QListWidget *HDDlistWidget;
                QPushButton *btn;
		list_disk_t *list_disk;
};
#endif
