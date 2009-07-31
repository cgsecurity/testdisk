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
#include <QDialog>
class QListWidget;
class QPushButton;

class QPhotorec: public QWidget
{
        public:
                QPhotorec(QWidget *parent = 0);
		void setupUi(QWidget *MainWindow);
                void ashow();
        private:
                QListWidget *HDDlistWidget;
                QPushButton *btn;
};
#endif
