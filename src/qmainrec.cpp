#include <QApplication>
#include "qphotorec.h"

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QPhotorec *p = new QPhotorec();
	p->showMaximized();
	p->show();
	return a.exec();
}
