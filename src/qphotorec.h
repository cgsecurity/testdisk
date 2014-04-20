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
#include <stdio.h>
#include <QWidget>
#include <QListWidget>
#include <QComboBox>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QRadioButton>
#include <QProgressBar>
#include "types.h"
#include "common.h"
#include "filegen.h"
#include "photorec.h"

class QPhotorec: public QWidget
{
  	Q_OBJECT

        public:
                QPhotorec(QWidget *parent = 0);
		~QPhotorec();
        private slots:
		/* Setup recovery UI */
	  	void disk_changed(int index);
		void partition_selected();
		void setExistingDirectory();
		void newSourceFile();
		void qphotorec_about();
		void qphotorec_formats();
		void qphotorec_search();
		void buttons_updateUI();
		/* Recovery UI */
		void qphotorec_search_updateUI();
		void stop_and_quit();
		/* Formats */
		void formats_reset();
		void formats_restore();
	protected:
                void setupUI();
		void clearWidgets();
                int no_disk_warning();
		QWidget *copyright(QWidget * qwparent = 0);
		QTableWidgetItem *offset_to_item(const disk_t *disk, const uint64_t offset);
		void PartListWidget_updateUI();
		void HDDlistWidget_updateUI();
		int photorec(alloc_data_t *list_search_space);
		pstatus_t photorec_find_blocksize(alloc_data_t *list_search_space);
		pstatus_t photorec_aux(alloc_data_t *list_search_space);
		void qphotorec_search_setupUI();
		void photorec_info(const file_stat_t *file_stats);
		void select_disk(disk_t *disk);
	signals:
		void finished();
        private:
		/* */
		list_disk_t		*list_disk;
		disk_t      		*selected_disk;
		list_part_t 		*list_part;
		partition_t 		*selected_partition;
		struct ph_param 	*params;
		struct ph_options 	*options;
		bool			stop_the_recovery;
		/* Setup recovery UI */
                QComboBox 		*HDDlistWidget;
                QTableWidget 		*PartListWidget;
		QLineEdit 		*directoryLabel;
		QPushButton 		*button_search;
		QRadioButton 		*qextRadioButton;
		QRadioButton 		*qfatRadioButton;
		QRadioButton 		*qfreeRadioButton;
		QRadioButton 		*qwholeRadioButton;
		/* Recovery UI */
		QLabel			*folder_txt;
		QLabel 			*progress_info;
		QLabel 			*progress_filefound;
		QProgressBar 		*progress_bar;
		QTimer 			*timer;
                QTableWidget 		*filestatsWidget;
		/* Formats */
		QListWidget		*formats;

};
#endif
