/*

    File: qphotorec.cpp

    Copyright (C) 2009-2014 Christophe GRENIER <grenier@cgsecurity.org>

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
#include <QTableView>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QDialogButtonBox>
#include <QSortFilterProxyModel>
#include <QGroupBox>
#include <QRadioButton>
#include <QFileDialog>
#include <QComboBox>
#include <QTimer>
#include <QMessageBox>
#include <QTextDocument>
#include "types.h"
#include "common.h"
#include "hdcache.h"
#include "hdaccess.h"
#include "fnctdsk.h"
#include "filegen.h"
#include "sessionp.h"
#include "intrf.h"
#include "partauto.h"
#include "phcfg.h"
#include "log.h"
#include "log_part.h"
#include "qphotorec.h"

extern const arch_fnct_t arch_none;
extern file_enable_t list_file_enable[];

QPhotorec::QPhotorec(QWidget *my_parent) : QWidget(my_parent)
{
  const int verbose=1;
  const int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  list_disk_t *element_disk;

  list_disk=NULL;
  selected_disk=NULL;
  list_part=NULL;
  selected_partition=NULL;

  params=(struct ph_param *)MALLOC(sizeof(*params));
  params->recup_dir=NULL;
  params->cmd_device=NULL;
  params->cmd_run=NULL;
  params->carve_free_space_only=1;
  params->disk=NULL;
  params->partition=NULL;

  options=(struct ph_options *)MALLOC(sizeof(*options));
  options->paranoid=1;
  options->keep_corrupted_file=0;
  options->mode_ext2=0;
  options->expert=0;
  options->lowmem=0;
  options->verbose=0;
  options->list_file_format=list_file_enable;
  reset_list_file_enable(options->list_file_format);

  stop_the_recovery=false;

  setWindowIcon( QPixmap( ":res/photorec_64x64.png" ) );
  this->setWindowTitle(tr("QPhotoRec"));
  QVBoxLayout *mainLayout = new QVBoxLayout();
  this->setLayout(mainLayout);

  list_disk=hd_parse(NULL, verbose, testdisk_mode);

  hd_update_all_geometry(list_disk, verbose);
  /* Activate the cache, even if photorec has its own */
  for(element_disk=list_disk;element_disk!=NULL;element_disk=element_disk->next)
    element_disk->disk=new_diskcache(element_disk->disk,testdisk_mode);
  if(list_disk==NULL)
  {
    no_disk_warning();
  }
  else
    select_disk(list_disk->disk);
  setupUI();
}

QPhotorec::~QPhotorec()
{
//  session_save(list_search_space, params, options);
  part_free_list(list_part);
  delete_list_disk(list_disk);
  free(options);
  free(params);
}

void QPhotorec::setExistingDirectory()
{
  QString directory = QFileDialog::getExistingDirectory(this,
      "Please select a destination to save the recovered files.",
      directoryLabel->text(),
      QFileDialog::ShowDirsOnly);
  if (!directory.isEmpty())
  {
    directoryLabel->setText(directory);
    buttons_updateUI();
  }
}

void QPhotorec::newSourceFile()
{
  const int testdisk_mode=TESTDISK_O_RDONLY|TESTDISK_O_READAHEAD_32K;
  QString filename = QFileDialog::getOpenFileName(this,
      "Please select a raw file",
      "",
      "Raw Files (*.dd *.raw *.img)");
  if(!filename.isEmpty())
  {
    disk_t *new_disk=NULL;
    QByteArray filenameArray= (filename).toUtf8();
    list_disk=insert_new_disk_aux(list_disk, file_test_availability(filenameArray.constData(), options->verbose, testdisk_mode), &new_disk);
    if(new_disk!=NULL)
    {
      select_disk(new_disk);
      HDDlistWidget_updateUI();
      PartListWidget_updateUI();
    }
  }
}

void QPhotorec::partition_selected()
{
  if(PartListWidget->selectedItems().count()<=0)
    return;
  list_part_t *tmp;
  const QString& s = PartListWidget->selectedItems()[0]->text();
  if(s.compare("")==0)
  {
    const QString& s2 = PartListWidget->selectedItems()[2]->text();
    for(tmp=list_part; tmp!=NULL; tmp=tmp->next)
    {
      partition_t *part=tmp->part;
      if(part->order==NO_ORDER && s2.compare(arch_none.get_partition_typename(part))==0)
      {
	selected_partition=part;
	buttons_updateUI();
	return ;
      }
    }
    if(list_part!=NULL)
    {
      selected_partition=list_part->part;
      buttons_updateUI();
      return ;
    }
    return ;
  }
  for(tmp=list_part; tmp!=NULL; tmp=tmp->next)
  {
    partition_t *part=tmp->part;
    if(QString::number(part->order).compare(s)==0)
    {
      selected_partition=part;
      buttons_updateUI();
      return ;
    }
  }
}

void QPhotorec::PartListWidget_updateUI()
{
  list_part_t *element;
  PartListWidget->setRowCount(0);
  PartListWidget->setSortingEnabled(false);
  for(element=list_part; element!=NULL; element=element->next)
  {
    const partition_t *partition=element->part;
    if(partition->status!=STATUS_EXT_IN_EXT)
    {
      const arch_fnct_t *arch=partition->arch;
      const int currentRow = PartListWidget->rowCount();
      PartListWidget->setRowCount(currentRow + 1);
      if(partition->order==NO_ORDER)
      {
	QTableWidgetItem *item = new QTableWidgetItem();
	item->setData(0, "");
	PartListWidget->setItem(currentRow, 0, item);
      }
      else
      {
	QTableWidgetItem *item = new QTableWidgetItem();
	item->setData(0, partition->order);
	PartListWidget->setItem(currentRow, 0, item);
      }
      {
	QTableWidgetItem *item=new QTableWidgetItem(QString(get_partition_status(partition)));
	item->setTextAlignment(Qt::AlignHCenter| Qt::AlignVCenter);
	PartListWidget->setItem(currentRow, 1, item);
      }
      if(arch->get_partition_typename(partition)!=NULL)
	PartListWidget->setItem(currentRow, 2, new QTableWidgetItem(QString(arch->get_partition_typename(partition))));
      else if(arch->get_part_type)
	PartListWidget->setItem(currentRow, 2, new QTableWidgetItem("Sys=" + QString::number(arch->get_part_type(partition))));
      else
	PartListWidget->setItem(currentRow, 2, new QTableWidgetItem("Unknown"));
      if(partition->upart_type>0)
      {
	QTableWidgetItem *item=new QTableWidgetItem(QString(arch_none.get_partition_typename(partition)));
	item->setToolTip(QString(partition->info));
	PartListWidget->setItem(currentRow, 3, item);
      }
      else
      {
	PartListWidget->setItem(currentRow, 3, new QTableWidgetItem(""));
      }
      {
	char sizeinfo[32];
	QTableWidgetItem *item;
	size_to_unit(partition->part_size, &sizeinfo[0]);
	item=new QTableWidgetItem(QString(sizeinfo));
	item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
	PartListWidget->setItem(currentRow, 4, item);
	/* Select the partition if it's already known */
	if(selected_partition == partition)
	  PartListWidget->setCurrentItem(item);
      }
      {
	QString partname="";
	if(partition->partname[0]!='\0')
	{
	  partname.sprintf("[%s]", partition->partname);
	}
	if(partition->fsname[0]!='\0')
	{
	  QString fsname;
	  fsname.sprintf(" [%s]", partition->fsname);
	  partname.append(fsname);
	}
	PartListWidget->setItem(currentRow, 5, new QTableWidgetItem(partname));
      }
    }
  }
  PartListWidget->setSortingEnabled(true);
  PartListWidget->sortByColumn(0, Qt::AscendingOrder);
  PartListWidget->resizeColumnsToContents();
}

void QPhotorec::select_disk(disk_t *disk)
{
  if(disk==NULL)
    return ;
  selected_disk=disk;
  selected_partition=NULL;
  autodetect_arch(selected_disk, &arch_none);
  log_info("%s\n", selected_disk->description_short(selected_disk));
  part_free_list(list_part);
  list_part=init_list_part(selected_disk, NULL);
  /* If only whole disk is listed, select it */
  /* If there is the whole disk and only one partition, select the partition */
  if(list_part!=NULL)
  {
    if(list_part->next==NULL)
      selected_partition=list_part->part;
    else if(list_part->next->next==NULL)
      selected_partition=list_part->next->part;
  }
  log_all_partitions(selected_disk, list_part);
}

void QPhotorec::disk_changed(int index)
{
  int i;
  list_disk_t *element_disk;
  for(element_disk=list_disk, i=0;
      element_disk!=NULL;
      element_disk=element_disk->next, i++)
  {
    if(i==index)
    {
      select_disk(element_disk->disk);
      PartListWidget_updateUI();
      return;
    }
  }
  if(i==index)
  {
    newSourceFile();
  }
}

QWidget *QPhotorec::copyright(QWidget * qwparent)
{
  QWidget *C_widget = new QWidget(qwparent);
  QLabel *t_logo=new QLabel(C_widget);
  QPixmap pixmap_img = QPixmap(":res/photorec_64x64.png");
  t_logo->setPixmap(pixmap_img);

  QSizePolicy c_sizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);
  t_logo->setSizePolicy(c_sizePolicy);

  QLabel *t_copy=new QLabel(C_widget);

  t_copy->setText( "PhotoRec " + QString(VERSION) + ", Data Recovery Utility, " + QString(TESTDISKDATE) + "<br>\nCopyright (C) Christophe GRENIER &lt;<a href=\"mailto:grenier@cgsecurity.org\">grenier@cgsecurity.org</a>&gt;<br>\n<a href=\"http://www.cgsecurity.org/\">http://www.cgsecurity.org</a>");
  t_copy->setTextFormat(Qt::RichText);
  t_copy->setTextInteractionFlags(Qt::TextBrowserInteraction);
  t_copy->setOpenExternalLinks(true);

  QHBoxLayout *C_layout = new QHBoxLayout(C_widget);
  C_layout->addStretch(1);
  C_layout->addWidget(t_logo);
  C_layout->addWidget(t_copy);
  C_layout->addStretch(1);
  C_widget->setLayout(C_layout);
  return C_widget;
}

/* TODO replace by a warning */
int QPhotorec::no_disk_warning()
{
  const char *msg;
  msg="No harddisk found";
#if defined(__CYGWIN__) || defined(__MINGW32__)
  msg="No harddisk found\n"
    "You need to be administrator to use this program.\n"
    "Under Win9x, use the DOS version instead.\n"
    "Under Vista or later, select this program, right-click and choose \"Run as administrator\".";
#elif defined(DJGPP)
#else
#ifdef HAVE_GETEUID
  if(geteuid()!=0)
  {
    msg="No harddisk found\n"
      "You need to be root to use PhotoRec.";
  }
#endif
#endif
  return QMessageBox::warning(this,"No Disk!", msg, QMessageBox::Ok);
}

void QPhotorec::buttons_updateUI()
{
  if(selected_disk==NULL || selected_partition==NULL)
  {
    button_search->setEnabled(false);
    qwholeRadioButton->setChecked(true);
    qfreeRadioButton->setEnabled(false);
    return ;
  }
  if(selected_partition->upart_type==UP_EXT2 || selected_partition->upart_type==UP_EXT3 || selected_partition->upart_type==UP_EXT4)
    qextRadioButton->setChecked(true);
  else
    qfatRadioButton->setChecked(true);
  switch(selected_partition->upart_type)
  {
    case UP_EXFAT:
    case UP_FAT12:
    case UP_FAT16:
    case UP_FAT32:
#if defined(HAVE_LIBNTFS) || defined(HAVE_LIBNTFS3G)
    case UP_NTFS:
#endif
#ifdef HAVE_LIBEXT2FS
    case UP_EXT2:
    case UP_EXT3:
    case UP_EXT4:
#endif
      qfreeRadioButton->setEnabled(true);
      qfreeRadioButton->setChecked(true);
      break;
    default:
      qwholeRadioButton->setChecked(true);
      qfreeRadioButton->setEnabled(false);
      break;
  }
  button_search->setEnabled(!directoryLabel->text().isEmpty());
}

void QPhotorec::HDDlistWidget_updateUI()
{
  list_disk_t *element_disk;
  int i;
  HDDlistWidget->clear();
  for(element_disk=list_disk, i=0;
      element_disk!=NULL;
      element_disk=element_disk->next, i++)
  {
    disk_t *disk=element_disk->disk;
    HDDlistWidget->addItem(
	QIcon::fromTheme("drive-harddisk", QIcon(":res/gnome/drive-harddisk.png")),
	disk->description_short(disk));
    if(disk==selected_disk)
      HDDlistWidget->setCurrentIndex(i);
  }
  HDDlistWidget->addItem(
      QIcon::fromTheme("application-x-cd-image", QIcon(":res/gnome/application-x-cd-image.png")),
      "Add a raw disk image...");
}

void QPhotorec::setupUI()
{
  QWidget *t_copy = copyright(this);
  QLabel *t_free_soft = new QLabel("PhotoRec is free software, and comes with ABSOLUTELY NO WARRANTY.");
  QLabel *t_select = new QLabel("Please select a media to recover from");

  HDDlistWidget = new QComboBox();
  HDDlistWidget->setToolTip("Disk capacity must be correctly detected for a successful recovery.\n"
      "If a disk listed above has incorrect size, check HD jumper settings, BIOS\n"
      "detection, and install the latest OS patches and disk drivers."
  );

  QStringList oLabel;
  oLabel.append("");
  oLabel.append("Flags");
  oLabel.append("Type");
  oLabel.append("File System");
  oLabel.append("Size");
  oLabel.append("Label");

  PartListWidget= new QTableWidget();
  PartListWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
  PartListWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
  PartListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
  PartListWidget->verticalHeader()->hide();
  PartListWidget->setShowGrid(false);
  PartListWidget->setColumnCount( 6 );
  PartListWidget->setHorizontalHeaderLabels( oLabel );
  PartListWidget_updateUI();

  QGroupBox *groupBox1;
  QGroupBox *groupBox2;

  groupBox1 = new QGroupBox("File System type");
  qextRadioButton = new QRadioButton("ext2/ext3/ext4 filesystem");
  qfatRadioButton = new QRadioButton("FAT/NTFS/HFS+/ReiserFS/...");
  qfatRadioButton->setChecked(true);

  groupBox2 = new QGroupBox();
  qfreeRadioButton = new QRadioButton("Free: Scan for file from unallocated space only");
  qwholeRadioButton = new QRadioButton("Whole: Extract files from whole partition");
  qfreeRadioButton->setEnabled(false);
  qwholeRadioButton->setChecked(true);


  QVBoxLayout *groupBox1Layout = new QVBoxLayout;
  QVBoxLayout *groupBox2Layout = new QVBoxLayout;

  groupBox1Layout->addWidget(qextRadioButton);
  groupBox1Layout->addWidget(qfatRadioButton);
  groupBox1->setLayout(groupBox1Layout);

  groupBox2Layout->addWidget(qfreeRadioButton);
  groupBox2Layout->addWidget(qwholeRadioButton);
  groupBox2->setLayout(groupBox2Layout);

  QWidget *groupBox= new QWidget();
  QHBoxLayout *groupBoxLayout = new QHBoxLayout;
  groupBoxLayout->addWidget(groupBox1);
  groupBoxLayout->addWidget(groupBox2);
  groupBox->setLayout(groupBoxLayout);


  QLabel *dstWidget= new QLabel("Please select a destination to save the recovered files.");
  directoryLabel=new QLineEdit("");
  QPushButton *dst_button = new QPushButton(
      QIcon::fromTheme("folder", QIcon(":res/gnome/folder.png")),
      "&Browse");

  QWidget *dst_widget= new QWidget(this);
  QWidget *dst_widget2= new QWidget(this);

  QHBoxLayout *dst_widgetLayout2 = new QHBoxLayout;
  dst_widgetLayout2->addWidget(directoryLabel);
  dst_widgetLayout2->addWidget(dst_button);
  dst_widget2->setLayout(dst_widgetLayout2);

  QVBoxLayout *dst_widgetLayout = new QVBoxLayout;
  dst_widgetLayout->addWidget(dstWidget);
  dst_widgetLayout->addWidget(dst_widget2);
  dst_widget->setLayout(dst_widgetLayout);
  

  button_search = new QPushButton(QIcon::fromTheme("go-next", QIcon(":res/gnome/go-next.png")), "&Search");
  button_search->setEnabled(false);
  QPushButton *button_quit= new QPushButton(QIcon::fromTheme("application-exit", QIcon(":res/gnome/application-exit.png")), "&Quit");
  QPushButton *button_about= new QPushButton(QIcon::fromTheme("help-about", QIcon(":res/gnome/help-about.png")), "&About");
  QPushButton *button_formats= new QPushButton(QIcon::fromTheme("image-x-generic.png", QIcon(":res/gnome/image-x-generic.png")),"&File Formats");

  QWidget *B_widget = new QWidget(this);
  QHBoxLayout *B_layout = new QHBoxLayout(B_widget);
  B_layout->addWidget(button_about);
  B_layout->addWidget(button_formats);
  B_layout->addWidget(button_search);
  B_layout->addWidget(button_quit);
  B_widget->setLayout(B_layout);

  clearWidgets();
//  QLayout *mainLayout = this->layout();
  delete this->layout();
  QVBoxLayout *mainLayout = new QVBoxLayout();
  mainLayout->addWidget(t_copy);
  mainLayout->addWidget(t_free_soft);
  mainLayout->addWidget(t_select);
  mainLayout->addWidget(HDDlistWidget);
  mainLayout->addWidget(PartListWidget);
  mainLayout->addWidget(groupBox);
  mainLayout->addWidget(dst_widget);
  mainLayout->addWidget(B_widget);
  this->setLayout(mainLayout);

  HDDlistWidget_updateUI();
  buttons_updateUI();

  connect(button_about, SIGNAL(clicked()), this, SLOT(qphotorec_about()) );
  connect(button_formats, SIGNAL(clicked()), this, SLOT(qphotorec_formats()) );
  connect(button_search, SIGNAL(clicked()), this, SLOT(qphotorec_search()) );
  connect(button_quit, SIGNAL(clicked()), qApp, SLOT(quit()) );
  connect(HDDlistWidget, SIGNAL(activated(int)),this,SLOT(disk_changed(int)));
  connect(PartListWidget, SIGNAL(itemSelectionChanged()), this, SLOT(partition_selected()));
  connect(dst_button, SIGNAL(clicked()), this, SLOT(setExistingDirectory()));
  connect(directoryLabel, SIGNAL(editingFinished()), this, SLOT(buttons_updateUI()));
}

void QPhotorec::clearWidgets()
{
  while(1)
  {
    QLayoutItem *layoutwidget;
    layoutwidget = this->layout()->takeAt(0);
    if(layoutwidget==NULL)
      return ;
    layoutwidget->widget()->hide();
    layoutwidget->widget()->deleteLater();
  }
}

void QPhotorec::photorec_info(const file_stat_t *file_stats)
{
  unsigned int i;
  unsigned int nbr;
  unsigned int others=0;
  if(file_stats==NULL)
    return ;
  file_stat_t *new_file_stats;
  filestatsWidget->setRowCount(0);
  for(i=0;file_stats[i].file_hint!=NULL;i++);
  nbr=i;
  if(nbr==0)
    return ;
  new_file_stats=(file_stat_t*)MALLOC(nbr*sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr*sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);
  for(i=0; i<10 && i<nbr && new_file_stats[i].recovered>0; i++)
  {
    QTableWidgetItem *item;
    filestatsWidget->setRowCount(i+1);
    if(new_file_stats[i].file_hint->extension!=NULL)
    {
      item = new QTableWidgetItem(new_file_stats[i].file_hint->extension);
      filestatsWidget->setItem(i, 0, item);
    }
    item = new QTableWidgetItem();
    item->setData(0, new_file_stats[i].recovered);
    filestatsWidget->setItem(i, 1, item);
  }
  for(; i<nbr && new_file_stats[i].recovered>0; i++)
    others+=new_file_stats[i].recovered;
  if(others>0)
  {
    QTableWidgetItem *item;
    filestatsWidget->setRowCount(11);
    item = new QTableWidgetItem("others");
    filestatsWidget->setItem(10, 0, item);
    item = new QTableWidgetItem();
    item->setData(0, others);
    filestatsWidget->setItem(10, 1, item);
  }
  free(new_file_stats);
}

void QPhotorec::qphotorec_search_updateUI()
{
  const partition_t *partition=params->partition;
  const unsigned int sector_size=params->disk->sector_size;
  QString tmp;
  folder_txt->setText("Destination: <a href=\"file://" + Qt::escape(directoryLabel->text()) + "/" +
      DEFAULT_RECUP_DIR + "." + QString::number(params->dir_num) + "\">" +
      Qt::escape(directoryLabel->text()) + "</a>");
  if(params->status==STATUS_QUIT)
  {
    tmp.sprintf("Recovery completed");
  }
  else if(params->status==STATUS_EXT2_ON_BF || params->status==STATUS_EXT2_OFF_BF)
  {
    tmp.sprintf("Bruteforce %10lu sectors remaining (test %u)",
        (unsigned long)((params->offset-partition->part_offset)/sector_size),
	params->pass);
  }
  else
  {
    tmp.sprintf("Pass %u - Reading sector %10llu/%llu",
	params->pass,
	(unsigned long long)(params->offset>partition->part_offset && params->offset < partition->part_size ?
	  ((params->offset-partition->part_offset)/sector_size):
	  0),
	(unsigned long long)(partition->part_size/sector_size));
  }
  progress_info->setText(tmp);

  if(params->status==STATUS_FIND_OFFSET)
    tmp.sprintf("%u/10 headers found", params->file_nbr);
  else
    tmp.sprintf("%u files found", params->file_nbr);
  progress_filefound->setText(tmp);

  if(params->status==STATUS_QUIT)
  {
    progress_bar->setMinimum(0);
    progress_bar->setMaximum(100);
    progress_bar->setValue(100);
  }
  else if(params->status==STATUS_FIND_OFFSET)
  {
    progress_bar->setMinimum(0);
    progress_bar->setMaximum(10);
    progress_bar->setValue(params->file_nbr);
  }
  else
  {
    progress_bar->setMinimum(0);
    progress_bar->setMaximum(100);
    progress_bar->setValue((params->offset-partition->part_offset)*100/ partition->part_size);
  }
  photorec_info(params->file_stats);
}

void QPhotorec::qphotorec_search_setupUI()
{
  clearWidgets();
  delete this->layout();
  QVBoxLayout *mainLayout = new QVBoxLayout();
  QWidget *t_copy = copyright(this);

  QSizePolicy c_sizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);

  QLabel *disk_img=new QLabel();
  QPixmap disk_pixmap = QPixmap(":res/gnome/drive-harddisk.png");
  disk_img->setPixmap(disk_pixmap);
  disk_img->setSizePolicy(c_sizePolicy);

  QLabel *disk_txt=new QLabel();
  disk_txt->setText(selected_disk->description_short(selected_disk));

  QWidget *diskWidget = new QWidget();
  QHBoxLayout *diskWidgetLayout = new QHBoxLayout(diskWidget);
  diskWidgetLayout->addWidget(disk_img);
  diskWidgetLayout->addWidget(disk_txt);
  diskWidget->setLayout(diskWidgetLayout);

  QLabel *folder_img=new QLabel();
  QPixmap *folder_pixmap = new QPixmap(":res/gnome/folder.png");
  folder_img->setPixmap(*folder_pixmap);
  folder_img->setSizePolicy(c_sizePolicy);

  folder_txt=new QLabel();
  folder_txt->setTextFormat(Qt::RichText);
  folder_txt->setTextInteractionFlags(Qt::TextBrowserInteraction);
  folder_txt->setOpenExternalLinks(true);

  QWidget *folderWidget = new QWidget();
  QHBoxLayout *folderWidgetLayout = new QHBoxLayout(folderWidget);
  folderWidgetLayout->addWidget(folder_img);
  folderWidgetLayout->addWidget(folder_txt);
  folderWidget->setLayout(folderWidgetLayout);


  progress_info=new QLabel();
  progress_filefound=new QLabel();
  progress_bar=new QProgressBar();

  QWidget *progressWidget = new QWidget();
  QHBoxLayout *progressWidgetLayout = new QHBoxLayout(progressWidget);
  progressWidgetLayout->addWidget(progress_info);
  progressWidgetLayout->addWidget(progress_bar);
  progressWidgetLayout->addWidget(progress_filefound);
  progressWidget->setLayout(progressWidgetLayout);

  QWidget *progressWidget2 = new QWidget();
  QHBoxLayout *progressWidgetLayout2 = new QHBoxLayout(progressWidget2);
// TODO
//  progressWidgetLayout2->addWidget(progress_elapsed);
//  progressWidgetLayout2->addWidget(progress_eta);
  progressWidget2->setLayout(progressWidgetLayout2);

  QStringList oLabel;
  oLabel.append("File familly");
  oLabel.append("Number of file recovered");

  filestatsWidget=new QTableWidget();
  filestatsWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
  filestatsWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
  filestatsWidget->setSelectionMode(QAbstractItemView::SingleSelection);
  filestatsWidget->verticalHeader()->hide();
  filestatsWidget->setColumnCount( 2 );
  filestatsWidget->setHorizontalHeaderLabels( oLabel );
  filestatsWidget->resizeColumnsToContents();

  QPushButton *button_quit= new QPushButton(QIcon::fromTheme("application-exit", QIcon(":res/gnome/application-exit.png")), "&Quit");
  mainLayout->addWidget(t_copy);
  mainLayout->addWidget(diskWidget);
  mainLayout->addWidget(folderWidget);
  mainLayout->addWidget(progressWidget);
  mainLayout->addWidget(progressWidget2);
  mainLayout->addWidget(filestatsWidget);
  mainLayout->addWidget(button_quit);
  this->setLayout(mainLayout);

  connect( button_quit, SIGNAL(clicked()), this, SLOT(stop_and_quit()) );
  connect(this, SIGNAL(finished()), qApp, SLOT(quit()));

  timer = new QTimer(this);
  timer->setInterval(500);
  connect(timer, SIGNAL(timeout()), this, SLOT(qphotorec_search_updateUI()));
}

void QPhotorec::stop_and_quit()
{
  stop_the_recovery=true;
  emit finished();
}

int QPhotorec::photorec(alloc_data_t *list_search_space)
{
  pstatus_t ind_stop=PSTATUS_OK;
  const unsigned int blocksize_is_known=params->blocksize;
  params_reset(params, options);
  /* make the first recup_dir */
  params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num);
  for(params->pass=0; params->status!=STATUS_QUIT; params->pass++)
  {
    timer->start();
    switch(params->status)
    {
      case STATUS_UNFORMAT:
	/* FIXME */
	break;
      case STATUS_FIND_OFFSET:
	{
	  uint64_t start_offset=0;
	  if(blocksize_is_known>0)
	  {
	    ind_stop=PSTATUS_OK;
	    if(!td_list_empty(&list_search_space->list))
	      start_offset=(td_list_entry(list_search_space->list.next, alloc_data_t, list))->start % params->blocksize;
	  }
	  else
	  {
	    ind_stop=photorec_find_blocksize(list_search_space);
	    params->blocksize=find_blocksize(list_search_space, params->disk->sector_size, &start_offset);
	  }
	  update_blocksize(params->blocksize, list_search_space, start_offset);
	}
	break;  
      case STATUS_EXT2_ON_BF:
      case STATUS_EXT2_OFF_BF:
	/* FIXME */
	break;
      default:
	ind_stop=photorec_aux(list_search_space);
	break;
    }
    timer->stop();
    qphotorec_search_updateUI();
    session_save(list_search_space, params, options);
    switch(ind_stop)
    {
      case PSTATUS_EACCES:
	{
	  int ret=QMessageBox::warning(this,"QPhotoRec: Failed to create file!", "Failed to create file! Please choose another destination", QMessageBox::Ok| QMessageBox::Cancel, QMessageBox::Ok);
	  if(ret==QMessageBox::Cancel)
	  {
	    params->status=STATUS_QUIT;
	  }
	  else
	  {
	    setExistingDirectory();
	    free(params->recup_dir);
	    QByteArray byteArray = (directoryLabel->text() + "/" + DEFAULT_RECUP_DIR).toUtf8();
	    params->recup_dir=strdup(byteArray.constData());
	    params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num);
	  }
	}
	break;
      case PSTATUS_ENOSPC:
	{
	  int ret=QMessageBox::warning(this,"QPhotoRec: Not enough space!", "There is not enough space left! Please free disk space and/or choose another destination", QMessageBox::Ok| QMessageBox::Cancel, QMessageBox::Ok);
	  if(ret==QMessageBox::Cancel)
	  {
	    params->status=STATUS_QUIT;
	  }
	  else
	  {
	    setExistingDirectory();
	    free(params->recup_dir);
	    QByteArray byteArray = (directoryLabel->text() + "/" + DEFAULT_RECUP_DIR).toUtf8();
	    params->recup_dir=strdup(byteArray.constData());
	    params->dir_num=photorec_mkdir(params->recup_dir, params->dir_num);
	  }
	}
break;
      case PSTATUS_OK:
	status_inc(params, options);
	if(params->status==STATUS_QUIT)
	  unlink("photorec.ses");
	break;
      case PSTATUS_STOP:
	params->status=STATUS_QUIT;
	break;
    }
    update_stats(params->file_stats, list_search_space);
    qphotorec_search_updateUI();
  }
  free_search_space(list_search_space);
  free_header_check();
  free(params->file_stats);
  params->file_stats=NULL;
  return 0;
}

void QPhotorec::qphotorec_search()
{
  if(selected_disk==NULL || selected_partition==NULL)
    return;
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };

  QByteArray byteArray = (directoryLabel->text() + "/" + DEFAULT_RECUP_DIR).toUtf8();
  params->recup_dir=strdup(byteArray.constData());
  params->carve_free_space_only=qfreeRadioButton->isChecked();
  params->disk=selected_disk;
  params->partition=selected_partition;
  log_partition(selected_disk, selected_partition);

  options->mode_ext2=qextRadioButton->isChecked();

  qphotorec_search_setupUI();
  if(td_list_empty(&list_search_space.list))
  {
    init_search_space(&list_search_space, params->disk, params->partition);
  }
  if(params->carve_free_space_only>0)
  {
    params->blocksize=remove_used_space(params->disk, params->partition, &list_search_space);
  }
  photorec(&list_search_space);
  free(params->recup_dir);
  params->recup_dir=NULL;
}

void QPhotorec::qphotorec_about()
{
  QPixmap pixmap_img = QPixmap(":res/photorec_64x64.png");
  QMessageBox msg;
  msg.setText("QPhotoRec is is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.\n\nQPhotoRec is is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License along with QPhotoRec.  If not, see <http://www.gnu.org/licenses/>.");
  msg.setWindowTitle("QPhotoRec: About");
  msg.addButton(QMessageBox::Close);
  msg.setIconPixmap(pixmap_img);
  msg.exec();
}

void QPhotorec::qphotorec_formats()
{
  file_enable_t *file_enable;
  QStringList list;
  formats=new QListWidget();
  for(file_enable=list_file_enable;
      file_enable->file_hint!=NULL;
      file_enable++)
  {
    QListWidgetItem * item;
    char descr[128];
    sprintf(descr, "%-4s %s",
	    (file_enable->file_hint->extension!=NULL?
	     file_enable->file_hint->extension:""),
	    file_enable->file_hint->description);
    item = new QListWidgetItem(descr, formats);
    if(file_enable->enable)
      item->setCheckState (Qt::Checked);
    else
      item->setCheckState (Qt::Unchecked);
  }

  QDialog fenetre3;
  fenetre3.setWindowTitle("QPhotoRec: File Formats");
  QDialogButtonBox buttonBox(Qt::Horizontal);

  QPushButton *bt_reset= new QPushButton("&Reset");
  QPushButton *bt_restore= new QPushButton("Res&tore");

  buttonBox.addButton(bt_reset, QDialogButtonBox::ResetRole);
  buttonBox.addButton(bt_restore, QDialogButtonBox::ResetRole);
  buttonBox.addButton(QDialogButtonBox::Ok);
  QVBoxLayout vbox;
  vbox.addWidget(formats);
  vbox.addWidget(&buttonBox);
  fenetre3.setLayout(&vbox);
  connect(&buttonBox, SIGNAL(accepted()), &fenetre3, SLOT(accept()));
  connect(bt_reset, SIGNAL(clicked()), this, SLOT(formats_reset()));
  connect(bt_restore, SIGNAL(clicked()), this, SLOT(formats_restore()));
  fenetre3.exec();
  int i;
  for (i = 0, file_enable=list_file_enable;
      i < formats->count() && file_enable->file_hint!=NULL;
      i++, file_enable++)
  {
    QListWidgetItem *item = formats->item(i);
    file_enable->enable=(item->checkState()==Qt::Checked?1:0);
  }
}

void QPhotorec::formats_reset()
{
  for (int i = 0; i < formats->count(); i++) {
    QListWidgetItem *item = formats->item(i);
    item->setCheckState (Qt::Unchecked);
  }
}

void QPhotorec::formats_restore()
{
  file_enable_t *file_enable;
  int i;
  for (i = 0, file_enable=list_file_enable;
      i < formats->count() && file_enable->file_hint!=NULL;
      i++, file_enable++)
  {
    QListWidgetItem *item = formats->item(i);
    if(file_enable->file_hint->enable_by_default)
      item->setCheckState (Qt::Checked);
    else
      item->setCheckState (Qt::Unchecked);
  }
}
