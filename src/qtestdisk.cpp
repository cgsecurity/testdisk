/*

    File: qtestdisk.cpp

    Qt front-end for TestDisk: runs "testdisk /cmd" and shows the results
    from its log, so the partition recovery logic stays in testdisk itself.

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

#include <cassert>
#include <QApplication>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QVBoxLayout>
#include <QWidget>

/* "testdisk /list" prints one "Disk <device> - <size> - ..." line per disk */
static QStringList parse_devices(const QString &out)
{
  QStringList devices;
  static const QRegularExpression re(QStringLiteral("^Disk (.+?) - "), QRegularExpression::MultilineOption);
  QRegularExpressionMatchIterator it=re.globalMatch(out);
  while(it.hasNext())
    devices << it.next().captured(1);
  return devices;
}

/* With /debug, interface_recovery() logs the found partitions after a "Results" line */
static QString results_from_log(const QString &log)
{
  const int pos=log.lastIndexOf(QStringLiteral("\nResults\n"));
  return pos<0 ? QString() : log.mid(pos+1);
}

static QString strip_ansi(QString s)
{
  static const QRegularExpression re(QStringLiteral("\x1b\\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-Za-z]|\x1b[=>]"));
  return s.remove(re);
}

static void self_test()
{
  const QStringList d=parse_devices(QStringLiteral(
	"TestDisk 7.3\nDisk /dev/sda - 500 GB / 465 GiB - CHS 60801 255 63\nSector size:512\n"
	"Disk \\\\.\\PhysicalDrive1 - 8 GB / 7 GiB\nDisk image.dd - 10 MB / 9 MiB\n"));
  assert(d==QStringList({"/dev/sda", "\\\\.\\PhysicalDrive1", "image.dd"}));
  assert(results_from_log("x\nResults\nold\nResults\n 1 P FAT32\n")=="Results\n 1 P FAT32\n");
  assert(results_from_log("no partition").isEmpty());
  assert(strip_ansi("\x1b[1;1H\x1b[?25lDisk")=="Disk");
  (void)d;
}

int main(int argc, char *argv[])
{
  QApplication app(argc, argv);
  self_test();
  const QString td=[]{
    /* testdisk_win is the name used in the Windows zip */
    for(const QString &name : {QStringLiteral("testdisk"), QStringLiteral("testdisk_win")})
      for(const QStringList &dirs : {QStringList(QCoreApplication::applicationDirPath()), QStringList()})
      {
	const QString p=QStandardPaths::findExecutable(name, dirs);
	if(!p.isEmpty())
	  return p;
      }
    return QString();
  }();
  QTemporaryDir tmp;
  const QString logPath=tmp.filePath(QStringLiteral("testdisk.log"));

  QWidget win;
  win.setWindowTitle(QStringLiteral("QTestDisk"));
  auto *disks=new QComboBox;
  disks->setMinimumContentsLength(30);
  auto *refresh=new QPushButton(QObject::tr("Refresh"));
  auto *openImg=new QPushButton(QObject::tr("Open image..."));
  auto *arch=new QComboBox;
  arch->addItem(QObject::tr("Auto-detect"), QString());
  arch->addItem(QStringLiteral("Intel/PC (MBR)"), QStringLiteral("partition_i386"));
  arch->addItem(QStringLiteral("EFI GPT"), QStringLiteral("partition_gpt"));
  arch->addItem(QStringLiteral("Humax"), QStringLiteral("partition_humax"));
  arch->addItem(QStringLiteral("Mac"), QStringLiteral("partition_mac"));
  arch->addItem(QObject::tr("None (non-partitioned)"), QStringLiteral("partition_none"));
  arch->addItem(QStringLiteral("Sun"), QStringLiteral("partition_sun"));
  arch->addItem(QStringLiteral("XBox"), QStringLiteral("partition_xbox"));
  auto *quick=new QPushButton(QObject::tr("Quick Search"));
  auto *deeper=new QPushButton(QObject::tr("Deeper Search"));
  auto *write=new QPushButton(QObject::tr("Write partition table..."));
  auto *stop=new QPushButton(QObject::tr("Stop"));
  auto *status=new QLabel;
  auto *output=new QPlainTextEdit;
  output->setReadOnly(true);
  output->setLineWrapMode(QPlainTextEdit::NoWrap);
  output->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

  auto *row1=new QHBoxLayout;
  row1->addWidget(new QLabel(QObject::tr("Disk:")));
  row1->addWidget(disks, 1);
  row1->addWidget(refresh);
  row1->addWidget(openImg);
  auto *row2=new QHBoxLayout;
  row2->addWidget(new QLabel(QObject::tr("Partition table type:")));
  row2->addWidget(arch);
  row2->addStretch();
  row2->addWidget(quick);
  row2->addWidget(deeper);
  row2->addWidget(write);
  row2->addWidget(stop);
  auto *layout=new QVBoxLayout(&win);
  layout->addLayout(row1);
  layout->addLayout(row2);
  layout->addWidget(output, 1);
  layout->addWidget(status);
  win.resize(900, 600);

  QProcess proc;
  {
    QProcessEnvironment env=QProcessEnvironment::systemEnvironment();
    /* testdisk starts ncurses even with /cmd: give it a terminal type and a size large enough not to block on "enlarge the terminal" */
    if(env.value(QStringLiteral("TERM")).isEmpty())
      env.insert(QStringLiteral("TERM"), QStringLiteral("xterm"));
    env.insert(QStringLiteral("LINES"), QStringLiteral("50"));
    env.insert(QStringLiteral("COLUMNS"), QStringLiteral("120"));
    proc.setProcessEnvironment(env);
  }
  bool listing=false;
  QString runningCmd, lastSearchCmd;

  auto setBusy=[&](bool busy, const QString &msg) {
    status->setText(msg);
    for(QWidget *w : {(QWidget*)disks, (QWidget*)refresh, (QWidget*)openImg, (QWidget*)arch, (QWidget*)quick, (QWidget*)deeper})
      w->setEnabled(!busy && (w==refresh || w==openImg || w==arch || w==disks || disks->count()>0));
    write->setEnabled(!busy && !lastSearchCmd.isEmpty());
    stop->setEnabled(busy);
  };
  auto start=[&](const QStringList &args) {
    if(td.isEmpty())
    {
      QMessageBox::critical(&win, win.windowTitle(), QObject::tr("The testdisk program was not found next to qtestdisk or in PATH."));
      return;
    }
    proc.start(td, args);
    proc.closeWriteChannel();	/* any unexpected prompt reads EOF instead of hanging */
  };
  auto listDisks=[&]() {
    listing=true;
    setBusy(true, QObject::tr("Looking for disks..."));
    start({QStringLiteral("/list")});
  };
  auto runCmd=[&](const QString &action) {
    const QString a=arch->currentData().toString();
    runningCmd=(a.isEmpty() ? QString() : a + ",") + action;
    QFile::remove(logPath);
    output->clear();
    setBusy(true, QObject::tr("Running testdisk /cmd %1 %2 ...").arg(disks->currentData().toString(), runningCmd));
    start({QStringLiteral("/logname"), logPath, QStringLiteral("/debug"), QStringLiteral("/cmd"), disks->currentData().toString(), runningCmd});
  };
  auto invalidate=[&]() {
    lastSearchCmd.clear();
    write->setEnabled(false);
  };

  QObject::connect(&proc, &QProcess::errorOccurred, [&](QProcess::ProcessError) {
    if(proc.state()==QProcess::NotRunning)
      setBusy(false, QObject::tr("Error: %1").arg(proc.errorString()));
  });
  QObject::connect(&proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [&](int code, QProcess::ExitStatus st) {
    const QString out=strip_ansi(QString::fromLocal8Bit(proc.readAll()));
    if(listing)
    {
      listing=false;
      const QString keep=disks->currentData().toString();
      disks->clear();
      for(const QString &line : out.split('\n'))
      {
	const QStringList dev=parse_devices(line);
	if(!dev.isEmpty())
	  disks->addItem(line.trimmed(), dev.first());
      }
      if(disks->findData(keep)<0 && !keep.isEmpty())
	disks->addItem(keep, keep);	/* keep an image opened by the user */
      disks->setCurrentIndex(qMax(0, disks->findData(keep)));
      if(disks->count()==0)
	output->setPlainText(out);	/* e.g. "You need to be root to use TestDisk." */
      setBusy(false, QObject::tr("%n disk(s) found", "", disks->count()));
      return;
    }
    QFile f(logPath);
    const QString log=f.open(QIODevice::ReadOnly) ? QString::fromLocal8Bit(f.readAll()) : QString();
    const QString results=results_from_log(log);
    const bool ok=(st==QProcess::NormalExit && code==0);
    output->setPlainText(!results.isEmpty() ? results : !log.isEmpty() ? log : out);
    if(ok && (runningCmd.endsWith(QStringLiteral("analyze")) || runningCmd.endsWith(QStringLiteral("analyze,search"))))
      lastSearchCmd=runningCmd;
    if(runningCmd.endsWith(QStringLiteral(",write")))
      invalidate();
    setBusy(false, !ok ? QObject::tr("testdisk stopped (exit code %1)").arg(code) :
	results.isEmpty() ? QObject::tr("Done, no partition found") : QObject::tr("Done"));
  });

  QObject::connect(refresh, &QPushButton::clicked, listDisks);
  QObject::connect(openImg, &QPushButton::clicked, [&]() {
    const QString file=QFileDialog::getOpenFileName(&win, QObject::tr("Open disk image"), QString(),
	QObject::tr("Disk images (*.dd *.img *.raw *.e01 *.E01);;All files (*)"));
    if(file.isEmpty())
      return;
    if(disks->findData(file)<0)
      disks->addItem(file, file);
    disks->setCurrentIndex(disks->findData(file));
    setBusy(false, QString());
  });
  QObject::connect(disks, QOverload<int>::of(&QComboBox::currentIndexChanged), invalidate);
  QObject::connect(arch, QOverload<int>::of(&QComboBox::currentIndexChanged), invalidate);
  QObject::connect(quick, &QPushButton::clicked, [&]() { runCmd(QStringLiteral("analyze")); });
  QObject::connect(deeper, &QPushButton::clicked, [&]() { runCmd(QStringLiteral("analyze,search")); });
  QObject::connect(stop, &QPushButton::clicked, [&]() { proc.kill(); });
  QObject::connect(write, &QPushButton::clicked, [&]() {
    const QString dev=disks->currentData().toString();
    if(QMessageBox::warning(&win, QObject::tr("Write partition table"),
	  QObject::tr("TestDisk will repeat the last search and write the partitions it finds to\n%1\n\n"
	    "The current partition table will be overwritten. Partition statuses are the ones TestDisk guessed; "
	    "use the text-mode testdisk if you need to change them.\n\nContinue?").arg(dev),
	  QMessageBox::Yes | QMessageBox::No, QMessageBox::No)!=QMessageBox::Yes)
      return;
    const QString a=arch->currentData().toString();
    const QString search=lastSearchCmd.mid(a.isEmpty() ? 0 : a.size()+1);	/* runCmd re-adds the arch prefix */
    runCmd(search + QStringLiteral(",noconfirm,write"));
  });

  win.show();
  listDisks();
  const int res=app.exec();
  if(proc.state()!=QProcess::NotRunning)
  {
    proc.kill();
    proc.waitForFinished();
  }
  return res;
}
