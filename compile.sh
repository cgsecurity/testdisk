#!/bin/sh
# default, host is empty, no cross compilation
# ./compile.sh [ i586-pc-msdosdjgpp | i386-pc-cygwin | i386-pc-mingw32 | powerpc-mac-darwin ]
# Comment the version definition to not compile the library
VER_E2FSPROGS=
VER_PROGSREISERFS="0.3.1-rc8"
#VER_LIBEWF=20100226
VER_LIBEWF=20120504
smp_mflags="-j 2"
crosscompile_target=
prefix=/usr/
if [ -z "$1" ];
then
  compiledir=.
else
  compiledir=$1
  if [ "$1" != "$CC" ];
  then
    crosscompile_target=$1
    TESTDISKCC=$crosscompile_target-gcc
    PKG_CONFIG_PATH=/usr/$crosscompile_target/lib/pkgconfig
    if [ ! -d $PKG_CONFIG_PATH ];
    then
      PKG_CONFIG_PATH=/usr/$crosscompile_target/sys-root/mingw/lib/pkgconfig
    fi
    if [ ! -d $PKG_CONFIG_PATH ];
    then
      unset PKG_CONFIG_PATH
    fi
    export PKG_CONFIG_PATH
  fi
fi
case "$crosscompile_target" in
  "")
  ;;
  *-msdosdjgpp)
	VER_LIBNTFS3G=
	VER_NTFSPROGS="2.0.0"
	VER_E2FSPROGS="1.42.8"
  ;;
  *-cygwin)
	VER_LIBNTFS3G=
	VER_NTFSPROGS="2.0.0"
	VER_E2FSPROGS="1.42.8"
	export PKG_CONFIG_SYSROOT_DIR=/usr/i386-pc-cygwin/
  ;;
  *-mingw32)
	VER_LIBNTFS3G=
	VER_NTFSPROGS="2.0.0"
	VER_E2FSPROGS=
  ;;
  i686-apple-darwin9|powerpc-apple-darwin)
	VER_LIBNTFS3G="2011.3.28-RC"
	VER_NTFSPROGS=
	VER_E2FSPROGS="1.42.8"
  ;;
  *)
	VER_LIBNTFS3G="2011.3.28-RC"
	VER_NTFSPROGS=
	VER_E2FSPROGS="1.42.8"
  ;;
esac
prefix=/usr/$crosscompile_target
LYNX=links
WGET="wget -N"
LIBEXT=$compiledir/e2fsprogs-$VER_E2FSPROGS/lib/ext2fs/libext2fs.a
LIBNTFS=$compiledir/ntfsprogs-$VER_NTFSPROGS/libntfs/.libs/libntfs.a
LIBNTFS3G=$compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G/libntfs-3g/.libs/libntfs-3g.a
LIBREISER=$compiledir/progsreiserfs-$VER_PROGSREISERFS/libreiserfs/.libs/libreiserfs.a
LIBEWF=$compiledir/ewf-$VER_LIBEWF/libewf/.libs/libewf.a
pwd_saved=`pwd`
confdir=`(dirname "$0") 2>/dev/null`
cd $confdir
confdir=`pwd`
cd $pwd_saved

PWDSRC=`pwd|sed 's#^\w:/#/#'`/$compiledir

CONFIGUREOPT=
mkdir -p $compiledir
echo "This script will try to compile e2fsprogs progsreiserfs ntfsprogs libraries"
if [ "$VER_E2FSPROGS" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-ext2fs-lib=${PWDSRC}/e2fsprogs-${VER_E2FSPROGS}/lib --with-ext2fs-includes=${PWDSRC}/e2fsprogs-${VER_E2FSPROGS}/lib"

if [ ! -e $compiledir/e2fsprogs-$VER_E2FSPROGS/configure ];
then
  if [ ! -e e2fsprogs-$VER_E2FSPROGS.tar.gz ];
  then
        $LYNX http://prdownloads.sourceforge.net/e2fsprogs/e2fsprogs-$VER_E2FSPROGS.tar.gz
  fi
  if [ -e e2fsprogs-$VER_E2FSPROGS.tar.gz ];
  then
        tar xzf e2fsprogs-$VER_E2FSPROGS.tar.gz -C $compiledir
  fi
fi

if [ ! -e $compiledir/e2fsprogs-$VER_E2FSPROGS/Makefile ];
then
  if [ -e $compiledir/e2fsprogs-$VER_E2FSPROGS/configure ];
  then
        rm -f $compiledir/Makefile
  	cd $compiledir/e2fsprogs-$VER_E2FSPROGS
        case "$crosscompile_target" in
	  arm-marvell-linux-gnu)
	  	CC=$TESTDISKCC CFLAGS="$CFLAGS -g -O2 -DOMIT_COM_ERR" ./configure --host=$crosscompile_target --prefix=$prefix --disable-tls
                ;;
          *)
		CC=$TESTDISKCC CFLAGS="$CFLAGS -g -O2 -DOMIT_COM_ERR" ./configure --host=$crosscompile_target --prefix=$prefix
                ;;
	esac
	cd $pwd_saved
  fi
fi

if [ ! -e $LIBEXT ];
then
  if [ -e $compiledir/e2fsprogs-$VER_E2FSPROGS/Makefile ];
  then
	cd $compiledir/e2fsprogs-$VER_E2FSPROGS
	make $smp_mflags libs
	cd $pwd_saved
  fi
fi
fi

if [ "$VER_PROGSREISERFS" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-reiserfs-lib=${PWDSRC}/progsreiserfs-${VER_PROGSREISERFS}/libreiserfs/.libs/ --with-reiserfs-includes=${PWDSRC}/progsreiserfs-${VER_PROGSREISERFS}/include/ --with-dal-lib=${PWDSRC}/progsreiserfs-${VER_PROGSREISERFS}/libdal/.libs/"
if [ ! -e $compiledir/progsreiserfs-$VER_PROGSREISERFS/configure ];
then
  if [ ! -e progsreiserfs-$VER_PROGSREISERFS.tar.gz ];
  then
        $LYNX http://reiserfs.osdn.org.ua/snapshots/progsreiserfs-$VER_PROGSREISERFS.tar.gz
  fi
  if [ -e progsreiserfs-$VER_PROGSREISERFS.tar.gz ];
  then
        tar xzf progsreiserfs-$VER_PROGSREISERFS.tar.gz -C $compiledir
        cd $compiledir/progsreiserfs-$VER_PROGSREISERFS
	patch -p1 < $pwd_saved/progsreiserfs-journal.patch
	patch -p1 < $pwd_saved/progsreiserfs-file-read.patch
        cd $pwd_saved
  fi
fi

if [ ! -e $compiledir/progsreiserfs-$VER_PROGSREISERFS/Makefile ];
then
  if [ -e $compiledir/progsreiserfs-$VER_PROGSREISERFS/configure ];
  then
#        rm -f $compiledir/Makefile
        cd $compiledir/progsreiserfs-$VER_PROGSREISERFS
        ./configure --host=$crosscompile_target --prefix=$prefix --disable-nls --disable-Werror
        cd $pwd_saved
  fi
fi

#vim /home/kmaster/src/testdisk/powerpc-apple-darwin/progsreiserfs-0.3.1-rc8/libtool
#%s/AR="ar"/AR="powerpc-apple-darwin-ar"/
if [ ! -e $LIBREISER ];
then
  if [ -e $compiledir/progsreiserfs-$VER_PROGSREISERFS/Makefile ];
  then
	cd $compiledir/progsreiserfs-$VER_PROGSREISERFS
	make $smp_mflags
	cd $pwd_saved
  fi
fi
fi

if [ "$VER_LIBNTFS3G" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-ntfs3g-lib=${PWDSRC}/ntfs-3g_ntfsprogs-${VER_LIBNTFS3G}/libntfs-3g/.libs/ --with-ntfs3g-includes=${PWDSRC}/ntfs-3g_ntfsprogs-${VER_LIBNTFS3G}/include/"
if [ ! -e $compiledir/ntfsprogs-$VER_LIBNTFS3G/configure ];
then
  if [ ! -e ntfs-3g_ntfsprogs-$VER_LIBNTFS3G.tgz ];
  then
	$WGET http://tuxera.com/opensource/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G.tgz
  fi
  if [ -e ntfs-3g_ntfsprogs-$VER_LIBNTFS3G.tgz ];
  then
	tar xzf ntfs-3g_ntfsprogs-$VER_LIBNTFS3G.tgz -C $compiledir
  fi
fi

if [ ! -e $compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G/Makefile ];
then
  if [ -e $compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G/configure ];
  then
#        rm -f $compiledir/Makefile
        cd $compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G
        case "$crosscompile_target" in
          powerpc-apple-darwin|i686-apple-darwin9)
	  	CC=$TESTDISKCC ./configure --host=$crosscompile_target --prefix=$prefix --disable-default-device-io-ops --disable-crypto --disable-nfconv
		;;
	*)
		CC=$TESTDISKCC ./configure --host=$crosscompile_target --prefix=$prefix --disable-default-device-io-ops --disable-crypto
		;;
	esac
# --disable-default-device-io-ops is need for NT 4
        cd $pwd_saved
  fi
fi

if [ ! -e $VER_LIBNTFS3G ];
then
  if [ -e $compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G/Makefile ];
  then
	cd $compiledir/ntfs-3g_ntfsprogs-$VER_LIBNTFS3G
#	make $smp_mflags libs
	make $smp_mflags
	cd $pwd_saved
  fi
fi
fi

if [ "$VER_NTFSPROGS" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-ntfs-lib=${PWDSRC}/ntfsprogs-${VER_NTFSPROGS}/libntfs/.libs/ --with-ntfs-includes=${PWDSRC}/ntfsprogs-${VER_NTFSPROGS}/include/"
if [ ! -e $compiledir/ntfsprogs-$VER_NTFSPROGS/configure ];
then
  if [ ! -e ntfsprogs-$VER_NTFSPROGS.tar.gz ];
  then
	$LYNX http://prdownloads.sourceforge.net/linux-ntfs/ntfsprogs-$VER_NTFSPROGS.tar.gz
  fi
  if [ -e ntfsprogs-$VER_NTFSPROGS.tar.gz ];
  then
	tar xzf ntfsprogs-$VER_NTFSPROGS.tar.gz -C $compiledir
  fi
fi

if [ ! -e $compiledir/ntfsprogs-$VER_NTFSPROGS/Makefile ];
then
  if [ -e $compiledir/ntfsprogs-$VER_NTFSPROGS/configure ];
  then
#        rm -f $compiledir/Makefile
        cd $compiledir/ntfsprogs-$VER_NTFSPROGS
# --disable-default-device-io-ops is need for NT 4
        ./configure --host=$crosscompile_target --prefix=$prefix --disable-default-device-io-ops --disable-crypto
        cd $pwd_saved
  fi
fi

if [ ! -e $LIBNTFS ];
then
  if [ -e $compiledir/ntfsprogs-$VER_NTFSPROGS/Makefile ];
  then
	cd $compiledir/ntfsprogs-$VER_NTFSPROGS
	make $smp_mflags libs
	cd $pwd_saved
  fi
fi
fi

if [ "$VER_LIBEWF" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-ewf-lib=${PWDSRC}/libewf-${VER_LIBEWF}/libewf/.libs/ --with-ewf-includes=${PWDSRC}/libewf-${VER_LIBEWF}/include/"

if [ ! -e $compiledir/libewf-$VER_LIBEWF/configure ];
then
  if [ ! -e libewf-$VER_LIBEWF.tar.gz -a ! -e libewf-alpha-$VER_LIBEWF.tar.gz -a ! -e libewf-beta-$VER_LIBEWF.tar.gz ];
    then
  	$LYNX "http://sourceforge.net/project/platformdownload.php?group_id=167783"
  fi
  if [ -e libewf-$VER_LIBEWF.tar.gz ];
  then
	tar xzf libewf-$VER_LIBEWF.tar.gz -C $compiledir
  fi
  if [ -e libewf-alpha-$VER_LIBEWF.tar.gz ];
  then
	tar xzf libewf-alpha-$VER_LIBEWF.tar.gz -C $compiledir
  fi
  if [ -e libewf-beta-$VER_LIBEWF.tar.gz ];
  then
	tar xzf libewf-beta-$VER_LIBEWF.tar.gz -C $compiledir
  fi
fi

if [ ! -e $compiledir/libewf-$VER_LIBEWF/Makefile ];
then
  if [ -e $compiledir/libewf-$VER_LIBEWF/configure ];
  then
#        rm -f $compiledir/Makefile
	cd $compiledir/libewf-$VER_LIBEWF
	CC=$TESTDISKCC ./configure --host=$crosscompile_target --prefix=$prefix
	cd $pwd_saved
  fi
fi

if [ ! -e $LIBEWF ];
then
  if [ -e $compiledir/libewf-$VER_LIBEWF/Makefile ];
  then
	cd $compiledir/libewf-$VER_LIBEWF
	make $smp_mflags lib
	cd $pwd_saved
  fi
fi
fi

echo "Try to compile TestDisk"
CC=$TESTDISKCC
export CC

if [ -d $compiledir ];
then
  if [ ! -e $compiledir/Makefile ];
  then
  	cd $compiledir
        case "$crosscompile_target" in
          powerpc-apple-darwin)
# libewf should work under MacOSX but it hasn't been tested
# use  --with-ncurses-lib=$prefix/usr/lib to get binaries that don't need libncurses
# but users may be unable to navigate...
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ewf --enable-sudo --with-sudo-bin=/usr/bin/sudo  --disable-qt --disable-assert
                ;;
	  i686-apple-darwin9)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --enable-sudo --with-sudo-bin=/usr/bin/sudo --disable-qt
                ;;
          i586-pc-msdosdjgpp)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ewf --without-iconv --disable-qt
                ;;
          i386-pc-cygwin)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --enable-qt
                ;;
          i386-mingw32)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-iconv --enable-missing-uuid-ok
                ;;
	  i686-pc-mingw32|x86_64-pc-mingw32|i686-w64-mingw32|x86_64-w64-mingw32)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --enable-missing-uuid-ok --enable-qt
                ;;
	  arm-marvell-linux-gnu)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ewf --without-ntfs --disable-qt
                ;;
	  arm-none-linux-gnueabi|powerpc-linux-gnuspe)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ntfs --disable-qt
                ;;
          *)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT
                ;;
	esac
	cd $pwd_saved
  fi
  if [ -e $compiledir/Makefile ];
  then
  	cd $compiledir
        make $smp_mflags
	cd $pwd_saved
  fi
fi
