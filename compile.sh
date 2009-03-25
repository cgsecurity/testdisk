#!/bin/sh
# default, host is empty, no cross compilation
# ./compile.sh [ i586-pc-msdosdjgpp | i386-pc-cygwin | i386-pc-mingw32 | powerpc-mac-darwin ]
# Comment the version definition to not compile the library
VER_E2FSPROGS=
VER_PROGSREISERFS=0.3.1-rc8
VER_NTFSPROGS=2.0.0
VER_LIBEWF=20080501
crosscompile_target=
prefix=/usr/
if [ "$CC" = "gcc295" ];
then
  VER_NTFSPROGS=
fi
if [ -z "$1" ];
then
  compiledir=.
else
  compiledir=$1
  if [ "$1" != "$CC" ];
  then
    VER_E2FSPROGS=1.41.4
    crosscompile_target=$1
    TESTDISKCC=$crosscompile_target-gcc
  fi
fi
prefix=/usr/$crosscompile_target
LYNX=links
LIBEXT=$compiledir/e2fsprogs-$VER_E2FSPROGS/lib/ext2fs/libext2fs.a
LIBNTFS=$compiledir/ntfsprogs-$VER_NTFSPROGS/libntfs/.libs/libntfs.a
LIBREISER=$compiledir/progsreiserfs-$VER_PROGSREISERFS/libreiserfs/.libs/libreiserfs.a
LIBEWF=$compiledir/ewf-$VER_NTFSPROGS/libewf/.libs/libewf.a
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
	CC=$TESTDISKCC CFLAGS="$CFLAGS -g -O2 -DOMIT_COM_ERR" ./configure --host=$crosscompile_target --prefix=$prefix
	cd $pwd_saved
  fi
fi

if [ ! -e $LIBEXT ];
then
  if [ -e $compiledir/e2fsprogs-$VER_E2FSPROGS/Makefile ];
  then
	cd $compiledir/e2fsprogs-$VER_E2FSPROGS
	make libs
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
	make
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
        CC=$TESTDISKCC ./configure --host=$crosscompile_target --prefix=$prefix --disable-default-device-io-ops --disable-crypto
        cd $pwd_saved
  fi
fi

if [ ! -e $LIBNTFS ];
then
  if [ -e $compiledir/ntfsprogs-$VER_NTFSPROGS/Makefile ];
  then
	cd $compiledir/ntfsprogs-$VER_NTFSPROGS
	make libs
	cd $pwd_saved
  fi
fi
fi

if [ "$VER_LIBEWF" != "" ];
then
CONFIGUREOPT="$CONFIGUREOPT --with-ewf-lib=${PWDSRC}/libewf-${VER_LIBEWF}/libewf/.libs/ --with-ewf-includes=${PWDSRC}/libewf-${VER_LIBEWF}/include/"

if [ ! -e $compiledir/libewf-$VER_LIBEWF/configure ];
then
  if [ ! -e libewf-$VER_LIBEWF.tar.gz ];
  then
    if [ ! -e libewf-beta-$VER_LIBEWF.tar.gz ];
    then
      	$LYNX "http://sourceforge.net/project/platformdownload.php?group_id=167783"
    fi
  fi
  if [ -e libewf-$VER_LIBEWF.tar.gz ];
  then
	tar xzf libewf-$VER_LIBEWF.tar.gz -C $compiledir
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
	make lib
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
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ewf --enable-sudo --with-sudo-bin=/usr/bin/sudo
                ;;
          i586-pc-msdosdjgpp)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-ewf --without-iconv
                ;;
          i386-pc-cygwin)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-iconv
                ;;
          i386-mingw32)
		$confdir/configure --host=$crosscompile_target --prefix=$prefix $CONFIGUREOPT --without-iconv --enable-missing-uuid-ok
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
        make
	cd $pwd_saved
  fi
fi

