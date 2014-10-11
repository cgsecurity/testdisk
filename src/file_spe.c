/*

    File: file_spe.c

    Copyright (C) 2007 Christophe GRENIER <grenier@cgsecurity.org>

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
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "log.h"

static void register_header_check_spe(file_stat_t *file_stat);
static int header_check_spe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_spe= {
  .extension="spe",
  .description="WinSpec bitmap image",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_spe
};

struct header_spe
{
  uint16_t        dioden;            /*    0  num of physical pixels (X axis)    */
  int16_t         avgexp;            /*    2  number of accumulations per scan   */
  /*         if > 32767, set to -1 and        */
  /*         see lavgexp below (668)          */
  int16_t         exposure;          /*    4  exposure time (in milliseconds)    */
  /*         if > 32767, set to -1 and        */
  /*         see lexpos below (660)           */
  uint16_t        xDimDet;           /*    6  Detector x dimension of chip       */
  int16_t         mode;              /*    8  timing mode                        */
  float         exp_sec;           /*   10  alternative exposure, in secs.     */
  int16_t           asyavg;            /*   14  number of asynchron averages       */
  int16_t           asyseq;            /*   16  number of asynchron sequential     */
  uint16_t  yDimDet;           /*   18  y dimension of CCD or detector.    */
  char          date[10];          /*   20  date as MM/DD/YY                   */
  int16_t           ehour;             /*   30  Experiment Time: Hours (as binary) */
  int16_t           eminute;           /*   32  Experiment Time: Minutes(as binary)*/
  int16_t           noscan;            /*   34  number of multiple scans           */
  /*       if noscan == -1 use lnoscan        */
  int16_t           fastacc;           /*   36                                     */
  int16_t           seconds;           /*   38  Experiment Time: Seconds(as binary)*/
  int16_t           DetType;           /*   40  CCD/DiodeArray type                */
  uint16_t  xdim;              /*   42  actual # of pixels on x axis       */
  int16_t           stdiode;           /*   44  trigger diode                      */
  float         nanox;             /*   46                                     */
  float         calibdio[10];      /*   50  calibration diodes                 */
  char          fastfile[16];      /*   90  name of pixel control file         */
  int16_t           asynen;            /*  106  asynchron enable flag  0 = off     */
  int16_t           datatype;          /*  108  experiment data type               */
  /*         0 =   FLOATING POINT             */
  /*         1 =   LONG INTEGER               */
  /*         2 =   INTEGER                    */
  /*         3 =   UNSIGNED INTEGER           */
  float         calibnan[10];      /*  110  calibration nanometer              */
  int16_t           BackGrndApplied;   /*  150  set to 1 if background sub done    */
  int16_t           astdiode;          /*  152                                     */
  uint16_t  minblk;            /*  154  min. # of strips per skips         */
  uint16_t  numminblk;         /*  156  # of min-blocks before geo skps    */
  double        calibpol[4];       /*  158  calibration coeffients             */
  uint16_t  ADCrate;           /*  190  ADC rate                           */
  uint16_t  ADCtype;           /*  192  ADC type                           */
  uint16_t  ADCresolution;     /*  194  ADC resolution                     */
  uint16_t  ADCbitAdjust;      /*  196  ADC bit adjust                     */
  uint16_t  gain;              /*  198  gain                               */
  char          exprem[5][80];     /*  200  experiment remarks                 */
  uint16_t  geometric;         /*  600  geometric operations rotate 0x01   */
  /*       reverse 0x02, flip 0x04            */
  char          xlabel[16];        /*  602  Intensity display string           */
  uint16_t  cleans;            /*  618  cleans                             */
  uint16_t  NumSkpPerCln;      /*  620 number of skips per clean.          */
  char          califile[16];      /*  622  calibration file name (CSMA)       */
  char          bkgdfile[16];      /*  638  background file name               */
  int16_t           srccmp;            /*  654  number of source comp. diodes      */
  uint16_t  ydim;              /*  656  y dimension of raw data.           */
  int16_t           scramble;          /*  658  0 = scrambled, 1 = unscrambled     */
  int32_t          lexpos;            /*  660  int32_t exposure in milliseconds      */
  /*         used if exposure set to -1       */
  int32_t          lnoscan;           /*  664  int32_t num of scans                  */
  /*         used if noscan set to -1         */
  int32_t          lavgexp;           /*  668  int32_t num of accumulations          */
  /*         used if avgexp set to -1         */
  char          stripfil[16];      /*  672  stripe file (st130)                */
  char            sw_version[16];    /*  688  Version of SW creating this file */
  int16_t           type;              /*  704   1 = new120 (Type II)              */
  /*        2 = old120 (Type I )              */
  /*        3 = ST130                         */
  /*        4 = ST121                         */
  /*        5 = ST138                         */
  /*        6 = DC131 (PentaMax)              */
  /*        7 = ST133 (MicroMax/SpectroMax),  */
  /*        8 = ST135 (GPIB)                  */
  /*        9 = VICCD                         */
  /*       10 = ST116 (GPIB)                  */
  /*       11 = OMA3 (GPIB)                   */
  /*       12 = OMA4                          */
  int16_t           flatFieldApplied;  /*  706  Set to 1 if flat field was applied */
  int16_t           spare[8];          /*  708  reserved                           */
  int16_t           kin_trig_mode;     /*  724  Kinetics Trigger Mode              */
  char          dlabel[16];        /*  726  Data label.						 */
  char          empty[686];        /*  742  EMPTY BLOCK FOR EXPANSION          */
  float         clkspd_us;         /* 1428 Vert Clock Speed in micro-sec       */
  int16_t           HWaccumFlag;       /* 1432 set to 1 if accum done by Hardware  */
  int16_t           StoreSync;         /* 1434 set to 1 if store sync used.        */
  int16_t           BlemishApplied;    /* 1436 set to 1 if blemish removal applied */
  int16_t           CosmicApplied;     /* 1438 set to 1 if cosmic ray removal done */
  int16_t           CosmicType;        /* 1440 if cosmic ray applied, this is type */
  float         CosmicThreshold;   /* 1442 Threshold of cosmic ray removal.    */
  int32_t          NumFrames;         /* 1446 number of frames in file.           */
  float         MaxIntensity;      /* 1450 max intensity of data (future)      */
  float         MinIntensity;      /* 1454 min intensity of data (future)      */
  char          ylabel[16];  /* 1458 y axis label.                       */
  uint16_t  ShutterType;       /* 1474 shutter type.                       */
  float         shutterComp;       /* 1476 shutter compensation time.          */
  uint16_t  readoutMode;       /* 1480 Readout mode, full,kinetics, etc    */
  uint16_t  WindowSize;        /* 1482 window size for kinetics only.      */
  uint16_t  clkspd;            /* 1484 clock speed for kinetics &          */
  /*      frame transfer.                     */
  uint16_t  interface_type;    /* 1486 computer interface (isa-taxi,       */
  /*      pci, eisa, etc.)                    */
  uint32_t ioAdd1;            /* 1488 I/O address of inteface card.       */
  uint32_t ioAdd2;            /* 1492 if more than one address for card.  */
  uint32_t ioAdd3;            /* 1496                                     */
  uint16_t  intLevel;          /* 1500 interrupt level interface card      */
  uint16_t  GPIBadd;           /* 1502  GPIB address (if used)             */
  uint16_t  ControlAdd;        /* 1504  GPIB controller address (if used)  */
  uint16_t  controllerNum;     /* 1506  if multiple controller system will */
  /*       have controller # data came from.  */
  /*       (Future Item)                      */
  uint16_t  SWmade;            /* 1508  Software which created this file   */
  int16_t           NumROI;            /* 1510  number of ROIs used. if 0 assume 1 */
  /* 1512 - 1630  ROI information             */
  struct ROIinfo {                 /*                                          */
    uint16_t startx;            /* left x start value.                      */
    uint16_t endx;              /* right x value.                           */
    uint16_t groupx;            /* amount x is binned/grouped in hw.        */
    uint16_t starty;            /* top y start value.                       */
    uint16_t endy;              /* bottom y value.                          */
    uint16_t groupy;            /* amount y is binned/grouped in hw.        */
  } ROIinfoblk[10];                /*    ROI Starting Offsets:                 */
  /*            ROI  1 = 1512                 */
  /*            ROI  2 = 1524                 */
  /*            ROI  3 = 1536                 */
  /*            ROI  4 = 1548                 */
  /*            ROI  5 = 1560                 */
  /*            ROI  6 = 1572                 */
  /*            ROI  7 = 1584                 */
  /*            ROI  8 = 1596                 */
  /*            ROI  9 = 1608                 */
  /*            ROI 10 = 1620                 */
  char          FlatField[120];    /* 1632 Flat field file name.               */
  char          background[120];   /* 1752 Background sub. file name.          */
  char          blemish[120];      /* 1872 Blemish file name.                  */
  float		  file_header_ver;   /* 1992 Version of this file header		 */
  char          UserInfo[1000];    /* 1996-2995 user data.                     */     
  int32_t          WinView_id;        /* 2996 Set to 0x01234567L if file was      */
  /*      created by WinX                     */

  /*                        START OF X CALIBRATION STRUCTURE                      */

  double        xcal_offset;            /* 3000  offset for absolute data scaling   */
  double        xcal_factor;            /* 3008  factor for absolute data scaling   */
  char          xcal_current_unit;      /* 3016  selected scaling unit              */
  char          xcal_reserved1;         /* 3017  reserved                           */
  char          xcal_string[40];        /* 3018  special string for scaling         */
  char          xcal_reserved2[40];     /* 3058  reserved                           */
  char          xcal_calib_valid;       /* 3098  flag if calibration is valid       */
  char          xcal_input_unit;        /* 3099  current input units for            */
  /*       "calib_value"                      */
  char          xcal_polynom_unit;      /* 3100  linear UNIT and used               */
  /*       in the "polynom_coeff"             */
  char          xcal_polynom_order;     /* 3101  ORDER of calibration POLYNOM       */
  char          xcal_calib_count;       /* 3102  valid calibration data pairs       */
  double        xcal_pixel_position[10];/* 3103  pixel pos. of calibration data     */
  double        xcal_calib_value[10];   /* 3183  calibration VALUE at above pos     */
  double        xcal_polynom_coeff[6];  /* 3263  polynom COEFFICIENTS               */
  double        xcal_laser_position;    /* 3311  laser wavenumber for relativ WN    */
  char          xcal_reserved3;         /* 3319  reserved                           */
  unsigned char xcal_new_calib_flag;    /* 3320  If set to 200, valid label below   */
  char          xcal_calib_label[81];   /* 3321  Calibration label (NULL term'd)    */
  char          xcal_expansion[87];     /* 3402  Calibration Expansion area         */

  /*                        START OF Y CALIBRATION STRUCTURE                      */

  double        ycal_offset;            /* 3489  offset for absolute data scaling   */
  double        ycal_factor;            /* 3497  factor for absolute data scaling   */
  char          ycal_current_unit;      /* 3505  selected scaling unit              */
  char          ycal_reserved1;         /* 3506  reserved                           */
  char          ycal_string[40];        /* 3507  special string for scaling         */
  char          ycal_reserved2[40];     /* 3547  reserved                           */
  char          ycal_calib_valid;       /* 3587  flag if calibration is valid       */
  char          ycal_input_unit;        /* 3588  current input units for            */
  /*       "calib_value"                      */
  char          ycal_polynom_unit;      /* 3589  linear UNIT and used               */
  /*       in the "polynom_coeff"             */
  char          ycal_polynom_order;     /* 3590  ORDER of calibration POLYNOM       */
  char          ycal_calib_count;       /* 3591  valid calibration data pairs       */
  double        ycal_pixel_position[10];/* 3592  pixel pos. of calibration data     */
  double        ycal_calib_value[10];   /* 3672  calibration VALUE at above pos     */
  double        ycal_polynom_coeff[6];  /* 3752  polynom COEFFICIENTS               */
  double        ycal_laser_position;    /* 3800  laser wavenumber for relativ WN    */
  char          ycal_reserved3;         /* 3808  reserved                           */
  unsigned char ycal_new_calib_flag;    /* 3809  If set to 200, valid label below   */
  char          ycal_calib_label[81];   /* 3810  Calibration label (NULL term'd)    */
  char          ycal_expansion[87];     /* 3891  Calibration Expansion area         */

  /*                         END OF CALIBRATION STRUCTURES                        */

  char          Istring[40];       /* 3978  special Intensity scaling string   */
  char          empty3[80];        /* 4018  empty block to reach 4100 bytes    */
  int16_t           lastvalue;         /* 4098 Always the LAST value in the header */
} __attribute__ ((__packed__));

static const unsigned char spe_header[4]= {0x67, 0x45, 0x23, 0x01};

static void register_header_check_spe(file_stat_t *file_stat)
{
  register_header_check(0xbb4, spe_header,sizeof(spe_header), &header_check_spe, file_stat);
}

static int header_check_spe(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_spe *spe=(const struct header_spe*)buffer;
  if(le32(spe->WinView_id)==0x01234567L && le16(spe->lastvalue)==0x5555)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_spe.extension;
    file_recovery_new->min_filesize=4100;
    file_recovery_new->calculated_file_size=(uint64_t)le16(spe->xdim)*le16(spe->ydim)*le32(spe->NumFrames);
    file_recovery_new->calculated_file_size*=(le16(spe->datatype)<=1?4:2);
    file_recovery_new->calculated_file_size+=4100;
    log_debug("spe xdim=%u ydim=%u NumFrames=%u datatype=%u size=%llu\n",
        le16(spe->xdim), le16(spe->ydim), (unsigned int)le32(spe->NumFrames), le16(spe->datatype),
        (long long unsigned) file_recovery_new->calculated_file_size);
    file_recovery_new->data_check=&data_check_size;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
  return 0;
}
