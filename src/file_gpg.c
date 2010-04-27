/*

    File: file_gpg.c

    Copyright (C) 2008 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#include "common.h"
#include "filegen.h"
#include "log.h"

static void register_header_check_gpg(file_stat_t *file_stat);
static int header_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int data_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery);
static unsigned int openpgp_packet_tag(const unsigned char *buf);
static unsigned int openpgp_length_type(const unsigned char *buf, unsigned int *length_type);

const file_hint_t file_hint_gpg= {
  .extension="gpg",
  .description="OpenPGP (Partial support)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gpg
};

/* See rfc4880 OpenPGP Message Format */

static const unsigned char gpg_header_pkey_enc[1]= {0x85};
static const unsigned char gpg_header_seckey[1]= {0x95};
#if 0
static const unsigned char gpg_header_pkey[1]= {0x99};
#endif

static void register_header_check_gpg(file_stat_t *file_stat)
{
  register_header_check(0, gpg_header_seckey, sizeof(gpg_header_seckey), &header_check_gpg, file_stat);
  register_header_check(0, gpg_header_pkey_enc, sizeof(gpg_header_pkey_enc), &header_check_gpg, file_stat);
#if 0
  register_header_check(0, gpg_header_pkey, sizeof(gpg_header_pkey), &header_check_gpg, file_stat);
#endif
}


static unsigned int openpgp_packet_tag(const unsigned char *buf)
{
  /* Bit 7 -- Always one */
  if((buf[0]&0x80)==0)
    return 0;	/* Invalid */
  return ((buf[0]&0x40)==0?((buf[0]>>2)&0x0f):(buf[0]&0x3f));
}

static unsigned int openpgp_length_type(const unsigned char *buf, unsigned int *length_type)
{
  /* Bit 7 -- Always one */
  if((buf[0]&0x80)==0)
  {
    /* Invalid */
    *length_type=0;
    return 0;
  }
#ifdef DEBUG_GPG
  log_info("%02x %02x %02x %02x %02x %02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
#endif
  if((buf[0]&0x40)==0)
  {
    /* Old format */
#ifdef DEBUG_GPG
    log_info(" old_format\n");
#endif
    switch(buf[0]&0x3)
    {
      case 0:
	*length_type=2;
	return buf[1];
      case 1:
	*length_type=3;
	return (buf[1] << 8) | buf[2];
      case 2:
	*length_type=5;
	return (buf[1] << 24) |(buf[2] << 16) |  (buf[3] << 8) | buf[4];
      default:
	*length_type=1;
	return 0;
    }
  }
#ifdef DEBUG_GPG
  log_info(" new_format\n");
#endif
  /* One-Octet Lengths */
  if(buf[1]<=191)
  {
    *length_type=1;
    return buf[1];
  }
  /* Two-Octet Lengths */
  if(buf[1]<=223)
  {
    *length_type=2;
    return ((buf[1] - 192) << 8) + buf[2] + 192;
  }
  /* Five-Octet Lengths */
  if(buf[1]==255)
  {
    *length_type=5;
    return (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8)  | buf[5];
  }
  /* Partial Body Lengths */
  *length_type=1;
  return 1 << (buf[1]& 0x1F);
}

static  int is_valid_pubkey_algo(const int algo)
{
  /*  1          - RSA (Encrypt or Sign)
   *  2          - RSA Encrypt-Only
   *  3          - RSA Sign-Only
   *  16         - Elgamal (Encrypt-Only), see [ELGAMAL]
   *  17         - DSA (Digital Signature Standard)
   *  18         - Reserved for Elliptic Curve
   *  19         - Reserved for ECDSA
   *  20         - Elgamal (Encrypt or Sign)
   *  21         - Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
   *  100 to 110 - Private/Experimental algorith
   */
  if(algo>=100 && algo<=100)
    return 1;
  switch(algo)
  {
    case 1:
    case 2:
    case 3:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
      return 1;
    default:
      return 0;
  }
}

static int header_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int potential_frame_offset=0;
  unsigned int packet_tag[5];
  unsigned int length_type[5];
  unsigned int length[5];
  unsigned int nbr=0;
  unsigned int i;
  int start_recovery=0;
  memset(packet_tag, 0, sizeof(packet_tag));
  memset(length_type, 0, sizeof(length_type));
  memset(length, 0, sizeof(length));
  while(nbr<5 && potential_frame_offset < buffer_size - 5)
  {
    packet_tag[nbr]=openpgp_packet_tag(&buffer[potential_frame_offset]);
    if(packet_tag[nbr]==0)	/* Reserved */
      break;
    length[nbr]=openpgp_length_type(&buffer[potential_frame_offset], &length_type[nbr]);
    if(length_type[nbr]==0)
      break;	/* Don't know how to find the size */
    potential_frame_offset+=length_type[nbr];
    potential_frame_offset+=length[nbr];
    nbr++;
  }
  if(nbr<2)
    return 0;
#ifdef DEBUG_GPG
  for(i=0;i<nbr;i++)
  {
    log_info("%02u gpg tag %u, size=%u (0x%x - %u)\n",
	i, packet_tag[i], length[i], length[i], length_type[i]);
  }
#endif
  /* Public-Key Encrypted Session Key Packet v3 */
  if(buffer[0]==0x85 && buffer[3]==0x03 && is_valid_pubkey_algo(buffer[3+1+8]))
  {
    for(i=1;i<nbr;i++)
    {
      /* Sym. Encrypted and Integrity Protected Data Packet */
      if(packet_tag[i]==18)
      {
	start_recovery=1;
	break;
      }
      /* Public-Key Encrypted Session Key Packet */
      else if(packet_tag[i]!=1)
	return 0;
    }
  }
  if(start_recovery>0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_gpg.extension;
    return 1;
  }
  /* Secret-Key Packet v4 followed by User ID Packet */
  if(buffer[0]==0x95 && buffer[3]==0x04 && packet_tag[1]==13 && is_valid_pubkey_algo(buffer[8])>0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->extension=file_hint_gpg.extension;
    file_recovery_new->data_check=&data_check_gpg;
    file_recovery_new->file_check=&file_check_size;
    return 1;
  }
    /* algo buffer[8]*/
  /* Public-Key Packet + User ID Packet */
#if 0
  if(buffer[0]==0x99 && packet_tag[1]==13)
    start_recovery=1;
#endif
  return 0;
}

static int data_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 < file_recovery->file_size + buffer_size/2)
  {
    unsigned int packet_tag;
    unsigned int length_type;
    unsigned int length;
    unsigned int i=file_recovery->calculated_file_size - file_recovery->file_size + buffer_size/2;
    packet_tag=openpgp_packet_tag(&buffer[i]);
    if(packet_tag==0)	/* Reserved */
      return 2;
    length=openpgp_length_type(&buffer[i], &length_type);
    if(length_type==0)
      return 2;	/* Don't know how to find the size */
#ifdef DEBUG_GPG
    log_info("gpg tag %u, size=%u\n", packet_tag, length);
#endif
    file_recovery->calculated_file_size+=length_type;
    file_recovery->calculated_file_size+=length;
  }
  return 1;
}

