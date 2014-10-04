/*

    File: file_gpg.c

    Copyright (C) 2008-2012 Christophe GRENIER <grenier@cgsecurity.org>
  
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
#ifdef DEBUG_GPG
#include "log.h"
#endif

static void register_header_check_gpg(file_stat_t *file_stat);
static int header_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_gpg= {
  .extension="gpg",
  .description="OpenPGP/GPG (Partial support)",
  .min_header_distance=0,
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_gpg
};

/* See rfc4880 OpenPGP Message Format */

/* Public-Key Encrypted Session Key Packets */
#define OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY	1
/* Signature Packet */
#define OPENPGP_TAG_SIGNATURE			2
/* Symmetric-Key Encrypted Session Key Packets */
#define OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY	3
/* One-Pass Signature Packets (Tag 4) */
#define OPENPGP_TAG_ONE_PASS_SIG		4
/* Secret-Key Packet (Tag 5) */
#define OPENPGP_TAG_SEC_KEY			5
/* Public-Key Packet (Tag 6)*/
#define OPENPGP_TAG_PUB_KEY			6
/* Secret-Subkey Packet (Tag 7)	*/
#define OPENPGP_TAG_SEC_SUBKEY			7
/* Compressed Data Packet (Tag 8) */
/* Symmetrically Encrypted Data Packet */
#define OPENPGP_TAG_SYM_ENC_DATA		9
/* Marker Packet (Tag 10) */
#define OPENPGP_TAG_MARKER			10
/* Literal Data Packet (Tag 11)
 * Trust Packet (Tag 12) */
#define OPENPGP_TAG_TRUST			12
 /* User ID Packet */
#define OPENPGP_TAG_USER_ID			13
 /* Public-Subkey Packet (Tag 14) */
#define OPENPGP_TAG_PUB_SUBKEY			14
/* User Attribute Packet (Tag 17)
 */
/* Sym. Encrypted Integrity Protected Data Packet */
#define OPENPGP_TAG_SYM_ENC_INTEGRITY		18
 /* Modification Detection Code Packet (Tag 19) */

static const unsigned char pgp_header[5]= {0xa8, 0x03, 'P', 'G', 'P'};

static void register_header_check_gpg(file_stat_t *file_stat)
{
  static const unsigned char gpg_header_pkey_enc[1]= {0x85};
  static const unsigned char gpg_header_symkey_enc[1]= {0x8c};
  static const unsigned char gpg_header_seckey[1]= {0x95};
#if 1
  static const unsigned char gpg_header_pkey[1]= {0x99};
#endif
  register_header_check(0, gpg_header_seckey, sizeof(gpg_header_seckey), &header_check_gpg, file_stat);
  register_header_check(0, gpg_header_symkey_enc, sizeof(gpg_header_symkey_enc), &header_check_gpg, file_stat);
  register_header_check(0, gpg_header_pkey_enc, sizeof(gpg_header_pkey_enc), &header_check_gpg, file_stat);
  register_header_check(0, pgp_header, sizeof(pgp_header), &header_check_gpg, file_stat);
#if 1
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

static unsigned int old_format_packet_length(const unsigned char *buf, unsigned int *length_type, int *indeterminate_length)
{
  /* Old format */
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
      *indeterminate_length=1;
      return 0;
  }
}

static unsigned int new_format_packet_length(const unsigned char *buf, unsigned int *length_type, int *partial_body_length)
{
  *partial_body_length=0;
  /* One-Octet Body Length */
  if(buf[0]<=191)
  {
    *length_type=1;
    return buf[0];
  }
  /* Two-Octet Body Length */
  if(buf[0]<=223)
  {
    *length_type=2;
    return ((buf[0] - 192) << 8) + buf[1] + 192;
  }
  /* Five-Octet Body Length */
  if(buf[0]==255)
  {
    *length_type=5;
    return (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8)  | buf[4];
  }
  /* Partial Body Lengths */
  *length_type=1;
  *partial_body_length=1;
  return 1 << (buf[0]& 0x1F);
}

static int is_valid_mpi(const uint16_t *size)
{
  if(be16(*size) <= 16384)
    return (be16(*size)+7)/8;
  return -1;
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
   *  100 to 110 - Private/Experimental algorithm
   */
  switch(algo)
  {
    case 1:
    case 2:
    case 3:
    case 16:
    case 17:
    case 20:
      return 1;
    default:
      return 0;
  }
}

static int is_valid_sym_algo(const int algo)
{
  /*
       0          - Plaintext or unencrypted data
       1          - IDEA [IDEA]
       2          - TripleDES (DES-EDE, [SCHNEIER] [HAC] -
                    168 bit key derived from 192)
       3          - CAST5 (128 bit key, as per [RFC2144])
       4          - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
       5          - Reserved
       6          - Reserved
       7          - AES with 128-bit key [AES]
       8          - AES with 192-bit key
       9          - AES with 256-bit key
       10         - Twofish with 256-bit key [TWOFISH]
       100 to 110 - Private/Experimental algorithm
       */
  switch(algo)
  {
    case 1:
    case 2:
    case 3:
    case 4:
    case 7:
    case 8:
    case 9:
    case 10:
      return 1;
    default:
      return 0;
  }
}

static int is_valid_S2K(const unsigned int algo)
{
  /*  ID          S2K Type
   *  --          --------
   *  0           Simple S2K
   *  1           Salted S2K
   *  2           Reserved value
   *  3           Iterated and Salted S2K
   *  100 to 110  Private/Experimental S2K
   */
  return (algo==0 || algo==1 || algo==3);
}

static void file_check_gpg(file_recovery_t *file_recovery)
{
  unsigned int tag=0;
  unsigned int nbr=0;
  int partial_body_length=0;
  int stop=0;
  off_t offset=0;
  unsigned char buffer[32];
  const uint64_t org_file_size=file_recovery->file_size;
  file_recovery->file_size=0;
  while(stop==0)
  {
    unsigned int i=0;
    unsigned int length_type=0;
    unsigned int length;
    const int old_partial_body_length=partial_body_length;
    if(
#ifdef HAVE_FSEEKO
	fseeko(file_recovery->handle, offset, SEEK_SET) < 0 ||
#else
	fseek(file_recovery->handle, offset, SEEK_SET) < 0 ||
#endif
	fread(&buffer, sizeof(buffer), 1, file_recovery->handle) != 1)
      return;

    if(partial_body_length==0)
    {
      if((buffer[i]&0x80)==0)	
	break;	/* Invalid */
      tag=openpgp_packet_tag(&buffer[i]);
      if((buffer[i]&0x40)==0)
      {
	length=old_format_packet_length(&buffer[i], &length_type, &stop);
      }
      else
      {
	length=new_format_packet_length(&buffer[i+1], &length_type, &partial_body_length);
	length_type++;
      }
    }
    else
    {
      length=new_format_packet_length(&buffer[i], &length_type, &partial_body_length);
    }
#ifdef DEBUG_GPG
    log_info("GPG 0x%04x: %02u tag=%2u, size=%u + %u)\n",
	i, nbr, tag, length_type, length);
#endif
#if 0
    if(tag==0 || tag==15 || (tag>19 && tag!=61))	/* Reserved or unused */
      return;
#endif
    if(length_type==0)
      break;	/* Don't know how to find the size */
    i+=length_type;
    offset+=length_type;
    if(old_partial_body_length==0)
    {
      if(tag==OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY)
      {
	const uint16_t *mpi=(const uint16_t *)&buffer[i+1+8+1];
	const int len=is_valid_mpi(mpi);
	/* uint8_t  version	must be 3
	 * uint64_t pub_key_id
	 * uint8_t  pub_key_algo
	 *          encrypted_session_key	*/
	if(buffer[i]==3 && is_valid_pubkey_algo(buffer[i+1+8]) &&
	    len>0)
	{
#ifdef DEBUG_GPG
	  log_info("GPG :pubkey enc packet: version %u, algo %u, keyid %02X%02X%02X%02X%02X%02X%02X%02X\n",
	      buffer[i], buffer[i+1+8],
	      buffer[i+1], buffer[i+2], buffer[i+3], buffer[i+4],
	      buffer[i+5], buffer[i+6], buffer[i+7], buffer[i+8]);
	  log_info(" data: [ %u bits]\n", be16(*mpi));
#endif
	  if((unsigned)(1+8+1+2+len) > length)
	    return ;
	  if(buffer[i+1+8]==16 || buffer[i+1+8]==20)
	  {
	    int len2;
	    unsigned char tmp[2];
	    if(
#ifdef HAVE_FSEEKO
		fseeko(file_recovery->handle, offset+1+8+1+2+len, SEEK_SET) < 0 ||
#else
		fseek(file_recovery->handle, offset+1+8+1+2+len, SEEK_SET) < 0 ||
#endif
		fread(&tmp, sizeof(tmp), 1, file_recovery->handle) != 1)
	      return;
	    mpi=(const uint16_t *)&tmp[0];
	    len2=is_valid_mpi(mpi);
#ifdef DEBUG_GPG
	    log_info(" data: [ %u bits]\n", be16(*mpi));
#endif
	    if(len2 <= 0)
	      return ;
	    if((unsigned)(1+8+1+2+len+2+len2) > length)
	      return ;
	  }
	}
	else
	  return;
      }
      else if(tag==OPENPGP_TAG_SIGNATURE)
      {
	/* v3 - length=5 */
	if(buffer[i]==3 && buffer[i+1]==5 && is_valid_pubkey_algo(buffer[i+1+1+5+8]))
	{
#ifdef DEBUG_GPG
	  log_info(":signature packet: algo %u\n", buffer[i+1+1+5+8]);
	  log_info(":signature packet: sig_class 0x%02x\n", buffer[i+1+1]);
#endif
	}
	/* v4 */
	else if(buffer[i]==4 && is_valid_pubkey_algo(buffer[i+2]))
	{
#ifdef DEBUG_GPG
	  log_info(":signature packet: algo %u\n", buffer[i+2]);
#endif
	}
	else
	  return;
      }
      else if(tag==OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY)
      {
	/* v4 */
	if(buffer[i]==4 && is_valid_sym_algo(buffer[i+1]) && is_valid_S2K(buffer[i+2]))
	{
	}
	else
	  return;
      }
      else if(tag==OPENPGP_TAG_ONE_PASS_SIG)
      {
	if(buffer[i]==3 && is_valid_sym_algo(buffer[i+1]))
	{
	}
	else
	  return;
      }
      else if(tag==OPENPGP_TAG_SYM_ENC_DATA)
      {
      }
      else if(tag==OPENPGP_TAG_MARKER)
      {
	/* Must be at the beginning of the packet */
	if(nbr!=0)
	  return;
      }
      else if(tag==OPENPGP_TAG_SYM_ENC_INTEGRITY)
      {
#ifdef DEBUG_GPG
	log_info("GPG :encrypted data packet:\n");
#endif
	/* Version must be 1 */
	if(buffer[i]!=1)
	  return;
      }
      else if(tag==OPENPGP_TAG_PUB_KEY ||
	  tag==OPENPGP_TAG_PUB_SUBKEY ||
	  tag==OPENPGP_TAG_SEC_KEY||
	  tag==OPENPGP_TAG_SEC_SUBKEY)
      {
	if((buffer[i]==2 || buffer[i]==3) && is_valid_pubkey_algo(buffer[i+1+4+2]))
	{ /* version 2 or 3 */
	}
	else if(buffer[i]==4 && is_valid_pubkey_algo(buffer[i+1+4]))
	{ /* version 4 */
	}
	else
	  return;
      }
    }
    if(partial_body_length==0)
      nbr++;
    offset+=length;
  }
  if(nbr<2)
    return;
  file_recovery->file_size=(stop==0?org_file_size:(uint64_t)offset);
}

static int header_check_gpg(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned int packet_tag[16];
  unsigned int nbr=0;
  unsigned int i=0;
  int partial_body_length=0;
  int stop=0;
  memset(packet_tag, 0, sizeof(packet_tag));
  while(nbr<16 && i < buffer_size - 20 && stop==0)
  {
    unsigned int length_type=0;
    unsigned int tag;
    unsigned int length;
    const int old_partial_body_length=partial_body_length;
    if(partial_body_length==0)
    {
      if((buffer[i]&0x80)==0)	
	break;	/* Invalid */
      packet_tag[nbr]=openpgp_packet_tag(&buffer[i]);
      if((buffer[i]&0x40)==0)
      {
	length=old_format_packet_length(&buffer[i], &length_type, &stop);
      }
      else
      {
	length=new_format_packet_length(&buffer[i+1], &length_type, &partial_body_length);
	length_type++;
      }
    }
    else
    {
      length=new_format_packet_length(&buffer[i], &length_type, &partial_body_length);
    }
    tag=packet_tag[nbr];
#ifdef DEBUG_GPG
    log_info("GPG 0x%04x: %02u tag=%2u, size=%u + %u)\n",
	i, nbr, tag, length_type, length);
#endif
#if 0
    if(tag==0 || tag==15 || (tag>19 && tag!=61))	/* Reserved or unused */
      return 0;
#endif
    if(length_type==0)
      break;	/* Don't know how to find the size */
    i+=length_type;
    if(old_partial_body_length==0)
    {
      if(tag==OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY)
      {
	const uint16_t *mpi=(const uint16_t *)&buffer[i+1+8+1];
	const int len=is_valid_mpi(mpi);
	/* uint8_t  version	must be 3
	 * uint64_t pub_key_id
	 * uint8_t  pub_key_algo
	 *          encrypted_session_key	*/
	if(buffer[i]==3 && is_valid_pubkey_algo(buffer[i+1+8]) &&
	    len>0)
	{
#ifdef DEBUG_GPG
	  log_info("GPG :pubkey enc packet: version %u, algo %u, keyid %02X%02X%02X%02X%02X%02X%02X%02X\n",
	      buffer[i], buffer[i+1+8],
	      buffer[i+1], buffer[i+2], buffer[i+3], buffer[i+4],
	      buffer[i+5], buffer[i+6], buffer[i+7], buffer[i+8]);
	  log_info(" data: [ %u bits]\n", be16(*mpi));
#endif
	  if((unsigned)(1+8+1+2+len) > length)
	    return 0;
	  if((buffer[i+1+8]==16 || buffer[i+1+8]==20) &&
	      i+1+8+1+2+len+2<buffer_size)
	  {
	    int len2;
	    mpi=(const uint16_t *)&buffer[i+1+8+1+2+len];
	    len2=is_valid_mpi(mpi);
#ifdef DEBUG_GPG
	    log_info(" data: [ %u bits]\n", be16(*mpi));
#endif
	    if(len2 <= 0)
	      return 0;
	    if((unsigned)(1+8+1+2+len+2+len2) > length)
	      return 0;
	  }
	}
	else
	  return 0;
      }
      else if(tag==OPENPGP_TAG_SIGNATURE)
      {
	/* v3 - length=5 */
	if(buffer[i]==3 && buffer[i+1]==5 && is_valid_pubkey_algo(buffer[i+1+1+5+8]))
	{
#ifdef DEBUG_GPG
	  log_info(":signature packet: algo %u\n", buffer[i+1+1+5+8]);
	  log_info(":signature packet: sig_class 0x%02x\n", buffer[i+1+1]);
#endif
	}
	/* v4 */
	else if(buffer[i]==4 && is_valid_pubkey_algo(buffer[i+2]))
	{
#ifdef DEBUG_GPG
	  log_info(":signature packet: algo %u\n", buffer[i+2]);
#endif
	}
	else
	  return 0;
      }
      else if(tag==OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY)
      {
	/* v4 */
	if(buffer[i]==4 && is_valid_sym_algo(buffer[i+1]) && is_valid_S2K(buffer[i+2]))
	{
	}
	else
	  return 0;
      }
      else if(tag==OPENPGP_TAG_ONE_PASS_SIG)
      {
	if(buffer[i]==3 && is_valid_sym_algo(buffer[i+1]))
	{
	}
	else
	  return 0;
      }
      else if(tag==OPENPGP_TAG_SYM_ENC_DATA)
      {
	unsigned int j;
	int ok=0;
	/* The symmetric cipher used may be specified in a Public-Key or
	 * Symmetric-Key Encrypted Session Key packet that precedes the
	 * Symmetrically Encrypted Data packet.
	 * PhotoRec assumes it must */
	for(j=0; j<nbr; j++)
	{
	  if(packet_tag[j]==OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY ||
	      packet_tag[j]==OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY)
	    ok=1;
	}
	if(ok==0)
	  return 0;
      }
      else if(tag==OPENPGP_TAG_MARKER)
      {
	/* Must be at the beginning of the packet */
	if(nbr!=0)
	  return 0;
      }
      else if(tag==OPENPGP_TAG_SYM_ENC_INTEGRITY)
      {
	unsigned int j;
	int ok=0;
#ifdef DEBUG_GPG
	log_info("GPG :encrypted data packet:\n");
#endif
	/* Version must be 1 */
	if(buffer[i]!=1)
	  return 0;
	/* The symmetric cipher used MUST be specified in a Public-Key or
	 * Symmetric-Key Encrypted Session Key packet that precedes the
	 * Symmetrically Encrypted Data packet. */
	for(j=0; j<nbr; j++)
	{
	  if(packet_tag[j]==OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY ||
	      packet_tag[j]==OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY)
	    ok=1;
	}
	if(ok==0)
	  return 0;
      }
      else if(tag==OPENPGP_TAG_PUB_KEY ||
	  tag==OPENPGP_TAG_PUB_SUBKEY ||
	  tag==OPENPGP_TAG_SEC_KEY||
	  tag==OPENPGP_TAG_SEC_SUBKEY)
      {
	if((buffer[i]==2 || buffer[i]==3) && is_valid_pubkey_algo(buffer[i+1+4+2]))
	{ /* version 2 or 3 */
	}
	else if(buffer[i]==4 && is_valid_pubkey_algo(buffer[i+1+4]))
	{ /* version 4 */
	}
	else
	  return 0;
      }
    }
    if(partial_body_length==0)
      nbr++;
    i+=length;
  }
  if(nbr<2)
    return 0;
  if(memcmp(buffer, pgp_header, sizeof(pgp_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->file_check=&file_check_gpg;
    file_recovery_new->extension="pgp";
    return 1;
  }
  if( /* encrypted_data.gpg */
      ((packet_tag[0]==OPENPGP_TAG_PUBKEY_ENC_SESSION_KEY ||
	packet_tag[0]==OPENPGP_TAG_SYMKEY_ENC_SESSION_KEY) &&
       (packet_tag[1]==OPENPGP_TAG_SYM_ENC_DATA ||
	packet_tag[1]==OPENPGP_TAG_SYM_ENC_INTEGRITY)) ||
       /* pubring.gpg */
      (packet_tag[0]==OPENPGP_TAG_PUB_KEY &&
       packet_tag[1]==OPENPGP_TAG_USER_ID &&
       packet_tag[2]==OPENPGP_TAG_SIGNATURE &&
       packet_tag[3]==OPENPGP_TAG_TRUST) ||
      (packet_tag[0]==OPENPGP_TAG_PUB_KEY &&
       packet_tag[1]==OPENPGP_TAG_USER_ID &&
       packet_tag[2]==OPENPGP_TAG_SIGNATURE &&
       packet_tag[3]==OPENPGP_TAG_PUB_SUBKEY) ||
       /* secring.gpg */
      (packet_tag[0]==OPENPGP_TAG_SEC_KEY &&
       packet_tag[1]==OPENPGP_TAG_USER_ID &&
       packet_tag[2]==OPENPGP_TAG_SIGNATURE &&
       packet_tag[3]==OPENPGP_TAG_TRUST) ||
      (packet_tag[0]==OPENPGP_TAG_SEC_KEY &&
       packet_tag[1]==61 &&
       packet_tag[2]==61 &&
       packet_tag[3]==61)
    )
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->file_check=&file_check_gpg;
    file_recovery_new->extension=file_hint_gpg.extension;
    return 1;
  }
#ifdef DEBUG_GPG
  log_info("tag don't match: nbr=%u - ", nbr);
  for(i=0; i<nbr; i++)
    log_info(" %u", packet_tag[i]);
  log_info("\n");
#endif
  return 0;
}
