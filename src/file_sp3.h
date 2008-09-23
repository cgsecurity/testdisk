/*

    File: file_sp3.h

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

/* Special thanks to Paulo Sousa for providing the information */

struct SP3FileInfo
{
  uint8_t	Versao;
  uint8_t	Revisao;
  char		zzReserved001[6];
  uint16_t	DataExameAno;			/* 2 bytes   (   9 -  10 ) */
  uint8_t    	DataExameMes;			/* 1 bytes   (    11     ) */
  uint8_t    	DataExameDia;			/* 1 bytes   (    12     ) */
  uint8_t    	DataExameHora;			/* 1 bytes   (    13     ) */
  uint8_t    	DataExameMinutos;		/* 1 bytes   (    14     ) */
  uint8_t    	DataExameSegundos;		/* 1 bytes   (    15     ) */
  uint8_t       zzReserved002;			/* 1 bytes   (    16     ) */
  uint32_t  	DuracaoExameMilisegundos;	/* 4 bytes   (  17 -  20 ) */
  char   	zzReserved003[6];		/* 6 bytes   (  21 -  26 ) */
  uint32_t    	TipoDeMonitorFetal;		/* 4 bytes   (  27 -  30 ) */
  char     	zzReserved004[2];		/* 2 bytes   (  31 -  32 ) */

  char     	LocalCod[6];			/* 6 bytes   (  33 -  38 ) */
    
  char         	zzReserved005[2];		/* 2 bytes   (  39 -  40 ) */
        
  char     	LocalNome[128];			/* 128 bytes (  41 - 168 ) */
  char     	LocalServicePlace[6];		/* 6 bytes   ( 169 - 174 ) */
    
  char         	zzReserved006[2];		/* 2 bytes   ( 175 - 176 ) */

  char     	FileName[64];			/* 64 bytes  ( 177 - 240 ) */
    
  char     	LocalBedOrDevice[4];		/* 4 bytes   ( 241 - 244 ) */
    
  char       	zzReserved007[12];		/* 12 bytes  ( 245 - 256 ) */

  char     	NumeroDoente[16];		/* 16 bytes  ( 257 - 272 ) */
  char         	zzReserved008[8];		/* 8 bytes   ( 273 - 280 ) */

  char     	NomeDoente[128];		/* 128 bytes ( 281 - 408 ) */
  uint16_t  	DataNascimentoAnoDoente;	/* 2 bytes   ( 409 - 410 ) */
  uint8_t    	DataNascimentoMesDoente;	/* 1 bytes   (    411    ) */
  uint8_t    	DataNascimentoDiaDoente;	/* 1 bytes   (    412    ) */
  uint8_t       zzReserved009;			/* 1 bytes   (    413    ) */
  uint8_t    	IdadeDoente;			/* 1 bytes   (    414    ) */
  char   	zzReserved010[3];		/* 3 bytes   ( 415 - 417 ) */
  uint8_t    	NumeroFetos;			/* 1 bytes   (    418    ) */
  uint8_t       zzReserved011;			/* 1 bytes   (    419    ) */
  uint8_t    	NumeroMeses;			/* 1 bytes   (    420    ) */
  char   	zzReserved012[5];		/* 5 bytes   ( 421 - 425 ) */
  uint8_t    	InvalidPointsA;			/* 1 bytes   (    426    ) */
  uint8_t       zzReserved013;			/* 1 bytes   (    427    ) */
  uint8_t    	GoodConfidencePointsA;		/* 1 bytes   (    428    ) */
  uint8_t       zzReserved014;			/* 1 bytes   (    429    ) */
  uint8_t    	ExcelentConfidencePointsA;	/* 1 bytes   (    430    ) */
  char   	zzReserved015[3];		/* 3 bytes   ( 431 - 433 ) */
  uint8_t    	InvalidPointsB;			/* 1 bytes   (    434    ) */
  uint8_t       zzReserved016;			/* 1 bytes   (    435    ) */
  uint8_t    	GoodConfidencePointsB;		/* 1 bytes   (    436    ) */
  uint8_t       zzReserved017;			/* 1 bytes   (    437    ) */
  uint8_t    	ExcelentConfidencePointsB;	/* 1 bytes   (    438    ) */

  char     	NumeroEpisodioUrgencia[16];	/* 16 bytes  ( 439 - 454 ) */
  char     	NumeroEpisodioInternamento[16];	/* 16 bytes  ( 455 - 470 ) */
  char     	NumeroEpisodioConsulta[16];	/* 16 bytes  ( 471 - 486 ) */
  char  	NumeroEpisodioAdicional[16];	/* 16 bytes  ( 487 - 502 ) */

  char		TipoDePesquisa_OLD;            	/* 1 bytes   (    503    ) */
    
  uint16_t	idTipoDePesquisa;		/* 2 bytes   ( 504 -  505) */

  char      	zzReserved018[11];            	/* 11 bytes  ( 506 - 516 ) */

  uint32_t    	ScaleFactorUc;			/* 4 bytes   ( 517 - 520 ) */

  uint32_t    	ProbeTypeFHR_A;			/* 4 bytes   ( 521 - 524 ) */
  uint32_t    	ProbeTypeFHR_B;			/* 4 bytes   ( 525 - 528 ) */

  uint32_t    	InternalDataBaseKey_OLD;	/* 4 bytes   ( 529 - 532) */
    
  char         	zzReserved019[4];		/* 4 bytes   ( 533 - 536) */

  /*------------------------------------------------------------------------*/
  /*Tamanho Antigo*/
  char     	ExternalDataBaseKey[38];	/* 38 bytes  ( 537 - 574) */
  /*------------------------------------------------------------------------*/
    
    
  /* UID PACIENTE INTERNO*/
  /* {480B57BB-CD71-4D48-A912-000000000000}*/
  /* 123456789 123456789 123456789 12345678   - Tamanho 38*/
  char     	InternalDataBaseKey__NEW[38];	/* 38 bytes  ( 575 - 612) */
    
  char         	zzReserved0201[2];		/* 2 bytes  ( 613 - 614) */
    
  /* UID EXAME CODE INTERNO	*/
  /* {480B57BB-CD71-4D48-A000-000000000000} */
  char     	ExameDataBase_UID[38];		/* 38 bytes  ( 612 - 652) */
        
  char         	zzReserved0202[2];		/* 2 bytes  ( 653 - 654) */
    
  char     	PartogramaDataBase_UID[38];	/* 38 bytes  ( 655 - 692) */
    
  char         	zzReserved0203[8];		/* 30 bytes  ( 693 - 700) */

  uint32_t    	TimeBaseDelta_POS;		/* 4 bytes   ( 701 - 704) */
  uint32_t    	TimeBaseDelta_LEN;		/* 4 bytes   ( 705 - 708) */
  uint32_t    	TimeBaseDelta_CRC32;		/* 4 bytes   ( 709 - 712) */
  char         	zzReserved021[8];		/* 8 bytes   ( 713 - 720) */


  uint32_t    	ExtraInfoFlag_POS;		/* 4 bytes   ( 721 - 724) */
  uint32_t    	ExtraInfoFlag_LEN;		/* 4 bytes   ( 725 - 728) */
  uint32_t    	ExtraInfoFlag_CRC32;		/* 4 bytes   ( 729 - 732) */
  char         	zzReserved022[8];		/* 8 bytes   ( 733 - 740) */

  uint32_t    	FHRa_POS; 
  uint32_t    	FHRa_LEN; 
  uint32_t    	FHRa_CRC32; 
  char         	zzReserved023[8];		/* 8 bytes   ( --- - 760) */

  uint32_t    	FHRb_POS; 
  uint32_t    	FHRb_LEN; 
  uint32_t    	FHRb_CRC32; 
  char         	zzReserved024[8];		/* 8 bytes   ( --- - 780) */

  uint32_t    	UC_POS; 
  uint32_t    	UC_LEN; 
  uint32_t    	UC_CRC32; 
  char         	zzReserved025[8];		/* 8 bytes   ( --- - 800) */


  uint32_t    	FM_POS; 
  uint32_t    	FM_LEN; 
  uint32_t    	FM_CRC32; 
  char         	zzReserved026[8];		/* 8 bytes   ( --- - 820) */

  uint32_t    	MHR_POS; 
  uint32_t    	MHR_LEN; 
  uint32_t    	MHR_CRC32; 
  char         	zzReserved027[8];		/* 8 bytes   ( --- - 840) */

    /*-----------------------------------------------------------------------------------*/

  uint32_t    	Fetal_SpO2_POS_POS; 
  uint32_t    	Fetal_SpO2_POS_LEN; 
  uint32_t    	Fetal_SpO2_POS_CRC32; 
  char         	zzReserved028[8];		/* 8 bytes   ( --- - 860) */

  uint32_t    	Fetal_SpO2_POS; 
  uint32_t    	Fetal_SpO2_LEN; 
  uint32_t    	Fetal_SpO2_CRC32; 
  char         	zzReserved029[8];		/* 8 bytes   ( --- - 880) */


    /*-----------------------------------------------------------------------------------*/
    

  uint32_t    	Pressure_POS_POS; 
  uint32_t    	Pressure_POS_LEN; 
  uint32_t    	Pressure_POS_CRC32; 
  char         	zzReserved030[8];		/* 8 bytes   ( --- - 900) */

  uint32_t    	Pressure_Systolic_BP_POS; 
  uint32_t    	Pressure_Systolic_BP_LEN; 
  uint32_t    	Pressure_Systolic_BP_CRC32; 
  char         	zzReserved031[8];		/* 8 bytes   ( --- - 920) */

  uint32_t    	Pressure_Diastolic_BP_POS; 
  uint32_t    	Pressure_Diastolic_BP_LEN; 
  uint32_t    	Pressure_Diastolic_BP_CRC32; 
  char         	zzReserved032[8];		/* 8 bytes   ( --- - 940) */


  uint32_t    	Pressure_Mean_BP_POS; 
  uint32_t    	Pressure_Mean_BP_LEN; 
  uint32_t    	Pressure_Mean_BP_CRC32; 
  char         	zzReserved033[8];		/* 8 bytes   ( --- - 960) */

  uint32_t    	Pressure_NIBP_MHR_POS; 
  uint32_t    	Pressure_NIBP_MHR_LEN; 
  uint32_t    	Pressure_NIBP_MHR_CRC32; 
  char         	zzReserved034[8];		/* 8 bytes   ( --- - 980) */

  /*-----------------------------------------------------------------------------------*/
    
  uint32_t    	Maternal_POS_POS; 
  uint32_t    	Maternal_POS_LEN; 
  uint32_t    	Maternal_POS_CRC32; 
  char         	zzReserved035[8];		/* 8 bytes   ( ---- - 1000) */

  uint32_t    	Maternal_SpO2_POS; 
  uint32_t    	Maternal_SpO2_LEN; 
  uint32_t    	Maternal_SpO2_CRC32; 
  char         	zzReserved036[8];		/* 8 bytes   ( ---- - 1020) */

  uint32_t    	Maternal_HR_POS; 
  uint32_t    	Maternal_HR_LEN; 
  uint32_t    	Maternal_HR_CRC32; 
  char         	zzReserved037[8];		/* 8 bytes   ( ---- - 1040) */

  /*-----------------------------------------------------------------------------*/

  uint32_t    	Event_POS_POS; 
  uint32_t    	Event_POS_LEN; 
  uint32_t    	Event_POS_CRC32; 
  char         	zzReserved038[8];		/* 8 bytes   ( ---- - 1060) */

  uint32_t    	Event_TYPE_POS; 
  uint32_t    	Event_TYPE_LEN; 
  uint32_t    	Event_TYPE_CRC32; 
  char         	zzReserved039[8];		/* 8 bytes   ( ---- - 1080) */

  uint32_t    	Event_DESC_POS; 
  uint32_t    	Event_DESC_LEN; 
  uint32_t    	Event_DESC_CRC32; 
  char         	zzReserved040[8];		/* 4 bytes   ( ---- - 1100) */

  /*-----------------------------------------------------------------------------*/
    
  uint32_t    	TQRS_POS_POS; 
  uint32_t    	TQRS_POS_LEN; 
  uint32_t    	TQRS_POS_CRC32; 
  char         	zzReserved041[8];		/* 8 bytes   ( ---- - 1120) */

  uint32_t    	TQRS_Status_POS; 
  uint32_t    	TQRS_Status_LEN; 
  uint32_t    	TQRS_Status_CRC32; 
  char         	zzReserved042[8];		/* 8 bytes   ( ---- - 1140) */

  uint32_t    	TQRS_Value_POS; 
  uint32_t    	TQRS_Value_LEN; 
  uint32_t    	TQRS_Value_CRC32; 
  char         	zzReserved043[8];		/* 8 bytes   ( ---- - 1160) */

  uint32_t    	TQRS_Biphasic_POS; 
  uint32_t    	TQRS_Biphasic_LEN; 
  uint32_t    	TQRS_Biphasic_CRC32; 
  char         	zzReserved044[8];		/* 8 bytes   ( ---- - 1180) */

  /*-----------------------------------------------------------------------------*/
   
  uint32_t    	Error_POS_POS; 
  uint32_t    	Error_POS_LEN; 
  uint32_t    	Error_POS_CRC32; 
  char         	zzReserved045[8];		/* 8 bytes   ( ---- - 1200) */

  uint32_t    	Error_TYPE_POS; 
  uint32_t    	Error_TYPE_LEN; 
  uint32_t    	Error_TYPE_CRC32; 
  char         	zzReserved046[8];		/* 8 bytes   ( ---- - 1220) */

  uint32_t    	Error_DESC_POS; 
  uint32_t    	Error_DESC_LEN; 
  uint32_t    	Error_DESC_CRC32; 
  char         	zzReserved047[8];		/* 8 bytes   ( ---- - 1240) */

  /*-----------------------------------------------------------------------------*/
  /*CommBUFFER*/
    
  uint32_t    	CommBUFFER_POS; 
  uint32_t    	CommBUFFER_LEN; 
  uint32_t    	CommBUFFER_CRC32; 
  char         	zzReserved048[8];		/* 8 bytes   ( ---- - 1260) */
        
  /*-----------------------------------------------------------------------------*/
    
    
  uint32_t    	Prove_FHRa_POS; 
  uint32_t    	Prove_FHRa_LEN; 
  uint32_t    	Prove_FHRa_CRC32; 
    
  char         	zzReserved049[8];		/* 8 bytes   ( ---- - 1280) */

  uint32_t    	Prove_FHRb_POS; 
  uint32_t    	Prove_FHRb_LEN; 
  uint32_t    	Prove_FHRb_CRC32; 
    
  char         	zzReserved050[8];		/* 8 bytes   ( ---- - 1300) */
         
  uint32_t    	Prove_UC_POS; 
  uint32_t    	Prove_UC_LEN; 
  uint32_t    	Prove_UC_CRC32; 
   
  char 		zzReserved999[1024*10-1312];
} __attribute__ ((__packed__));
