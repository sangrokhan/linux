#ifndef _COMSTACK_CFG_H
#define _COMSTACK_CFG_H

#include <linux/types.h>

//dependent on setting
#define PDU_ID_MAX_255

#ifdef PDU_ID_MAX_255
#define PDU_ID_MAX 255
uint8_t 	PduIdType;
#else
#define PDU_ID_MAX 65535
uint16_t 	PduIdType;
#endif

#define PDU_LENGTH_TYPE_8

#ifdef PDU_LENGTH_TYPE_8
#define PDU_LENGTH_MAX 255
uint8_t		PduLengthType;
#elseif PDU_LENGTH_TYPE_16
#define PDU_LEGNTH_MAX 65535
uint16_t 	

#endif
