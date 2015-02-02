#ifndef _COMSTACK_CFG_H
#define _COMSTACK_CFG_H

#include <linux/types.h>
#include <linux/kernel.h>

//dependent on setting
#define PDU_ID_MAX_255

#ifdef PDU_ID_MAX_255
#define PDU_ID_MAX 255
typedef uint8_t 	PduIdType;
#else
#define PDU_ID_MAX 65535
typedef uint16_t 	PduIdType;
#endif

#define PDU_LENGTH_TYPE_8

#ifdef PDU_LENGTH_TYPE_8

#define PDU_LENGTH_MAX 255
typedef uint8_t		PduLengthType;

#else 

#ifdef PDU_LENGTH_TYPE_16

#define PDU_LEGNTH_MAX 65535
typedef uint16_t 	PduLengthType;

#else 

#define PDU_LENGTH_MAX UINT_MAX
typedef uint32_t	PduLengthType;

#endif /* end of PDU_LENGTH_TYPE_16 */

#endif /* end of PDU_LENGTH_TYPE_8*/

#endif /* end of _COMSTACK_CFG_H */
