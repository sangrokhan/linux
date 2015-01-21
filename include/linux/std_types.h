/*
 * WIDEN AUTOSAR SOURCE CODE
 * Create Date 2015-01-21
 * Create By   Sangrok Han
 */

#ifndef STD_TYPES_H
#define STD_TYPES_H

#include <linux/types.h>

#ifndef	STATUSTYPEDEFINED
#define STATUSTYPEDEFINED
#define E_OK		0x00u
typedef uint8_t Std_ReturnType;	/* OSEK compliance */
#endif
#define E_NOT_OK	0x01u

typedef struct {
  	uint16_t	vendorID;
	uint16_t	moduleID;
	uint8_t		sw_major_version;
	uint8_t		sw_minor_version;
	uint8_t		sw_patch_version;
} Std_versionInfoType;

#define STD_HIGH	0x01u	/* Physical state 5V or 3.3V */
#define STD_LOW		0x00u 	/* Physical state 0V */

#define STD_ACTIVE	0x01u	/* Logical state active */
#define STD_IDLE	0x00u	/* Logical state idle */

#define STD_ON		0x01u
#define STD_OFF		0x00u

#endif
