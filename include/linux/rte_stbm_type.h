#ifndef RTE_STBM_TYPE_H
#define RTE_STBM_TYPE_H

#include <linux/types.h>
#include <linux/std_types.h>

typedef uint16_t StbM_SynchronizedTimeBaseType;

typedef struct {
  	unsigned 		TIMEOUT			:	1;
	unsigned 		TIMELEAP		:	1;
	unsigned 		SYNC_TO_GATEWAY		:	1;
  	unsigned 		GLOBAL_TIME_BASE	:	1;
  	unsigned 		rsv 			:	4;
} StbM_TimeBaseStatusType;

typedef struct {
  	StbM_TimeBaseStatusType timeBaseStatus;
  	uint32_t 		nanoseconds;
	uint32_t		seconds;
  	uint16_t		secondsHi;
} StbM_TimeStampType;

typedef struct {
  	StbM_TimeBaseStatusType	timeBaseStatus;
  	uint32_t		nanoseconds;
  	uint64_t		seconds;
} StbM_TimeStampExtendedType;

typedef struct {
  	uint8_t			userDataLength;
  	uint8_t			userByte0;
  	uint8_t			userByte1;
  	uint8_t			userByte2;
} StbM_UserDataType;

#endif
