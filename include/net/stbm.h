#ifndef _STBM_H
#define _STBM_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/std_types.h>
#include <linux/rte_stbm_type.h>

typedef uint16_t StbM_SynchronizedTimeBaseType;
typedef uint32_t StbM_TimeStampRawType;

/* StbMGeneral */
extern bool StbMDevErrorDetect;
extern bool StbMGetCurrentTimeExtendedAvailable;
extern uint32_t StbMMainFunctionPeriod;	/* Standard using floating point to present from 1E-6 to INF */
extern bool StbMVersionInfo;

/* StbMSynchronizedTimeBase */
extern bool StbMIsSystemWideGlobalTimeMaster;
enum {
  	NO_STORAGE=0,
	STORAGE_AT_SHUTDOWN
} StbMStoreTimebaseNonVolatile;
extern uint32_t StbMSyncLossThreshold; 	/* Standard using floating point to present 0 to INF SEC(s) */
extern uint32_t StbMSyncLossTimeout;	/* Standard using floating point to present 0 to INF SEC(s) */
extern uint16_t StbMSynchronizedTimeBaseIdentifier;
//extern Unknown StbMEthGlobalTimeDomainRef; /* Reference to EthTSyncGloblaTimeDomain */
//extern Unknown StbMLocalTimeRef; /* Reference to OsCounter */
//extern Unknown StbMOffsetTimeBase; /* Reference to StbMSynchronizedTimeBase */

/* StbMTriggeredCustomer */
extern uint32_t StbMTriggeredCustomerPeriod;
//extern Unknown StbMOSScheduleTableRef; /* Reference to OsScheduleTable */
//extern Unknown StbMSynchronizedTimeBaseRef; /* Reference to StbMSynchronizedTimeBase*/

extern void 		StbM_GetVersionInfo(void);
extern void		StbM_Init(void);
extern Std_ReturnType	StbM_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
					    StbM_TimeStampType*	timeStampPtr,
					    StbM_UserDataType* userDataPtr);
extern Std_ReturnType	StbM_GetCurrentTimeExtended(StbM_SynchronizedTimeBaseType timeBaseId, 
						    StbM_TimeStampExtendedType* timeStampPtr, 
						    StbM_UserDataType* userDataPtr);
extern Std_ReturnType	StbM_GetCurrentTimeRaw(StbM_TimeStampRawType* timeStampRawPtr);
extern Std_ReturnType	StbM_GetCurrentTimeDiff(StbM_TimeStampRawType givenTimeStamp,
						StbM_TimeStampRawType* timeStampDiffPtr);
extern Std_ReturnType	StbM_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					   StbM_TimeStampType* timeStampPtr,
					   StbM_UserDataType* userDataPtr);
extern Std_ReturnType	StbM_SetUserData(StbM_SynchronizedTimeBaseType timeBaseId, 
					 StbM_UserDataType* userDataPtr);
extern Std_ReturnType	StbM_SetOffset(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr);
extern Std_ReturnType	StbM_GetOffset(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr);
extern Std_ReturnType	StbM_BusSetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					      StbM_TimeStampType* timeStampPtr, 
					      StbM_UserDataType* userDataPtr,
					      bool syncToTimeBase);
extern void 		StbM_MainFunction(void);

#endif
