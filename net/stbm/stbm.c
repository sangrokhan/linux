#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/export.h>
#include <linux/posix-clock.h>
#include <linux/std_types.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>
#include <net/ptp.h>

/* StbMSynchronizedTimeBase */
bool StbMIsSystemWideGlobalTimeMaster;
enum StbMStoreTimebaseNonVolatile;
uint32_t StbMSyncLossThreshold; 	/* Standard using floating point to present 0 to INF SEC(s) */
uint32_t StbMSyncLossTimeout;		/* Standard using floating point to present 0 to INF SEC(s) */
uint16_t StbMSynchronizedTimeBaseIdentifier;

void StbM_GetVersionInfo(void) {

}

void StbM_Init(void) {
  	StbMIsSystemWideGlobalTimeMaster = 0;
  	StbMSyncLossThreshold = 0;
  	StbMSyncLossTimeout = 0;
  	StbMSynchronizedTimeBaseIdentifier = 0;
}

Std_ReturnType StbM_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				   StbM_TimeStampType* timeStampPtr,
				   StbM_UserDataType* userDataPtr) {
  struct timespec local_current_time;
  
  if(EthTSynHardwareTimestampSupport) {
    //get time from ethernet hardware
  } else {
    getrawmonotonic(&local_current_time);
    timeStampPtr->secondsHi = (uint16_t)((local_current_time.tv_sec & 0x0000FFFF00000000) >> 32);
    timeStampPtr->seconds = (uint32_t)(local_current_time.tv_sec & 0xFFFFFFFF);
    timeStampPtr->nanoseconds = local_current_time.tv_nsec;
  }
  return E_OK;
}
//Service ID 0x08
Std_ReturnType StbM_GetCurrentTimeExtended(StbM_SynchronizedTimeBaseType timeBaseId, 
					   StbM_TimeStampExtendedType* timeStampPtr,
					   StbM_UserDataType* userDataPtr) {
  struct timespec local_current_time;
  
  if(EthTSynHardwareTimestampSupport) {
    //get time from ethernet hardware
  } else {
    getrawmonotonic(&local_current_time);
    timeStampPtr->seconds = local_current_time.tv_sec;
    timeStampPtr->nanoseconds = local_current_time.tv_nsec;
  }
  return E_OK;
}

Std_ReturnType	StbM_GetCurrentTimeRaw(StbM_TimeStampRawType* timeStampRawPtr) {
  struct timespec local_current_time;
  
  getrawmonotonic(&local_current_time);	//return void
  
  *timeStampRawPtr = local_current_time.tv_nsec;

  return E_OK;
}

Std_ReturnType	StbM_GetCurrentTimeDiff(StbM_TimeStampRawType givenTimeStamp,
					StbM_TimeStampRawType* timeStampDiffPtr) {
  struct timespec local_current_time;

  getrawmonotonic(&local_current_time);

  //if local_current_time is just exceed UINT_MAX
  if(local_current_time.tv_nsec > givenTimeStamp) {
    *timeStampDiffPtr = local_current_time.tv_nsec - givenTimeStamp;
  } else {
    *timeStampDiffPtr = (UINT_MAX - givenTimeStamp) + local_current_time.tv_nsec;
  }
  return E_OK;
}

//Service ID 0x0b
//Allow the Customer to set the new global timer
//Make this to be call by Application on UserSpace
Std_ReturnType	StbM_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				   StbM_TimeStampType* timeStampPtr,
				   StbM_UserDataType* userDataPtr) {
  struct timespec local_current_time;
  
  //init timeStampPtr
  timeStampPtr->timeBaseStatus.TIMEOUT = 0;
  timeStampPtr->timeBaseStatus.TIMELEAP = 0;
  timeStampPtr->timeBaseStatus.SYNC_TO_GATEWAY = 0;
  timeStampPtr->timeBaseStatus.GLOBAL_TIME_BASE = 1;
  timeStampPtr->timeBaseStatus.rsv = 0;

  getrawmonotonic(&local_current_time);

  timeStampPtr->nanoseconds = local_current_time.tv_nsec;
  timeStampPtr->seconds = local_current_time.tv_sec;
  timeStampPtr->secondsHi = 0;

  //if UserDataType is not null -> setting to where?
  
  return E_OK;
error:
  return E_NOT_OK;
}

Std_ReturnType	StbM_SetUserData(StbM_SynchronizedTimeBaseType timeBaseId, 
				 StbM_UserDataType* userDataPtr) {
  return E_OK;
}

Std_ReturnType	StbM_SetOffset(StbM_SynchronizedTimeBaseType timeBaseId, 
			       StbM_TimeStampType* timeStampPtr) {
  return E_OK;
}

Std_ReturnType	StbM_GetOffset(StbM_SynchronizedTimeBaseType timeBaseId,
			       StbM_TimeStampType* timeStampPtr) {
  return E_OK;
}

Std_ReturnType	StbM_BusSetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr, 
				      StbM_UserDataType* userDataPtr,
				      bool syncToTimeBase) {
  

  return E_OK;
}

void 		StbM_MainFunction(void) {

}


