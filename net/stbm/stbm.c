
#include <linux/types.h>
#include <linux/posix-clock.h>
#include <net/stbm.h>

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
				   StbM_TimeStampType*	timeStampPtr,
				   StbM_UserDataType* userDataPtr) {
  return E_OK;
}

Std_ReturnType StbM_GetCurrentTimeExtended(StbM_SynchronizedTimeBaseType timeBaseId, 
					   StbM_TimeStampExtendedType* timeStampPtr,
					   StbM_UserDataType* userDataPtr) {
  return E_OK;
}

Std_ReturnType	StbM_GetCurrentTimeRaw(StbM_TimeStampRawType* timeStampRawPtr) {
  
  return E_OK;
}

Std_ReturnType	StbM_GetCurrentTimeDiff(StbM_TimeStampRawType givenTimeStamp,
					StbM_TimeStampRawType* timeStampDiffPtr) {
  

  return E_OK;
}

//Service ID 0x0b
//Allow the Customer to set the new global timer
//Make this to be call by Application on UserSpace
Std_ReturnType	StbM_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				   StbM_TimeStampType* timeStampPtr,
				   StbM_UserDataType* userDataPtr) {
  struct timespec current_time;
  
  //init timeStampPtr
  timeStampPtr->timeBaseStatus.TIMEOUT = 0;
  timeStampPtr->timeBaseStatus.TIMELEAP = 0;
  timeStampPtr->timeBaseStatus.SYNC_TO_GATEWAY = 0;
  timeStampPtr->timeBaseStatus.GLOBAL_TIME_BASE = 1;
  timeStampPtr->timeBaseStatus.rsv = 0;

  getrawmonotonic(&current_time);

  timeStampPtr->nanoseconds = current_time.tv_nsecs;
  timeStampPtr->seconds = current_time.tv_sec;
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


