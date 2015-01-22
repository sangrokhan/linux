
#include <linux/types.h>
#include <net/stbm.h>

void StbM_GetVersionInfo(void) {

}

void StbM_Init(void) {

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

Std_ReturnType	StbM_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				   StbM_TimeStampType* timeStampPtr,
				   StbM_UserDataType* userDataPtr) {
  return E_OK;
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


