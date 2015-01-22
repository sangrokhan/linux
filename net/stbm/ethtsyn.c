
#include <linux/types.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>

bool EthTSynHardwareTimestampSupport;

/* Initialize all internal variables and set the EthTSync module to init state */
void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {
  //When DET reporting is enabled EthTSyn module shall call DEt_ReportError() with the error code
  //ETHTSYN_E_NOT_INITIALIZED when any API is called in uninitialized state

  //After first initialized, when init function is called, reinitialize

  //rate correction -> 0
  //latency for ingress and egress to 0
  
  EthTSynHardwareTimestampSupport = false; //Hardware can't support timestamp on RaspberryPi

}

void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo) {

}

Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr,
				       EthTSyn_SyncStateType* syncState) {
  return E_OK;
}

Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr) {
  return E_OK;
}

Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
					    EthTSyn_TransmissionModeType Mode) {
  return E_OK;
}

void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte) {

}

void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx) {
   if(EthTSynHardwareTimestampSupport == true) {
      /* the egress time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
      // EthIf_GetEgressTimeStamp(uint8_t, uint8_t, Eth_TimeStampQualType*, Eth_TimeStampType*);
   } else {    // In case EthTSynHardwareTimestamp is set to FALSE
      if(Type == Sync || Type == Pdelay_Resp) {
         // StbM_GetCurrentTime(StdM_ReturnType, StbM_SynchronizedTimeBaseType, StbM_TimeStampType*, StbM_UserDataType*);
      } else if(Type == Pdelay_Req) {
         // StbM_GetCurrentTimeRaw(Std_ReturnType, Std_TimeStampRawType*);
         // T1 = *timeStampRawPtr;
      } else if(Type == Pdelay_Resp) {
         // givenTimeStamp = T2;
         // StbM_GetCurrentTimeDiff(Std_ReturnType, Std_TimeStampRawType, StbM_TimeStampRawType*);
         // timeStampDiffPtr = (T3-T2)    /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
      } else if(Type == Sync && Type == EthTimeGatewayMasterPort) {
         // givenTimeStamp = (Tr,i);   // Maybe 'Tr' means the time that received message, and 'i' means time-aware system indexed i
         // StbM_GetCurrentTimeDiff(Std_ReturnType, StbM_TimeStampRawType, StbM_TimeStampRawType*)
         // timeStampDiffPtr = (Ts,i - Tr,i);   /* For correctionField(i) calculation of Time Aware Bridges */
         // 'Ts' means the synchronized time, maybe
         // 'Ts,i - Tr,i' means the residence time
      }
   }
}

Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

void 		EthTSyn_MainFunction(void) {

}
                                                                                                                                                                                                                                                                                                                                                                        
