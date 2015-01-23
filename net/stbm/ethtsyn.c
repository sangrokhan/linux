
#include <linux/types.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>
#include <net/ethif.h>


bool EthTSynHardwareTimestampSupport;

Std_ReturnType hardwareRegisterTime;

Eth_TimeStampQualType* timeQualPtr;

Std_ReturnType globalTime;
Std_ReturnType currentTime;
Std_ReturnType currentTimeRaw;
Std_ReturnType timeDifferenceOfCurrentTimeRaw;

StbM_SynchronizedTimeBaseType timeBaseId;
StbM_TimeStampType*	timeStampPtr;
StbM_UserDataType* userDataPtr;
StbM_TimeStampRawType* timeStampRawPtr;
StbM_TimeStampRawType givenTimeStamp;
StbM_TimeStampRawType* timeStampDiffPtr;



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
   // hardwareRegisterTime = EthIf_GetCurrentTime(CtrlIdx, timeQualPtr, timeStampPtr);
   //if(timeQualPtr == ) {
   //} else {
   //}
  
   return E_OK;
}

Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr) {
   // globalTime = EthIf_SetGlobalTime(CtrlIdx, timeStampPtr);
   return globalTime;
}

Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
					    EthTSyn_TransmissionModeType Mode) {
   if(Mode == ETHTSYN_TX_OFF) {
      /* All transmit request from EthTSyn shall be omitted on this Ethernet controller */
   }

   if(Mode == ETHTSYN_TX_ON) {
      /* All transmit request from EthTSyn on this Ethernet controller shall be able to be transmitted */
   }
   return E_OK;
}

void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte) {
   if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
      if(EthTSynHardwareTimestampSupport == true) {
	     /* the time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {
         if(Type == Pdelay_Req) {
		 	currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
		 } else if(Type == Sync || Type == Pdelay_Req) {
		    currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr); // why??

			if(Type == Pdelay_Req) {
		       T2 = *timeStampRawPtr;
		    } else if(Type == Sync || Type == EthTimeGatewayslavePort) {
			   /* Start time stamp for correctionField(i) calculation of Time Aware Bridges */
			   // Tr,i = *timeStampRawPtr
		    } else if(Type == Pdelay_Resp) {
		       givenTimeStamp = T1;
			   timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr);
			   timeStampDiffPtr = (T4-T1); /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
			}
		 }
	  }
   }

}

void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx) {
   if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
   	
      if(EthTSynHardwareTimestampSupport == true) {
         /* the egress time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 /* the egress time stamp shall be retrieved for Sync from the EthIf */ // ??
         // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {    // In case EthTSynHardwareTimestamp is set to FALSE
         if(Type == Sync || Type == Pdelay_Resp) {
            currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
         } else if(Type == Pdelay_Req) {
            currentTimeRaw = StbM_GetCurrentTimeRaw(timeStampRawPtr);
             T1 = *timeStampRawPtr;
         } else if(Type == Pdelay_Resp) {
            givenTimeStamp = T2;
            timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr);
            timeStampDiffPtr = (T3-T2);    /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
         } else if(Type == Sync && Type == EthTimeGatewayMasterPort) {
            // givenTimeStamp = (Tr,i);   // Maybe 'Tr' means the time that received message, and 'i' means time-aware system indexed i
            timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr);
            // timeStampDiffPtr = (Ts,i - Tr,i);   /* For correctionField(i) calculation of Time Aware Bridges */
            // 'Ts' means the synchronized time, maybe
            // 'Ts,i - Tr,i' means the residence time
         }
      }
   	}
}

Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

void 		EthTSyn_MainFunction(void) {

}
                                                                                                                                                                                                                                                                                                                                                                        
