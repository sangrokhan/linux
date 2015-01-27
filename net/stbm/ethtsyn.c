
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

EthTSyn_MessageType Type;

time_t temp;



/* Initialize all internal variables and set the EthTSync module to init state */
void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {
  //When DET reporting is enabled EthTSyn module shall call DEt_ReportError() with the error code
  //ETHTSYN_E_NOT_INITIALIZED when any API is called in uninitialized state

  //After first initialized, when init function is called, reinitialize

  //rate correction -> 0
  //latency for ingress and egress to 0
  
   switch(*configPtr) {
      case 6 : // If configured as Time Master,
         // the StbM shall allow configuration of the initialization value of the Global Time Base.
         // The initialization value can be either a value from static configuration or a value from non-volatile memory.
         // StbM_SetGlobalTime();
         break;
      case 9 : // If configured as Time slave,
         // the StbM shall use the Local Time Base while no valid Global Time Base is available (e.g. at startup)
         //    - Startup with a defined Time Base.
         // the StbM shall initialize the Local Time Base with 0 at startup.
         //    - Startup with a network wide common Time Base value.
         // StbM_SetGlobalTime();
         break;
   }

   EthTSynHardwareTimestampSupport = false; //Hardware can't support timestamp on RaspberryPi
}

/* Returns the version information of this module */
void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo) {
   if(EthTSynVersionInfo == 0) {   // False : version information API deactivated
   } else {   // True : version information API activated
   }
}

/* Returns a time value according its definition out of the HW registers */
Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr,
				       EthTSyn_SyncStateType* syncState) {
   // hardwareRegisterTime = EthIf_GetCurrentTime(CtrlIdx, timeQualPtr, timeStampPtr);
   //if(timeQualPtr == ) {
   //} else {
   //}
  
   return E_OK;
}

/* Allows the Time Master to adjust the global ETH Reference clock in HW */
/* This method is used to set a Global Time Base on ETH in general or to synchronize the Global ETH Time Base with another time base, e.g. Ethernet */
Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr) {
   uint8_t CtrlIdx;
   Eth_TimeStampType* ethTimeStampPtr = timeStampPtr;
   globalTime = EthIf_SetGlobalTime(CtrlIdx, ethTimeStampPtr);
   return globalTime;
}

/* This API is used to turn on and off the TX capabilities of the EthTSyn */
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

/* By this API service the EthTSyn gets an indication and the data of a received frame */
void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte) {
   if(Type.Sync == 1 || Type.Pdelay_Req == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
      if(EthTSynHardwareTimestampSupport == true) {
	     /* the time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {
         if(Type.Pdelay_Req == 1) {   // if(Type == Pdelay_Req) {
		    	currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
	  	   } else if(Type.Sync == 1 || Type.Pdelay_Req == 1) {   // else if(Type == Sync || Type == Pdelay_Req) {
		      currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr); // why??

            if(Type.Pdelay_Req == 1) {   // if(Type == Pdelay_Req) {
		         EthTSynTime2 = *timeStampRawPtr;
		      } else if(Type.Sync == 1 && Type == EthTimeGatewaySlavePort) {   // else if(Type == Sync || Type == EthTimeGatewaySlavePort) {
			      /* Start time stamp for correctionField(i) calculation of Time Aware Bridges */
			      // Tr,i = *timeStampRawPtr
		      } else if(Type.Pdelay_Resp == 1) {   // else if(Type == Pdelay_Resp) {
		         givenTimeStamp = EthTSynTime1;

			      if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
                  temp = EthTSynTime4 - EthTSynTime1;
			         timeStampDiffPtr = (StbM_TimeStampRawType*)&temp; /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
               }
		  	   }
		   }
	   }
   }
}

/* Confirms the transmission of an Ethernet frame */
void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx) {
   if(Type.Sync == 1 || Type.Pdelay_Req == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Req || Type == Pdelay_Resp) {
      if(EthTSynHardwareTimestampSupport == true) {
         /* the egress time stamp shall be retrieved for Pdelay_Req and Pdelay_Resp from the EthIf */
		 /* the egress time stamp shall be retrieved for Sync from the EthIf */ // ??
         // EthIf_GetEgressTimeStamp(CtrlIdx, BufIdx, timeQualPtr, timeStampPtr);
      } else {    // In case EthTSynHardwareTimestamp is set to FALSE
         if(Type.Sync == 1 || Type.Pdelay_Resp == 1) {   // if(Type == Sync || Type == Pdelay_Resp) {
            currentTime = StbM_GetCurrentTime(timeBaseId, timeStampPtr, userDataPtr);
         } else if(Type.Pdelay_Req == 1) {   // else if(Type == Pdelay_Req) {
            if((currentTimeRaw = StbM_GetCurrentTimeRaw(timeStampRawPtr)) == "E_OK") {
               EthTSynTime1 = *timeStampRawPtr;
            }
         } else if(Type.Pdelay_Resp == 1) {   // else if(Type == Pdelay_Resp) {
            givenTimeStamp = EthTSynTime2;
            
            if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
               temp = EthTSynTime3 - EthTSynTime2;
               timeStampDiffPtr = (StbM_TimeStampRawType*)&temp;    /* One part of D = ((T4-T1) - (T3-T2)) / 2 */
            }
         } else if(Type.Sync == 1 && Type == EthTimeGatewayMasterPort) {   // } else if(Type == Sync && Type == EthTimeGatewayMasterPort) {
            // givenTimeStamp = (Tr,i);   // Maybe 'Tr' means the time that received message, and 'i' means time-aware system indexed i
            if((timeDifferenceOfCurrentTimeRaw = StbM_GetCurrentTimeDiff(givenTimeStamp, timeStampDiffPtr)) == "E_OK") {
               // timeStampDiffPtr = (Ts,i - Tr,i);   /* For correctionField(i) calculation of Time Aware Bridges */
               // 'Ts' means the synchronized time, maybe
               // 'Ts,i - Tr,i' means the residence time
            }
         }
      }
   }
}

/* Allow resetting state machine in case of unexpected Link loss to avoid inconsistent Sync and Follw_Up sequences */
Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

/* Main function for cyclic call / resp. Sync, Follow_Up and Pdelay_Req transmissions */
void 		EthTSyn_MainFunction(void) {

}
                                                                                                                                                                                                                                                                                                                                                                        
