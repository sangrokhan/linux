
#include <linux/types.h>
#include <net/stbm.h>
#include <net/ethtsyn.h>

/* Initialize all internal variables and set the EthTSync module to init state */
void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {
  //When DET reporting is enabled EthTSyn module shall call DEt_ReportError() with the error code
  //ETHTSYN_E_NOT_INITIALIZED when any API is called in uninitialized state

  //After first initialized, when init function is called, reinitialize

  //rate correction -> 0
  //latency for ingress and egress to 0
  
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
 
}

Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {
  return E_OK;
}

void 		EthTSyn_MainFunction(void) {

}
                                                                                                                                                                                                                                                                                                                                                                        
