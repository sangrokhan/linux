

#include <linux/stbm.h>
#include <net/ethtsyn.h>

void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr) {

}

void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo) {

}

Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId,
				       StbM_TimeStampType* timeStampPtr,
				       EthTSyn_SyncStateType* syncState) {

}

Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
				      StbM_TimeStampType* timeStampPtr) {

}

Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
					    EthTSyn_TransmissionModeType Mode) {

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

Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8 CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState) {

}

void 		EthTSyn_MainFunction(void) {

}

