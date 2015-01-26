#include <linux/types.h>
#include <linux/std_types.h>
#include <net/eth.h>

void 			Eth_Init(const Eth_ConfigType* CfgPtr) {

}

Std_ReturnType		Eth_ControllerInit(uint8_t CtrlIdx, 
					   uint8_t CfgIdx) {
  return E_OK;
}

Std_ReturnType		Eth_SetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType CtrlMode) {
  return E_OK;
}

Std_ReturnType		Eth_GetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType* CtrlModePtr) {
  return E_OK;
}

void			Eth_GetPhysAddr(uint8_t CtrlIdx, 
					uint8_t* PhysAddrPtr) {

}

void 			Eth_SetPhysAddr(uint8_t CtrlIdx,
					const uint8_t* PhysAddrPtr) {

}

Std_ReturnType		Eth_UpdatePhyAddrFilter(uint8_t CtrlIdx, 
						uint8_t* PhysAddrPtr, 
						Eth_FilterActionType Action) {
  return E_OK;
}

Std_ReturnType		Eth_WriteMii(uint8_t CtrlIdx, 				       
				     uint8_t TrcvIdx,
 				     uint8_t RegIdx, 
				     uint16_t RegVal) {
  return E_OK;
}

Std_ReturnType		Eth_ReadMii(uint8_t CtrlIdx, 				    
				    uint8_t TrcvIdx,
				    uint8_t RegIdx, 
				    uint16_t* RegValPtr) {
  return E_OK;
}

Std_ReturnType		Eth_GetDropCount(uint8_t CtrlIdx,
 					 uint8_t CountValues,
 					 uint32_t* DropCount) {
  return E_OK;
}

Std_ReturnType		Eth_GetEtherStats(uint8_t CtrlIdx, 
					  uint32_t* etherStats) {
  return E_OK;
}

Std_ReturnType		Eth_GetCurrentTime(uint8_t CtrlIdx,
					   Eth_TimeStampQualType* timeQualPtr,
					   Eth_TimeStampType* timeStampPtr) {
  return E_OK;
}

void			Eth_EnableEgressTimeStamp(uint8_t CtrlIdx,
						  uint8_t BufIdx) {

}

void 			Eth_GetEgressTimeStamp(uint8_t CtrlIdx,
					       uint8_t BufIdx,
					       Eth_TimeStampQualType* timeQualPtr,
					       Eth_TimeStampType* timeStampPtr) {

}

void			Eth_GetIngressTimeStamp(uint8_t CtrlIdx, 
						Eth_DataType* DataPtr, 
						Eth_TimeStampQualType* timeQualPtr, 
						Eth_TimeStampType* timeStampPtr) {

}

void			Eth_SetCorrectionTime(uint8_t CtrlIdx, 
					      Eth_TimeIntDiffType* timeOffsetPtr, 
					      Eth_RateRatioType* rateRatioPtr) {

}

Std_ReturnType		Eth_SetGlobalTime(uint8_t CtrlIdx, 
					  Eth_TimeStampType* timeStampPtr) {
  return E_OK;
}

BufReq_ReturnType 	Eth_ProvideTxBuffer(uint8_t CtrlIdx, 
					    Eth_BufIdxType* BufIdxPtr, 
					    uint8_t** BufPtr, 
					    uint16_t* LenBytePtr) {
  return BUFREQ_OK;
}

Std_ReturnType		Eth_Transmit(uint8_t CtrlIdx, 
				     Eth_BufIdxType BufIdx, 
				     Eth_FrameType FrameType, 
				     bool TxConfirmation, 
				     uint16_t LenByte, 
				     uint8_t* PhysAddrPtr) {
  return E_OK;
}

void			Eth_Receive(uint8_t CtrlIdx, 
				    Eth_RxStatusType* RxStatusPtr) {

}

void			Eth_TxConfirmation(uint8_t CtrlIdx) {

}

void			Eth_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr) {

}

void			Eth_MainFunction(void) {

}


