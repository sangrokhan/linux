#ifndef _ETHIF_H
#define _ETHIF_H

#include <linux/types.h>
#include <linux/std_types.h>
#include <net/eth.h>

typedef struct {

} EthIf_ConfigType;

typedef enum {
  ETHCTRL_STATE_UNINIT = 0x00,
  ETHCTRL_STATE_INIT
} EthIf_StateType;


//EthIfGeneral
extern bool	EthIfDevErrorDetect;
extern bool	EthIfEnableRxInterrupt;
extern bool	EthIfEnableTxInterrupt;
extern bool	EthIfGetBaudRate;
extern bool	EthIfGetCounterState;
extern bool	EthIfTransceiverWakeupModeApi;
extern bool	EthIfGlobalTimeSupoort;
extern uint32_t EthIfMainFunctionPeriod; /* Standard using float to present from 0 to INF */

extern void 		EthIf_Init(const EthIf_ConfigType* CfgPtr);
extern Std_ReturnType	EthIf_ControllerInit(uint8_t CtrlIdx, uint8_t CfgIdx);
extern Std_ReturnType	EthIf_SetControllerMode(uint8_t CtrlIdx, Eth_ModeType CtrlMode);
extern Std_ReturnType	EthIf_GetControllerMode(uint8_t CtrlIdx, Eth_ModeType* CtrlModePtr);
extern Std_ReturnType	EthIf_TransceiverInit(uint8_t CtrlIdx, uint8_t CfgIdx);
extern Std_ReturnType	EthIf_SetTransceiverMode(uint8_t CtrlIdx, EthTrcv_ModeType TrcvMode);
extern Std_ReturnType	EthIf_GetTransceiverMode(uint8_t CtrlIdx, EthTrcv_ModeType* TrcvModePtr);
extern Std_ReturnType	EthIf_SetTransceiverWakeupMode(uint8_t TrcvIdx, EthTrcv_WakeupModeType TrcvWakeupMode);
extern Std_ReturnType	EthIf_GetTransceiverWakeupMode(uint8_t TrcvIdx, EthTrcv_WakeupModeType* TrcvWakeupModePtr);
extern Std_ReturnType	EthIf_CheckWakeup(uint8_t TrcvIdx);
extern void		EthIf_GetPhysAddr(uint8_t CtrlIdx, uint8_t* PhysAddrPtr);
extern void		EthIf_SetPhysAddr(uint8_t CtrlIdx, const uint8_t* PhysAddrPtr);
extern Std_ReturnType	EthIf_UpdatePhysAddrFilter(uint8_t CtrlIdx, uint8_t* PhysAddrPtr, Eth_FilterActionType Action);
extern Std_ReturnType	EthIf_GetPortMacAddr(uint8_t* MacAddrPtr, uint8_t* SwitchIdxPtr, uint8_t* PortIdxPtr);
extern Std_ReturnType	EthIf_GetArlTable(uint8_t SwitchIdx, EthSwt_MacVlanType[]* ArlTable);
extern Std_ReturnType	EthIf_GetBufferLevel(uint8_t SwitchIdx, uint32_t* SwitchBufferLevelPtr);
extern Std_ReturnType	EthIf_GetDropCount(uint8_t SwitchIdx, uint32_t[]* DropCount);
extern std_ReturnType	EthIf_StorCOnfiguration(uint8_t SwitchIdx);
extern Std_ReturnType	EthIf_ResetConfiguration(uint8_t SwitchIdx);
extern Std_ReturnType	EthIf_GetCurrentTime(uint8_t CtrlIdx, Eth_TimeStampQualType* timeQualPtr, Eth_TimeStampType* timeStampPtr);
extern void		EthIf_EnableEgressTimeStamp(uint8_t CtrlIdx, uint8_t BufIdx);
extern void		EthIf_GetEgressTimeStamp(uint8_t CtrlIdx, uint8_t BufIdx, Eth_TimeStampQualType* timeQualPtr, Eth_TimeStampType* timeStampPtr);
extern void		EthIf_GetIngressTimeStamp(uint8_t CtrlIdx, Eth_DataType* DataPtr, Eth_TimeStampQualType* timeQualPtr, Eth_TimeStampType* timeStampPtr);
extern void		EthIf_SetCorrectionTime(uint8_t CtrlIdx, Eth_TimeIntDiffType* timeOffsetPtr, Eth_RateRatioType* rateRatioPtr);
extern Std_ReturnType	EthIf_SetGlobalTime(uint8_t CtrlIdx, Eth_TimeStampType* timeStmapPtr);
extern BufReq_ReturnType EthIf_ProvideTxBuffer(uint8_t CtrlIdx, Eth_FrameType FrameType, uint8_t Priority, Eth_BufIdxType* BufIdxPtr, uint8_t** BufPtr, uint16_t* LenBytePtr);
extern Std_ReturnType	EthIf_Transmit(uint8_t CtrlIdx, Eth_BufIdxType BufIdx, Eth_FrameType FrameType, bool TxConfirmation, uint16_t LenByte, uint8_t* PhysAddrPtr);
extern void 		EthIf_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);

//callback functions
//move to ethif_cbk.h
extern void		EthIf_RxIndication(uint8_t CtrlIdx, Eth_FrameType FrameType, bool IsBroadcast, uint8_t* PhysAddrPtr, Eth_DataType* DataPtr, uint16_t LenByte);
extern void		EthIf_TxConfirmation(uint8_t CtrlIdx, Eth_BufIdxType BufIdx);
extern void		EthIf_CtrlModeIndication(uint8_t CtrlIdx, Eth_ModeType CtrlMode);
extern void		EthIf_TrcvModeIndication(uint8_t CtrlIdx, EthTrcv_ModeType TrcvMode);

//Scheduled functions
extern void		EthIf_MainFunctionRx(void);
extern void		EthIf_MainFunctionTx(void);


#endif
