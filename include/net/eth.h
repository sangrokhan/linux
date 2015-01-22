#ifndef _ETH_H
#define _ETH_H

#include <linux/types.h>
#include <linux/std_types.h>

typedef struct {

} Eth_ConfigType;

typedef enum {
  ETH_OK,
  ETH_E_NOT_OK,
  ETH_E_NO_ACCESS
} Eth_ReturnType;

typedef enum {
  ETH_MODE_DOWN,
  ETH_MODE_ACTIVE
} Eth_ModeType;

typedef enum {
  ETH_STATE_UNINIT,
  ETH_STATE_INIT,
  ETH_STATE_ACTIVE
} Eth_StateType;

typedef uint16_t Eth_FrameType;

//based on cpu bit definition 
//Needo to be fixed for support 8bit CPU, 16bit CPU
typedef uint32_t Eth_DataType;

typedef uint32_t Eth_BufIdxType;

typedef enum {
  ETH_RECEIVED,
  ETH_NOT_RECEIVED,
  ETH_RECEIVED_MORE_DATA_AVAILABLE
} Eth_RxStatusType;

typedef enum {
  ETH_ADD_TO_FILTER,
  ETH_REMOVE_FROM_FILTER
} Eth_FilterActionType;

typedef enum {
  ETH_VALID, 
  ETH_INVALID,
  ETH_UNCERTAIN
} Eth_TimeStampQualType;

typedef struct {
  uint32_t nanoseconds;
  uint32_t seconds;
  uint16_t secondsHi;
} Eth_TimeStampType;

typedef struct {
  Eth_TimeStampType diff;
  bool sign;	//positive True / negative false
} Eth_TimeIntDiffType;

typedef struct {
  Eth_TimeIntDiffType IngressTimeStampDelta;
  Eth_TimeIntDiffType OriginTimeStampDelta;
} Eth_RateRatioType;

//EthCtrlConfig
extern bool	EthCtrlEnableMii;
extern bool	EthCtrlEnableRxInterrupt;
extern bool	EthCtrlEnableTxInterrupt;
extern uint8_t	EthCtrlIdx;
extern uint8_t*	EthCtrlPhyAddress;
#define MAX_ETH_PHY_ADDR_LENTH 17
extern uint16_t	EthCtrlRxBufLenByte;
extern uint16_t EthCtrlTxBufLenByte;
extern uint8_t	EthRxBufTotal;
extern uint8_t	EthTxBufTotal;

//EthGeneral
extern bool	EthDevErrorDetect;
extern bool	EthGetDropCountApi;
extern bool	EthGetEhterStatsApi;
extern bool	EthGlobalTimeSupport;
extern uint8_t	EthIndex;
extern uint32_t EthMainFunctionPeriod; /* Standard using floating point to present from 0 to INF */
extern uint8_t	EthMaxCtrlsSupported;
extern bool	EthUpdatePhysAddrFilter;
extern bool	EthVersionInfoApi;



extern void 		Eth_Init(const Eth_ConfigType* CfgPtr);
extern Std_ReturnType	Eth_ControllerInit(uint8_t CtrlIdx, 
					   uint8_t CfgIdx);
extern Std_ReturnType	Eth_SetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType CtrlMode);
extern Std_ReturnType	Eth_GetControllerMode(uint8_t CtrlIdx, 
					      Eth_ModeType* CtrlModePtr);
extern void		Eth_GetPhysAddr(uint8_t CtrlIdx, 
					uint8_t* PhysAddrPtr);
extern void 		Eth_SetPhysAddr(uint8_t CtrlIdx, 
					const uint8* PhysAddrPtr);
extern Std_ReturnType	Eth_UpdatePhyAddrFilter(uint8_t CtrlIdx, 
						uint8_t* PhysAddrPtr, 
						Eth_FilterActionType Action);
extern Std_ReturnType	Eth_WriteMii(uint8_t CtrlIdx, 
				     uint8_t TrcvIdx, 
				     uint8_t RegIdx, 
				     uint16_t RegVal);
extern Std_ReturnType	Eth_ReadMii(uint8_t CtrlIdx, 
				    uint8_t TrcvIdx, 
				    uint8_t RegIdx, 
				    uint16_t* RegValPtr);
extern Std_ReturnType	Eth_GetDropCount(uint8_t CtrlIdx, 
					 uint8_t CountValues, 
					 uint32_t* DropCount);
extern Std_ReturnType	Eth_GetEtherStats(uint8_t CtrlIdx, 
					  uint32_t* etherStats);
extern Std_ReturnType	Eth_GetCurrentTime(uint8_t CtrlIdx, 
					   Eth_TimeStampQualType* timeQualPtr, 
					   Eth_TimeStampType* timeStampPtr);
extern void		Eth_EnableEgressTimeStamp(uint8_t CtrlIdx, 
						  uint8_t BufIdx);
extern void 		Eth_GetEgressTimeStamp(uint8_t CtrlIdx, 
					       uint8_t BufIdx, 
					       Eth_TimeStampQualType* timeQualPtr, 
					       Eth_TimeStampType* timeStampPtr);
extern void		Eth_GetIngressTimeStamp(uint8_t CtrlIdx, 
						Eth_DataType* DataPtr, 
						Eth_TimeStampQualType* timeQualPtr, 
						Eth_TimeStamp* timeStampPtr);
extern void		Eth_SetCorrectionTime(uint8_t CtrlIdx, 
					      Eth_TimeIntDiffType* timeOffsetPtr, 
					      Eth_RateRatioType* rateRatioPtr);
extern Std_ReturnType	Eth_SetGlobalTime(uint8_t CtrlIdx, 
					  Eth_TimeStampType* timeStampPtr);
extern BufReq_ReturType Eth_ProvideTxBuffer(uint8_t CtrlIdx, 
					    Eth_BufIdxType* BufIdxPtr, 
					    uint8_t** BufPtr, 
					    uint16_t* LenBytePtr);
extern Std_ReturnType	Eth_Transmit(uint8_t CtrlIdx, 
				     Eth_bufIdxType BufIdx, 
				     Eth_FrameType FrameType, 
				     bool TxConfirmation, 
				     uint16_t LenByte, 
				     uint8_t* PhysAddrPtr);
extern void		Eth_Receive(uint8_t CtrlIdx, 
				    Eth_RxStatusType* RxStatusPtr);
extern void		Eth_TxConfirmation(uint8_t CtrlIdx);
extern void		Eth_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);
extern void		Eth_MainFunction(void);

#endif
