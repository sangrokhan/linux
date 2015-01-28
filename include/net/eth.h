#ifndef _ETH_H
#define _ETH_H

#include <linux/time.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/posix-clock.h>
#include <linux/std_types.h>
#include <net/eth_generaltypes.h>

typedef enum {
  ETH_OK,
  ETH_E_NOT_OK,
  ETH_E_NO_ACCESS
} Eth_ReturnType;

typedef enum {
  ETH_STATE_UNINIT,
  ETH_STATE_INIT,
  ETH_STATE_ACTIVE
} Eth_StateType;

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
extern bool	EthGetEtherStatsApi;
extern bool	EthGlobalTimeSupport;
extern uint8_t	EthIndex;
extern uint32_t EthMainFunctionPeriod; /* Standard using floating point to present from 0 to INF */
extern uint8_t	EthMaxCtrlsSupported;
extern bool	EthUpdatePhysAddrFilter;
extern bool	EthVersionInfoApi;

extern void 			Eth_Init(const Eth_ConfigType* CfgPtr);
extern Std_ReturnType		Eth_ControllerInit(uint8_t CtrlIdx, 
						   uint8_t CfgIdx);
extern Std_ReturnType		Eth_SetControllerMode(uint8_t CtrlIdx, 
						      Eth_ModeType CtrlMode);
extern Std_ReturnType		Eth_GetControllerMode(uint8_t CtrlIdx, 
						      Eth_ModeType* CtrlModePtr);
extern void			Eth_GetPhysAddr(uint8_t CtrlIdx, 
						uint8_t* PhysAddrPtr);
extern void 			Eth_SetPhysAddr(uint8_t CtrlIdx, 
						const uint8_t* PhysAddrPtr);
extern Std_ReturnType		Eth_UpdatePhyAddrFilter(uint8_t CtrlIdx, 
							uint8_t* PhysAddrPtr, 
							Eth_FilterActionType Action);
extern Std_ReturnType		Eth_WriteMii(uint8_t CtrlIdx, 
					     uint8_t TrcvIdx, 
					     uint8_t RegIdx, 
					     uint16_t RegVal);
extern Std_ReturnType		Eth_ReadMii(uint8_t CtrlIdx, 
					    uint8_t TrcvIdx, 
					    uint8_t RegIdx, 
					    uint16_t* RegValPtr);
extern Std_ReturnType		Eth_GetDropCount(uint8_t CtrlIdx, 
						 uint8_t CountValues, 
						 uint32_t* DropCount);
extern Std_ReturnType		Eth_GetEtherStats(uint8_t CtrlIdx, 
						  uint32_t* etherStats);
extern Std_ReturnType		Eth_GetCurrentTime(uint8_t CtrlIdx, 
						   Eth_TimeStampQualType* timeQualPtr, 
						   Eth_TimeStampType* timeStampPtr);
extern void			Eth_EnableEgressTimeStamp(uint8_t CtrlIdx, 
							  uint8_t BufIdx);
extern void 			Eth_GetEgressTimeStamp(uint8_t CtrlIdx, 
						       uint8_t BufIdx, 
						       Eth_TimeStampQualType* timeQualPtr, 
						       Eth_TimeStampType* timeStampPtr);
extern void			Eth_GetIngressTimeStamp(uint8_t CtrlIdx, 
							Eth_DataType* DataPtr, 
							Eth_TimeStampQualType* timeQualPtr, 
							Eth_TimeStampType* timeStampPtr);
extern void			Eth_SetCorrectionTime(uint8_t CtrlIdx, 
						      Eth_TimeIntDiffType* timeOffsetPtr, 
						      Eth_RateRatioType* rateRatioPtr);
extern Std_ReturnType		Eth_SetGlobalTime(uint8_t CtrlIdx, 
						  Eth_TimeStampType* timeStampPtr);
extern BufReq_ReturnType 	Eth_ProvideTxBuffer(uint8_t CtrlIdx, 
						    Eth_BufIdxType* BufIdxPtr, 
						    uint8_t** BufPtr, 
						    uint16_t* LenBytePtr);
extern Std_ReturnType		Eth_Transmit(uint8_t CtrlIdx, 
					     Eth_BufIdxType BufIdx, 
					     Eth_FrameType FrameType, 
					     bool TxConfirmation, 
					     uint16_t LenByte, 
					     uint8_t* PhysAddrPtr);
extern void			Eth_Receive(uint8_t CtrlIdx, 
					    Eth_RxStatusType* RxStatusPtr);
extern int			Eth_Receive_linux(struct sk_buff*, 
						  struct net_device*, 
						  struct packet_type*, 
						  struct net_device*);
extern void			Eth_TxConfirmation(uint8_t CtrlIdx);
extern void			Eth_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);
extern void			Eth_MainFunction(void);

#endif
