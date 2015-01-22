#ifndef _ETHTSYN_H
#define _ETHTSYN_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <net/eth.h>
#include <net/ethtrcv.h>

typedef struct {
  
} EthTSyn_ConfigType;

typedef enum {
  	ETHTSYN_TX_OFF = 0,
	ETHTSYN_TX_ON
} EthTSyn_TransmissionModeType;

typedef enum {
	ETHTSYN_SYNC = 0,
	ETHTSYN_UNSYNC,
	ETHTSYN_UNCERTAIN,
	ETHTSYN_NEVERSYNC
} EthTSyn_SyncStateType;

/* EthTSynGeneral */
extern bool EthTSynDevErrorDetect;
extern bool EthTSynHardwareTimestampSupport;
extern uint32_t EthTSynMainFunctionPeriod;	/* Standard using floating point to present INF */
extern bool EthTSynVersionInfo;

/* EthTSynGlobalTimeDomain */
extern uint32_t EthTSynGlobalTimeDomainId;
extern uint32_t EthTSynGlobalTimeFollowUpTimeout;
//extern Unknown EthTSynSynchronizedTimeBaseRef; /* Reference to StbMSynchronizedTimeBase */

/* EthTSynGlobalTimeMaster & EthTSynGlobalTimeSlave */
extern uint32_t EthTSynGlobalTimeTxFollowUpOffset; /* Standard using floating point to present INF */
extern uint32_t EthTSynGlobalTimeTxPdelayReqPeriod; /* Standard using floating point to present INF */
extern uint32_t EthTSynGlobalTimeTxPeriod; /* Standard using floating point to present INF */
//extern Unknown EthTSynGlobalTimeEthIfRef; /* Reference to EthIfController */

extern void 		EthTSyn_Init(const EthTSyn_ConfigType* configPtr);
extern void 		EthTSyn_GetVersionInfo(Std_VersionInfoType* versioninfo);
extern Std_ReturnType 	EthTSyn_GetCurrentTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					       StbM_TimeStampType* timeStampPtr,
					       EthTSyn_SyncStateType* syncState);
extern Std_ReturnType 	EthTSyn_SetGlobalTime(StbM_SynchronizedTimeBaseType timeBaseId, 
					      StbM_TimeStampType* timeStampPtr);
extern Std_ReturnType	EthTSyn_SetTransmissionMode(uint8_t CtrlIdx, 
						    EthTSyn_TransmissionModeType Mode);
extern void		EthTSyn_RxIndication(uint8_t CtrlIdx,
				     Eth_FrameType FrameType,
				     bool IsBroadcast,
				     uint8_t* PhyAddrPtr,
				     uint8_t* DataPtr,
				     uint16_t LenByte);
extern void		EthTSyn_TxConfirmation(uint8_t CtrlIdx,
				       uint8_t BufIdx);
extern Std_ReturnType	EthTSyn_TrcvLinkStateChg(uint8_t CtrlIdx, 
					 EthTrcv_LinkStateType TrcvLinkState);
extern void 		EthTSyn_MainFunction(void);

#endif
